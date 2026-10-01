//! The authority state machine (spec/KEYLOG.md §4), identical to Go's
//! `relay/internal/tlog/state.go`, plus the two pure questions Gateways and Workers ask.

use crate::entry::{Body, Entry, Kind, Roles, pop_message, sig_message};
use ed25519_zebra::{Signature, VerificationKey};
use std::collections::HashMap;

/// Stable rejection/denial codes (same strings as Go).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    DupDevice,
    DupKey,
    BadPop,
    NotOwner,
    BadSig,
    Replay,
    RepoBinding,
    CatalogVersion,
    UnknownDevice,
    Revoked,
    Unclaimed,
    Role,
    Scope,
    NotApproved,
    NotMember,
}

impl Code {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DupDevice => "dup_device",
            Self::DupKey => "dup_key",
            Self::BadPop => "bad_pop",
            Self::NotOwner => "not_owner",
            Self::BadSig => "bad_sig",
            Self::Replay => "replay",
            Self::RepoBinding => "repo_binding",
            Self::CatalogVersion => "catalog_version",
            Self::UnknownDevice => "unknown_device",
            Self::Revoked => "revoked",
            Self::Unclaimed => "unclaimed",
            Self::Role => "role",
            Self::Scope => "scope",
            Self::NotApproved => "not_approved",
            Self::NotMember => "not_member",
        }
    }
}

/// A logged device key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub pseudonym: String,
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    pub suite: String,
    pub roles: Roles,
    pub repo_scope: Option<String>,
    /// Index of the KEY_ADDED entry.
    pub idx: u64,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug)]
struct Grant {
    active: bool,
    idx: u64,
    issued: u64,
}

#[derive(Clone, Debug)]
struct Repo {
    provider: String,
    provider_repo_id: String,
    owner: String,
    issued: u64,
    /// (is_member, subject pseudonym) → grant.
    grants: HashMap<(bool, String), Grant>,
}

/// The result of a successful [`State::sealable`] check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealable {
    pub enc_pub: [u8; 32],
    pub key_idx: u64,
    pub approval_idx: u64,
}

#[derive(Clone, Debug, Default)]
pub struct State {
    devices: HashMap<String, Device>,
    pubs: HashMap<[u8; 32], String>,
    repos: HashMap<String, Repo>,
    catalogs: HashMap<u64, [u8; 32]>,
    catalog: u64,
}

fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(k), Ok(s)) = (VerificationKey::try_from(*pubkey), <[u8; 64]>::try_from(sig)) else { return false };
    k.verify(&Signature::from(s), msg).is_ok()
}

impl State {
    /// Applies entry `idx` if it is valid against the state; on `Err` the state is
    /// unchanged and the entry confers no authority. `check_sigs = false` only for
    /// reloading entries this mirror already verified.
    pub fn apply(&mut self, idx: u64, e: &Entry<'_>, check_sigs: bool) -> Result<(), Code> {
        match e.body {
            Body::Key { device_id, pseudonym, sign_pub, enc_pub, suite, roles, repo_scope } => {
                if self.devices.contains_key(device_id) {
                    return Err(Code::DupDevice);
                }
                if self.pubs.contains_key(sign_pub) {
                    return Err(Code::DupKey);
                }
                if check_sigs && !verify(sign_pub, &pop_message(sign_pub, enc_pub, suite), e.sig) {
                    return Err(Code::BadPop);
                }
                self.pubs.insert(*sign_pub, device_id.to_owned());
                self.devices.insert(
                    device_id.to_owned(),
                    Device {
                        pseudonym: pseudonym.to_owned(),
                        sign_pub: *sign_pub,
                        enc_pub: *enc_pub,
                        suite: suite.to_owned(),
                        roles,
                        repo_scope: repo_scope.map(str::to_owned),
                        idx,
                        revoked: false,
                    },
                );
            }
            Body::Revoke { device_id, pseudonym, .. } => {
                let d = self.devices.get_mut(device_id).filter(|d| d.pseudonym == pseudonym).ok_or(Code::UnknownDevice)?;
                if d.revoked {
                    return Err(Code::Revoked);
                }
                d.revoked = true;
            }
            Body::Claim { repo_id, provider, provider_repo_id, owner, signer, issued_at_ms } => {
                self.check_signer(signer, owner, e, check_sigs)?;
                if let Some(r) = self.repos.get(repo_id) {
                    if r.provider != provider || r.provider_repo_id != provider_repo_id {
                        return Err(Code::RepoBinding);
                    }
                    if issued_at_ms <= r.issued {
                        return Err(Code::Replay);
                    }
                }
                let r = self.repos.entry(repo_id.to_owned()).or_insert_with(|| Repo {
                    provider: provider.to_owned(),
                    provider_repo_id: provider_repo_id.to_owned(),
                    owner: owner.to_owned(),
                    issued: 0,
                    grants: HashMap::new(),
                });
                if r.owner != owner {
                    // New owner: every approval and membership must be re-signed.
                    r.grants.clear();
                    owner.clone_into(&mut r.owner);
                }
                r.issued = issued_at_ms;
            }
            Body::Grant { repo_id, subject, signer, issued_at_ms } => {
                let owner = self.repos.get(repo_id).ok_or(Code::Unclaimed)?.owner.clone();
                self.check_signer(signer, &owner, e, check_sigs)?;
                let member = matches!(e.kind, Kind::MemberAdded | Kind::MemberRemoved);
                let r = self.repos.get_mut(repo_id).ok_or(Code::Unclaimed)?;
                let key = (member, subject.to_owned());
                if r.grants.get(&key).is_some_and(|g| issued_at_ms <= g.issued) {
                    return Err(Code::Replay);
                }
                let active = matches!(e.kind, Kind::DonorApproved | Kind::MemberAdded);
                r.grants.insert(key, Grant { active, idx, issued: issued_at_ms });
            }
            Body::Catalog { version, sha256, .. } => {
                if version <= self.catalog {
                    return Err(Code::CatalogVersion);
                }
                self.catalog = version;
                self.catalogs.insert(version, *sha256);
            }
            Body::Moderation { .. } => {}
        }
        Ok(())
    }

    fn check_signer(&self, dev: &str, owner: &str, e: &Entry<'_>, check_sigs: bool) -> Result<(), Code> {
        let d = self.devices.get(dev).ok_or(Code::UnknownDevice)?;
        if d.revoked {
            return Err(Code::Revoked);
        }
        if d.pseudonym != owner {
            return Err(Code::NotOwner);
        }
        if check_sigs && !verify(&d.sign_pub, &sig_message(e.kind, e.raw_body), e.sig) {
            return Err(Code::BadSig);
        }
        Ok(())
    }

    #[must_use]
    pub fn device(&self, id: &str) -> Option<&Device> {
        self.devices.get(id)
    }

    /// Device id logged for a signing key, if any.
    #[must_use]
    pub fn device_by_key(&self, sign_pub: &[u8; 32]) -> Option<&str> {
        self.pubs.get(sign_pub).map(String::as_str)
    }

    /// Current owner pseudonym of a claimed repo.
    #[must_use]
    pub fn owner(&self, repo_id: &str) -> Option<&str> {
        self.repos.get(repo_id).map(|r| r.owner.as_str())
    }

    /// SHA-256 of the catalog JSON logged for `version`.
    #[must_use]
    pub fn catalog_sha256(&self, version: u64) -> Option<&[u8; 32]> {
        self.catalogs.get(&version)
    }

    fn usable(&self, id: &str, worker: bool, repo_id: &str) -> Result<(&Device, &Repo), Code> {
        let d = self.devices.get(id).ok_or(Code::UnknownDevice)?;
        if d.revoked {
            return Err(Code::Revoked);
        }
        if !(if worker { d.roles.has_worker() } else { d.roles.has_gateway() }) {
            return Err(Code::Role);
        }
        if d.repo_scope.as_deref().is_some_and(|s| s != repo_id) {
            return Err(Code::Scope);
        }
        Ok((d, self.repos.get(repo_id).ok_or(Code::Unclaimed)?))
    }

    /// May a Gateway seal a task for `repo_id` to `worker`? The key must be logged,
    /// unrevoked, have the worker role and scope, and its user must hold an active
    /// owner-signed DONOR_APPROVED for the repo.
    pub fn sealable(&self, worker: &str, repo_id: &str) -> Result<Sealable, Code> {
        let (d, r) = self.usable(worker, true, repo_id)?;
        match r.grants.get(&(false, d.pseudonym.clone())) {
            Some(g) if g.active => Ok(Sealable { enc_pub: d.enc_pub, key_idx: d.idx, approval_idx: g.idx }),
            _ => Err(Code::NotApproved),
        }
    }

    /// May `gateway` submit tasks for `repo_id`? The key must be logged, unrevoked, have
    /// the gateway role and scope, and its user must own the repo or hold an active
    /// owner-signed MEMBER_ADDED. The Worker also checks the task signature against
    /// [`Device::sign_pub`].
    pub fn gateway_allowed(&self, gateway: &str, repo_id: &str) -> Result<&Device, Code> {
        let (d, r) = self.usable(gateway, false, repo_id)?;
        if d.pseudonym == r.owner || r.grants.get(&(true, d.pseudonym.clone())).is_some_and(|g| g.active) {
            Ok(d)
        } else {
            Err(Code::NotMember)
        }
    }
}
