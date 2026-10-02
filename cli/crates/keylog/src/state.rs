//! The authority state machine (spec/KEYLOG.md §4), identical to Go's
//! `relay/internal/tlog/state.go`, plus the two pure questions Gateways and Workers ask.

use crate::entry::{Body, Entry, Kind, Roles, owner_key_id, pop_message, sig_message, unlp};
use crate::webauthn::{self, Assertion, Passkey, verify_assertion};
use ed25519_zebra::{Signature, VerificationKey};
use sha2::{Digest, Sha256};
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
    /// The mirror saw a forked log: no authority question is answered (fail closed).
    LogForked,
    /// The relay's pool.sync / route indexes do not match the mirrored log.
    IndexMismatch,
    /// The mirror is unavailable (lock poisoned).
    Unavailable,
    /// A signer / prev / revoked key that is not a logged owner key of that user
    /// (a device key signing an approval lands here).
    UnknownOwnerKey,
    /// A second owner key without the current owner key's rotation signature.
    OwnerKeyExists,
    /// Sealing gate: no verified checkpoint yet (or it is too old).
    NoCheckpoint,
    StaleLog,
    /// Passkey assertion checks (spec/KEYLOG.md §4a).
    WebAuthnType,
    WebAuthnChallenge,
    WebAuthnOrigin,
    WebAuthnRp,
    WebAuthnFlags,
    WebAuthnFormat,
    /// Sign counter not above the credential's last one (cloned authenticator or replay).
    Counter,
    /// ECDSA signature with s > n/2 (relays normalize before appending).
    HighS,
    /// A box device past its expiry (§17.1).
    Expired,
    /// A box KEY_ADDED whose expiry is not within (logged_at, logged_at + 30 days].
    BoxExpiry,
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
            Self::LogForked => "log_forked",
            Self::IndexMismatch => "index_mismatch",
            Self::Unavailable => "unavailable",
            Self::UnknownOwnerKey => "unknown_owner_key",
            Self::OwnerKeyExists => "owner_key_exists",
            Self::NoCheckpoint => "no_checkpoint",
            Self::StaleLog => "stale_log",
            Self::WebAuthnType => "webauthn_type",
            Self::WebAuthnChallenge => "webauthn_challenge",
            Self::WebAuthnOrigin => "webauthn_origin",
            Self::WebAuthnRp => "webauthn_rp",
            Self::WebAuthnFlags => "webauthn_flags",
            Self::WebAuthnFormat => "webauthn_format",
            Self::Counter => "counter",
            Self::HighS => "high_s",
            Self::Expired => "expired",
            Self::BoxExpiry => "box_expiry",
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
    /// Box device (§17.1): its enrollment token id. Gateway only, one repo, no owner or
    /// donor powers.
    pub box_id: Option<String>,
    /// Box devices: inactive from this time on (ms); 0 = never expires.
    pub expires_at_ms: u64,
}

/// Longest box lifetime from its KEY_ADDED: 30 days.
pub const MAX_BOX_TTL_MS: u64 = 30 * 24 * 3600 * 1000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
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
    /// subject pseudonym → DONOR_* grant (looked up by `&str`: no allocation per query).
    donors: HashMap<String, Grant>,
    /// subject pseudonym → MEMBER_* grant.
    members: HashMap<String, Grant>,
}

/// A logged owner key (CONTRACT §15.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerKeyInfo {
    pub id: String,
    pub pseudonym: String,
    /// The Ed25519 key; for a passkey, SHA-256 of its COSE key (the digest monitors
    /// know and acknowledge).
    pub owner_pub: [u8; 32],
    /// Index of the OWNER_KEY_ADDED entry.
    pub idx: u64,
    pub revoked: bool,
    /// `webauthn-es256` owner keys only.
    pub passkey: Option<PasskeyInfo>,
}

/// A logged passkey owner key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyInfo {
    /// `04 ‖ x ‖ y`.
    pub point: [u8; 65],
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub origins: String,
    /// Last sign counter seen (strictly increasing unless 0).
    pub counter: u32,
    /// First owner key of the account, registered with the relay-attested email proof.
    pub email_proof: bool,
}

/// SHA-256 of a passkey's COSE key: how monitors name a passkey they know.
#[must_use]
pub fn passkey_digest(cose: &[u8]) -> [u8; 32] {
    Sha256::digest(cose).into()
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
    /// owner key id → key.
    owners: HashMap<String, OwnerKeyInfo>,
    /// pseudonym → active Ed25519 owner key id.
    owner_of: HashMap<String, String>,
    /// pseudonym → number of active passkeys.
    passkeys_of: HashMap<String, u32>,
    /// passkey credential id → owner key id.
    creds: HashMap<Vec<u8>, String>,
}

fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(k), Ok(s)) = (
        VerificationKey::try_from(*pubkey),
        <[u8; 64]>::try_from(sig),
    ) else {
        return false;
    };
    k.verify(&Signature::from(s), msg).is_ok()
}

impl State {
    /// Applies entry `idx` if it is valid against the state; on `Err` the state is
    /// unchanged and the entry confers no authority. `check_sigs = false` only for
    /// reloading entries this mirror already verified.
    #[allow(clippy::too_many_lines)] // one flat arm per entry kind
    pub fn apply(&mut self, idx: u64, e: &Entry<'_>, check_sigs: bool) -> Result<(), Code> {
        match e.body {
            Body::Key {
                device_id,
                pseudonym,
                sign_pub,
                enc_pub,
                suite,
                roles,
                repo_scope,
                box_id,
                expires_at_ms,
            } => {
                if self.devices.contains_key(device_id) {
                    return Err(Code::DupDevice);
                }
                if self.pubs.contains_key(sign_pub) {
                    return Err(Code::DupKey);
                }
                if box_id.is_some()
                    && (expires_at_ms <= e.logged_at_ms
                        || expires_at_ms.saturating_sub(e.logged_at_ms) > MAX_BOX_TTL_MS)
                {
                    return Err(Code::BoxExpiry);
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
                        box_id: box_id.map(str::to_owned),
                        expires_at_ms,
                    },
                );
            }
            Body::Revoke {
                device_id,
                pseudonym,
                ..
            } => {
                let d = self
                    .devices
                    .get_mut(device_id)
                    .filter(|d| d.pseudonym == pseudonym)
                    .ok_or(Code::UnknownDevice)?;
                if d.revoked {
                    return Err(Code::Revoked);
                }
                d.revoked = true;
            }
            Body::Claim {
                repo_id,
                provider,
                provider_repo_id,
                owner,
                signer,
                issued_at_ms,
            } => {
                let ctr = self.check_signer(signer, owner, e, check_sigs)?;
                if let Some(r) = self.repos.get(repo_id) {
                    if r.provider != provider || r.provider_repo_id != provider_repo_id {
                        return Err(Code::RepoBinding);
                    }
                    if issued_at_ms <= r.issued {
                        return Err(Code::Replay);
                    }
                }
                self.bump(signer, ctr);
                let r = self
                    .repos
                    .entry(repo_id.to_owned())
                    .or_insert_with(|| Repo {
                        provider: provider.to_owned(),
                        provider_repo_id: provider_repo_id.to_owned(),
                        owner: owner.to_owned(),
                        issued: 0,
                        donors: HashMap::new(),
                        members: HashMap::new(),
                    });
                if r.owner != owner {
                    // New owner: every approval and membership must be re-signed.
                    r.donors.clear();
                    r.members.clear();
                    owner.clone_into(&mut r.owner);
                }
                r.issued = issued_at_ms;
            }
            Body::Grant {
                repo_id,
                subject,
                signer,
                issued_at_ms,
            } => {
                let owner = self
                    .repos
                    .get(repo_id)
                    .ok_or(Code::Unclaimed)?
                    .owner
                    .clone();
                let ctr = self.check_signer(signer, &owner, e, check_sigs)?;
                let member = matches!(e.kind, Kind::MemberAdded | Kind::MemberRemoved);
                let r = self.repos.get(repo_id).ok_or(Code::Unclaimed)?;
                let grants = if member { &r.members } else { &r.donors };
                if grants
                    .get(subject)
                    .is_some_and(|g| issued_at_ms <= g.issued)
                {
                    return Err(Code::Replay);
                }
                self.bump(signer, ctr);
                let r = self.repos.get_mut(repo_id).ok_or(Code::Unclaimed)?;
                let grants = if member {
                    &mut r.members
                } else {
                    &mut r.donors
                };
                let active = matches!(e.kind, Kind::DonorApproved | Kind::MemberAdded);
                grants.insert(
                    subject.to_owned(),
                    Grant {
                        active,
                        idx,
                        issued: issued_at_ms,
                    },
                );
            }
            Body::Catalog {
                version, sha256, ..
            } => {
                if version <= self.catalog {
                    return Err(Code::CatalogVersion);
                }
                self.catalog = version;
                self.catalogs.insert(version, *sha256);
            }
            Body::Moderation { .. } | Body::Pad => {}
            Body::OwnerKey {
                pseudonym,
                owner_pub,
                prev,
                authorizer,
                ..
            } => {
                if self.pubs.contains_key(owner_pub) {
                    return Err(Code::DupKey);
                }
                let cur = self
                    .owner_of
                    .get(pseudonym)
                    .and_then(|id| self.owners.get(id));
                match (cur, prev) {
                    (None, Some(_)) => return Err(Code::UnknownOwnerKey),
                    // A passkey exists: an unauthorized first CLI key would be trust-on-first-use.
                    (None, None)
                        if authorizer.is_none()
                            && self.passkeys_of.get(pseudonym).is_some_and(|n| *n > 0) =>
                    {
                        return Err(Code::OwnerKeyExists);
                    }
                    // A CLI key exists: rotate it (prev) instead.
                    (Some(_), _) if authorizer.is_some() => return Err(Code::OwnerKeyExists),
                    (Some(c), p) if p != Some(&c.owner_pub) => return Err(Code::OwnerKeyExists),
                    _ => {}
                }
                let msg = sig_message(Kind::OwnerKeyAdded, e.raw_body);
                let (new_sig, auth_sig) = match authorizer {
                    Some(_) => unlp::<2>(e.sig)
                        .map(|[n, a]| (n, a))
                        .map_err(|_| Code::BadSig)?,
                    None => (e.sig, &[][..]),
                };
                if check_sigs && !verify(owner_pub, &msg, new_sig.get(..64).unwrap_or_default()) {
                    return Err(Code::BadPop);
                }
                if let (true, Some(p)) = (check_sigs, prev)
                    && !verify(p, &msg, e.sig.get(64..).unwrap_or_default())
                {
                    return Err(Code::BadSig);
                }
                let mut auth_ctr = None;
                if let Some(a) = authorizer {
                    let k = self.owners.get(a).ok_or(Code::UnknownOwnerKey)?;
                    if k.revoked {
                        return Err(Code::Revoked);
                    }
                    if k.pseudonym != pseudonym {
                        return Err(Code::NotOwner);
                    }
                    auth_ctr =
                        Self::owner_sig(k, Kind::OwnerKeyAdded, e.raw_body, auth_sig, check_sigs)?;
                }
                let cur_id = cur.map(|c| c.id.clone());
                if let Some(a) = authorizer {
                    self.bump(a, auth_ctr);
                }
                let id = owner_key_id(owner_pub);
                self.pubs.insert(*owner_pub, id.clone());
                if let Some(c) = cur_id.and_then(|c| self.owners.get_mut(&c)) {
                    c.revoked = true;
                }
                self.owners.insert(
                    id.clone(),
                    OwnerKeyInfo {
                        id: id.clone(),
                        pseudonym: pseudonym.to_owned(),
                        owner_pub: *owner_pub,
                        idx,
                        revoked: false,
                        passkey: None,
                    },
                );
                self.owner_of.insert(pseudonym.to_owned(), id);
            }
            Body::OwnerPasskey {
                pseudonym,
                cose,
                authorizer,
                credential_id,
                rp_id,
                origins,
                email_proof,
                ..
            } => {
                let id = owner_key_id(cose);
                if self.owners.contains_key(&id) || self.creds.contains_key(credential_id) {
                    return Err(Code::DupKey);
                }
                let [pop, auth] = unlp::<2>(e.sig).map_err(|_| Code::BadSig)?;
                let pop = Assertion::parse(pop).map_err(|_| Code::BadSig)?;
                let point = webauthn::point_of(cose);
                let msg = sig_message(Kind::OwnerKeyAdded, e.raw_body);
                if check_sigs {
                    let k = Passkey {
                        point: &point,
                        rp_id,
                        origins,
                    };
                    verify_assertion(&k, &msg, &pop, 0)?;
                }
                let bump = match authorizer {
                    // First owner key of the account: only with the email proof (grammar), A224.
                    None => {
                        if self.owner_of.contains_key(pseudonym)
                            || self.passkeys_of.get(pseudonym).is_some_and(|n| *n > 0)
                        {
                            return Err(Code::OwnerKeyExists);
                        }
                        None
                    }
                    Some(a) => {
                        let k = self.owners.get(a).ok_or(Code::UnknownOwnerKey)?;
                        if k.revoked {
                            return Err(Code::Revoked);
                        }
                        if k.pseudonym != pseudonym {
                            return Err(Code::NotOwner);
                        }
                        if auth.is_empty() {
                            return Err(Code::BadSig);
                        }
                        Self::owner_sig(k, Kind::OwnerKeyAdded, e.raw_body, auth, check_sigs)?
                    }
                };
                if let Some(a) = authorizer {
                    self.bump(a, bump);
                }
                self.creds.insert(credential_id.to_vec(), id.clone());
                let n = self.passkeys_of.entry(pseudonym.to_owned()).or_default();
                *n = n.saturating_add(1);
                self.owners.insert(
                    id.clone(),
                    OwnerKeyInfo {
                        id,
                        pseudonym: pseudonym.to_owned(),
                        owner_pub: passkey_digest(cose),
                        idx,
                        revoked: false,
                        passkey: Some(PasskeyInfo {
                            point,
                            credential_id: credential_id.to_vec(),
                            rp_id: rp_id.to_owned(),
                            origins: origins.to_owned(),
                            counter: pop.counter(),
                            email_proof: email_proof.is_some(),
                        }),
                    },
                );
            }
            Body::OwnerPasskeyRevoke {
                pseudonym, cose, ..
            } => {
                let id = owner_key_id(cose);
                let k = self
                    .owners
                    .get_mut(&id)
                    .filter(|k| k.pseudonym == pseudonym)
                    .ok_or(Code::UnknownOwnerKey)?;
                if k.revoked {
                    return Err(Code::Revoked);
                }
                k.revoked = true;
                if let Some(n) = self.passkeys_of.get_mut(pseudonym) {
                    *n = n.saturating_sub(1);
                }
            }
            Body::OwnerRevoke {
                pseudonym,
                owner_pub,
                ..
            } => {
                let id = owner_key_id(owner_pub);
                let k = self
                    .owners
                    .get_mut(&id)
                    .filter(|k| k.pseudonym == pseudonym)
                    .ok_or(Code::UnknownOwnerKey)?;
                if k.revoked {
                    return Err(Code::Revoked);
                }
                k.revoked = true;
                if self.owner_of.get(pseudonym) == Some(&id) {
                    self.owner_of.remove(pseudonym);
                }
            }
        }
        Ok(())
    }

    /// Checks the owner signature of kinds 3–7; returns the passkey's new sign counter
    /// (applied by the caller with [`Self::bump`] once every other check passed).
    fn check_signer(
        &self,
        key_id: &str,
        owner: &str,
        e: &Entry<'_>,
        check_sigs: bool,
    ) -> Result<Option<u32>, Code> {
        let k = self.owners.get(key_id).ok_or(Code::UnknownOwnerKey)?;
        if k.revoked {
            return Err(Code::Revoked);
        }
        if k.pseudonym != owner {
            return Err(Code::NotOwner);
        }
        Self::owner_sig(k, e.kind, e.raw_body, e.sig, check_sigs)
    }

    /// `sig` by owner key `k` over `sig_message(kind, body)`: Ed25519, or a WebAuthn
    /// assertion for passkeys (then `Some(new counter)`; without `check_sigs`, the
    /// counter is still replayed from the stored assertion).
    fn owner_sig(
        k: &OwnerKeyInfo,
        kind: Kind,
        body: &[u8],
        sig: &[u8],
        check_sigs: bool,
    ) -> Result<Option<u32>, Code> {
        let Some(p) = &k.passkey else {
            if sig.len() != 64 || check_sigs && !verify(&k.owner_pub, &sig_message(kind, body), sig)
            {
                return Err(Code::BadSig);
            }
            return Ok(None);
        };
        let a = Assertion::parse(sig).map_err(|_| Code::BadSig)?;
        if !check_sigs {
            return Ok(Some(a.counter()));
        }
        let pk = Passkey {
            point: &p.point,
            rp_id: &p.rp_id,
            origins: &p.origins,
        };
        verify_assertion(&pk, &sig_message(kind, body), &a, p.counter).map(Some)
    }

    fn bump(&mut self, key_id: &str, ctr: Option<u32>) {
        if let (Some(c), Some(p)) = (
            ctr,
            self.owners.get_mut(key_id).and_then(|k| k.passkey.as_mut()),
        ) {
            p.counter = c;
        }
    }

    /// A logged owner key by id (`ok_…`), active or not.
    #[must_use]
    pub fn owner_key(&self, id: &str) -> Option<&OwnerKeyInfo> {
        self.owners.get(id)
    }

    /// The user's active owner key.
    #[must_use]
    pub fn active_owner_key(&self, pseudonym: &str) -> Option<&OwnerKeyInfo> {
        self.owner_of
            .get(pseudonym)
            .and_then(|id| self.owners.get(id))
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

    /// The user's box devices (§17.1), in log order, expired and revoked ones included:
    /// `(device_id, device)`.
    #[must_use]
    pub fn boxes(&self, pseudonym: &str) -> Vec<(&str, &Device)> {
        let mut v: Vec<(&str, &Device)> = self
            .devices
            .iter()
            .filter(|(_, d)| d.box_id.is_some() && d.pseudonym == pseudonym)
            .map(|(id, d)| (id.as_str(), d))
            .collect();
        v.sort_by_key(|(_, d)| d.idx);
        v
    }

    /// Does `pseudonym` own `repo_id` or hold an active MEMBER_ADDED for it?
    #[must_use]
    pub fn owner_or_member(&self, repo_id: &str, pseudonym: &str) -> bool {
        self.repos.get(repo_id).is_some_and(|r| {
            r.owner == pseudonym || r.members.get(pseudonym).is_some_and(|g| g.active)
        })
    }

    fn usable(
        &self,
        id: &str,
        worker: bool,
        repo_id: &str,
        now_ms: u64,
    ) -> Result<(&Device, &Repo), Code> {
        let d = self.devices.get(id).ok_or(Code::UnknownDevice)?;
        if d.revoked {
            return Err(Code::Revoked);
        }
        if d.expires_at_ms != 0 && now_ms >= d.expires_at_ms {
            return Err(Code::Expired);
        }
        if !(if worker {
            d.roles.has_worker()
        } else {
            d.roles.has_gateway()
        }) {
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
        self.sealable_at(worker, repo_id, now_ms())
    }

    /// [`Self::sealable`] at wall-clock time `now_ms` (box expiry).
    pub fn sealable_at(&self, worker: &str, repo_id: &str, now_ms: u64) -> Result<Sealable, Code> {
        let (d, r) = self.usable(worker, true, repo_id, now_ms)?;
        match r.donors.get(d.pseudonym.as_str()) {
            Some(g) if g.active => Ok(Sealable {
                enc_pub: d.enc_pub,
                key_idx: d.idx,
                approval_idx: g.idx,
            }),
            _ => Err(Code::NotApproved),
        }
    }

    /// May `gateway` submit tasks for `repo_id`? The key must be logged, unrevoked, have
    /// the gateway role and scope, and its user must own the repo or hold an active
    /// owner-signed MEMBER_ADDED. The Worker also checks the task signature against
    /// [`Device::sign_pub`].
    pub fn gateway_allowed(&self, gateway: &str, repo_id: &str) -> Result<&Device, Code> {
        self.gateway_allowed_at(gateway, repo_id, now_ms())
    }

    /// [`Self::gateway_allowed`] at wall-clock time `now_ms`: an expired box is refused.
    pub fn gateway_allowed_at(
        &self,
        gateway: &str,
        repo_id: &str,
        now_ms: u64,
    ) -> Result<&Device, Code> {
        let (d, r) = self.usable(gateway, false, repo_id, now_ms)?;
        if d.pseudonym == r.owner
            || r.members
                .get(d.pseudonym.as_str())
                .is_some_and(|g| g.active)
        {
            Ok(d)
        } else {
            Err(Code::NotMember)
        }
    }
}
