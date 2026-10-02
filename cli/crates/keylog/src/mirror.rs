//! Full incremental mirror of the key log and the monitor rules (plan 06 §10.1).
//!
//! The mirror keeps one leaf hash per entry (32 B) and the authority [`State`]; records
//! themselves are persisted by the caller (it gets them in [`Mirror::update`] and
//! hands them back to [`Mirror::restore`] at start-up). New entries are applied only
//! after their hashes reproduce the signed checkpoint root over the whole mirrored
//! history, so a rewritten or forked log can never change local state.

use crate::{
    Error,
    entry::{Body, Kind, MAX_RECORD, parse_record},
    merkle::{CompactRange, Hash, leaf_hash, root_of},
    note::{Checkpoint, NoteKey, open_checkpoint},
    state::{Code, State},
};

/// Who this Node is, for the monitor rules.
#[derive(Clone, Debug, Default)]
pub struct Me {
    pub pseudonym: String,
    /// Signing keys the user created on their devices or acknowledged after an
    /// [`Alert::UnknownKey`] ("yes, that was me").
    pub known_keys: Vec<[u8; 32]>,
}

impl Me {
    fn knows(&self, k: &[u8; 32]) -> bool {
        self.known_keys.contains(k)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    /// A record that does not parse: the relay appended garbage.
    Invalid { idx: u64 },
    /// A well-formed record the state machine refuses; it confers no authority.
    Rejected { idx: u64, kind: Kind, code: Code },
    /// A key was added to my account that I neither created nor acknowledged.
    UnknownKey { idx: u64, device_id: String },
    /// One of my keys was logged for another account.
    KeyHijack {
        idx: u64,
        device_id: String,
        pseudonym: String,
    },
    /// A claim, approval or membership on my repo signed by a key I do not know.
    NotSignedByMe {
        idx: u64,
        kind: Kind,
        repo_id: String,
        signer: String,
    },
    /// A repo I owned was claimed by another account.
    RepoClaimedByOther {
        idx: u64,
        repo_id: String,
        owner: String,
    },
    /// An owner key was registered on my account that I neither created nor acknowledged.
    UnknownOwnerKey { idx: u64, owner_key: String },
    /// One of my owner keys was revoked by the relay (first step of an account takeover,
    /// or a recovery I asked for).
    OwnerKeyRevoked { idx: u64, owner_key: String },
}

/// Result of comparing a checkpoint (e.g. the Git anchor) with the mirror.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorStatus {
    /// Same root at that size: the mirrored history extends the checkpoint.
    Consistent,
    /// The checkpoint is ahead of the mirror: sync first. If the relay's own latest
    /// checkpoint is smaller than the anchor, the relay rolled back.
    Behind,
    /// Different root at the same size: the log was forked or rewritten.
    Fork,
}

#[derive(Clone, Debug)]
pub struct Mirror {
    origin: String,
    key: NoteKey,
    leaves: Vec<Hash>,
    range: CompactRange,
    state: State,
    me: Option<Me>,
    /// Owner keys the user created (CONTRACT §15.4) or acknowledged after an
    /// [`Alert::UnknownOwnerKey`]; approvals on the user's repos signed by any other
    /// key raise [`Alert::NotSignedByMe`].
    owner_keys: Vec<[u8; 32]>,
    checkpoint: Option<Checkpoint>,
}

impl Mirror {
    /// An empty mirror for the log `origin`, pinned to the log verifier key.
    #[must_use]
    pub fn new(origin: &str, key: NoteKey) -> Self {
        Self {
            origin: origin.to_owned(),
            key,
            leaves: Vec::new(),
            range: CompactRange::default(),
            state: State::default(),
            me: None,
            owner_keys: Vec::new(),
            checkpoint: None,
        }
    }

    /// Rebuilds a mirror from records it verified earlier (persisted by the caller)
    /// without re-checking signatures; the hashes must reproduce `cp`.
    pub fn restore<'a>(
        origin: &str,
        key: NoteKey,
        records: impl IntoIterator<Item = &'a [u8]>,
        cp: &Checkpoint,
    ) -> Result<Self, Error> {
        let mut m = Self::new(origin, key);
        for r in records {
            let idx = m.size();
            m.push(r, false, &mut Vec::new())?;
            if idx >= cp.size {
                return Err(Error::Format("restore: more records than checkpoint"));
            }
        }
        if m.size() != cp.size || m.range.root() != cp.root {
            return Err(Error::Fork { size: cp.size });
        }
        m.checkpoint = Some(*cp);
        Ok(m)
    }

    pub fn set_me(&mut self, me: Option<Me>) {
        self.me = me;
    }

    /// Sets the user's own owner keys (public halves) for the owner rules.
    pub fn set_owner_keys(&mut self, keys: Vec<[u8; 32]>) {
        self.owner_keys = keys;
    }

    /// The user just created (or confirmed) this device key: later entries for it are
    /// not "unknown" any more. No effect without [`Me`].
    pub fn acknowledge_device_key(&mut self, sign_pub: [u8; 32]) {
        if let Some(me) = self
            .me
            .as_mut()
            .filter(|m| !m.known_keys.contains(&sign_pub))
        {
            me.known_keys.push(sign_pub);
        }
    }

    /// The user just created (or confirmed) this owner key.
    pub fn acknowledge_owner_key(&mut self, owner_pub: [u8; 32]) {
        if !self.owner_keys.contains(&owner_pub) {
            self.owner_keys.push(owner_pub);
        }
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.range.size()
    }

    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The newest checkpoint this mirror verified.
    #[must_use]
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        self.checkpoint
    }

    /// Verifies a signed checkpoint note against the pinned key and origin.
    pub fn open_checkpoint(&self, note: &[u8]) -> Result<Checkpoint, Error> {
        open_checkpoint(note, &self.origin, &self.key)
    }

    /// Root of the mirrored tree at `size` (O(size) for historical sizes).
    #[must_use]
    pub fn root_at(&self, size: u64) -> Option<Hash> {
        if size == self.size() {
            return Some(self.range.root());
        }
        self.leaves.get(..usize::try_from(size).ok()?).map(root_of)
    }

    /// Compares a verified checkpoint (relay or Git anchor) with the mirror.
    #[must_use]
    pub fn check(&self, cp: &Checkpoint) -> AnchorStatus {
        match self.root_at(cp.size) {
            None => AnchorStatus::Behind,
            Some(r) if r == cp.root => AnchorStatus::Consistent,
            Some(_) => AnchorStatus::Fork,
        }
    }

    /// Grows the mirror to the verified checkpoint `cp` with the records
    /// `[size, cp.size)`. Fails with [`Error::Fork`] (state untouched) unless the
    /// mirrored history plus `records` hashes to `cp.root`. Returns monitor alerts.
    pub fn update(&mut self, cp: &Checkpoint, records: &[&[u8]]) -> Result<Vec<Alert>, Error> {
        let size = self.size();
        if cp.size <= size {
            return match self.check(cp) {
                AnchorStatus::Consistent if records.is_empty() => Ok(Vec::new()),
                AnchorStatus::Consistent => Err(Error::Format("records beyond checkpoint")),
                _ => Err(Error::Fork { size: cp.size }),
            };
        }
        if u64::try_from(records.len()).ok() != cp.size.checked_sub(size) {
            return Err(Error::Format("record count"));
        }
        let mut range = self.range.clone();
        for r in records {
            if r.len() > MAX_RECORD {
                return Err(Error::TooLarge);
            }
            range.push(leaf_hash(r));
        }
        if range.root() != cp.root {
            return Err(Error::Fork { size: cp.size });
        }
        let mut alerts = Vec::new();
        for r in records {
            self.push(r, true, &mut alerts)?;
        }
        self.checkpoint = Some(*cp);
        Ok(alerts)
    }

    #[allow(clippy::too_many_lines)] // one flat arm per monitor rule
    fn push(&mut self, rec: &[u8], check_sigs: bool, alerts: &mut Vec<Alert>) -> Result<(), Error> {
        if rec.len() > MAX_RECORD {
            return Err(Error::TooLarge);
        }
        let idx = self.size();
        let h = leaf_hash(rec);
        self.leaves.push(h);
        self.range.push(h);
        let Ok(e) = parse_record(rec) else {
            alerts.push(Alert::Invalid { idx });
            return Ok(());
        };
        let owner_before = match e.body {
            Body::Claim { repo_id, .. } | Body::Grant { repo_id, .. } => {
                self.state.owner(repo_id).map(str::to_owned)
            }
            _ => None,
        };
        if let Err(code) = self.state.apply(idx, &e, check_sigs) {
            alerts.push(Alert::Rejected {
                idx,
                kind: e.kind,
                code,
            });
            return Ok(());
        }
        let Some(me) = &self.me else { return Ok(()) };
        let knows_owner = |k: &[u8; 32]| self.owner_keys.contains(k);
        let signer_known = |signer: &str| {
            self.state
                .owner_key(signer)
                .is_some_and(|k| knows_owner(&k.owner_pub))
        };
        match e.body {
            Body::OwnerKey {
                pseudonym,
                owner_pub,
                ..
            } if pseudonym == me.pseudonym && !knows_owner(owner_pub) => {
                alerts.push(Alert::UnknownOwnerKey {
                    idx,
                    owner_key: crate::entry::owner_key_id(owner_pub),
                });
            }
            Body::OwnerKey {
                pseudonym,
                owner_pub,
                ..
            } if pseudonym != me.pseudonym && (knows_owner(owner_pub) || me.knows(owner_pub)) => {
                alerts.push(Alert::KeyHijack {
                    idx,
                    device_id: crate::entry::owner_key_id(owner_pub),
                    pseudonym: pseudonym.to_owned(),
                });
            }
            Body::OwnerRevoke {
                pseudonym,
                owner_pub,
                ..
            } if pseudonym == me.pseudonym => {
                alerts.push(Alert::OwnerKeyRevoked {
                    idx,
                    owner_key: crate::entry::owner_key_id(owner_pub),
                });
            }
            Body::Key {
                device_id,
                pseudonym,
                sign_pub,
                ..
            } => {
                if pseudonym == me.pseudonym && !me.knows(sign_pub) {
                    alerts.push(Alert::UnknownKey {
                        idx,
                        device_id: device_id.to_owned(),
                    });
                } else if pseudonym != me.pseudonym && me.knows(sign_pub) {
                    alerts.push(Alert::KeyHijack {
                        idx,
                        device_id: device_id.to_owned(),
                        pseudonym: pseudonym.to_owned(),
                    });
                }
            }
            Body::Claim {
                repo_id,
                owner,
                signer,
                ..
            } => {
                if owner == me.pseudonym && !signer_known(signer) {
                    alerts.push(Alert::NotSignedByMe {
                        idx,
                        kind: e.kind,
                        repo_id: repo_id.to_owned(),
                        signer: signer.to_owned(),
                    });
                }
                if owner_before.as_deref() == Some(me.pseudonym.as_str()) && owner != me.pseudonym {
                    alerts.push(Alert::RepoClaimedByOther {
                        idx,
                        repo_id: repo_id.to_owned(),
                        owner: owner.to_owned(),
                    });
                }
            }
            Body::Grant {
                repo_id, signer, ..
            } if owner_before.as_deref() == Some(me.pseudonym.as_str())
                && !signer_known(signer) =>
            {
                alerts.push(Alert::NotSignedByMe {
                    idx,
                    kind: e.kind,
                    repo_id: repo_id.to_owned(),
                    signer: signer.to_owned(),
                });
            }
            _ => {}
        }
        Ok(())
    }
}
