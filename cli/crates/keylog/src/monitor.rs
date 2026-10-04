//! The Node's key-log monitor (plan 06 §10.1; wiring in `WIRING.md`).
//!
//! [`Monitor::run`] mirrors the key log over the relay link the Node already has
//! (a [`LogLink`]: `GetLogTile` + the checkpoints the relay pushes), verifies every
//! checkpoint against the mirrored history (consistency, no rollback, optional witness
//! threshold), runs the monitor rules, compares with the public Git anchor, persists
//! the mirror, and publishes a shared [`View`] that Gateways and Workers query. Once a
//! fork is seen, the view refuses every authority question (fail closed), also across
//! restarts.

use crate::{
    Error,
    cosig::{CosignerKey, cosignatures},
    mirror::{Alert, AnchorStatus, Me, Mirror},
    note::NoteKey,
    state::{Code, Device, Sealable, State},
    tiles::{MAX_BUNDLE_BYTES, MAX_CHECKPOINT_BYTES, bundles, parse_bundle},
};
use std::{
    fs,
    future::Future,
    io::Write as _,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

/// What the monitor needs from the relay link. The Node implements it on its own
/// link type (tonic client + the receiver of pushed checkpoints).
pub trait LogLink: Send {
    /// `NodeLink.GetLogTile(path)`: `"checkpoint"` or a C2SP tile path.
    fn get_tile(&mut self, path: &str) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;
    /// The next checkpoint note to check: `Hello.log_checkpoint` at connect, then every
    /// pushed `RelayMsg.log_checkpoint` (a periodic `get_tile("checkpoint")` is a fine
    /// fallback). `None` ends [`Monitor::run`].
    fn next_checkpoint(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send;
    /// The newest checkpoint note of the public Git anchor when one is due (the Node
    /// fetches it at most hourly and caches it); `None` = nothing new.
    fn anchor(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send {
        async { None }
    }
    /// Whether [`LogLink::anchor`] is wired to a public Git anchor. With no anchor
    /// and no required witness cosignatures, a first-contact Node cannot detect a
    /// split view, and [`Monitor::run`] says so loudly ([`Event::FailOpen`], A204).
    fn anchor_configured(&self) -> bool {
        false
    }
}

/// Monitor configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Checkpoint origin, e.g. `moochy.dev/keylog`.
    pub origin: String,
    /// The pinned log key.
    pub key: NoteKey,
    /// Persistence directory (`records`, `checkpoint`, `fork-evidence`); `None` = memory.
    pub dir: Option<PathBuf>,
    /// The user, for the own-key and owner rules.
    pub me: Option<Me>,
    /// Public halves of the user's own owner keys (CONTRACT §15.4).
    pub known_owner_keys: Vec<[u8; 32]>,
    /// Pinned witness keys and how many distinct valid cosignatures a checkpoint
    /// needs before it is applied (0 = witnesses not required).
    pub witnesses: Vec<CosignerKey>,
    pub min_cosignatures: usize,
}

/// Something the Node must log, and for security events, show the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The mirror grew to `size` (verified).
    Synced { size: u64 },
    /// A monitor rule fired.
    Alert(Alert),
    /// The relay served a history inconsistent with the mirror or the anchor.
    Fork { size: u64, detail: String },
    /// The relay served an older (consistent) checkpoint than one it served before.
    Stale { served: u64, mirrored: u64 },
    /// The public anchor is ahead of what the relay serves (rollback / withholding).
    Rollback { anchored: u64, served: u64 },
    /// The anchor matches the mirror.
    AnchorConsistent { size: u64 },
    /// A checkpoint lacked the required witness cosignatures (not applied).
    Unwitnessed { size: u64, cosignatures: usize },
    /// Transport or format problem (retried at the next checkpoint).
    Error(String),
    /// Split-view protection is off: no witness cosignatures required and no Git
    /// anchor wired, so a relay could show this Node a history nobody else sees
    /// (A204). Emitted once per [`Monitor::run`]; never silent outside tests.
    FailOpen,
}

impl Event {
    /// Security events must be shown to the user, not only logged.
    #[must_use]
    pub fn is_security(&self) -> bool {
        !matches!(
            self,
            Self::Synced { .. } | Self::AnchorConsistent { .. } | Self::Error(_)
        )
    }

    /// One log line. Contains stable keywords (`unknown_key`, `rogue`, `unsigned`,
    /// `fork`, `stale`, `rollback`) that tooling and tests grep for. Every string
    /// in it comes from validated ASCII grammar (no terminal escapes possible).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Synced { size } => format!("keylog: synced, {size} entries verified"),
            Self::Alert(a) => alert_message(a),
            Self::Fork { size, detail } => {
                format!(
                    "keylog: SECURITY: log fork detected at tree size {size} ({detail}); the relay showed a rewritten history; key-log decisions are refused until resolved"
                )
            }
            Self::Stale { served, mirrored } => {
                format!(
                    "keylog: SECURITY: stale checkpoint: relay served tree size {served} after {mirrored} (rollback or freeze)"
                )
            }
            Self::Rollback { anchored, served } => {
                format!(
                    "keylog: SECURITY: rollback: the public Git anchor has tree size {anchored} but the relay serves {served}"
                )
            }
            Self::AnchorConsistent { size } => {
                format!("keylog: public Git anchor at {size} is consistent")
            }
            Self::Unwitnessed { size, cosignatures } => {
                format!(
                    "keylog: SECURITY: checkpoint {size} has {cosignatures} witness cosignatures, below the required threshold; not applied"
                )
            }
            Self::Error(e) => format!("keylog: {e}"),
            Self::FailOpen => "keylog: SECURITY: WARNING fail-open: split-view protection is OFF (no witness cosignatures required and no public Git anchor configured); forks within this Node's own history are still caught, but a relay could show this Node a log nobody else sees".to_owned(),
        }
    }
}

/// "repo", "organisation" (§19) or "person profile" (§24), from the id prefix.
fn target(id: &str) -> &'static str {
    if id.starts_with("o_") {
        "organisation"
    } else if id.starts_with("m_") {
        "person profile"
    } else {
        "repo"
    }
}

fn alert_message(a: &Alert) -> String {
    match a {
        Alert::UnknownKey { idx, device_id } => format!(
            "keylog: SECURITY: unknown_key: a new device {device_id} was added to your account (log #{idx}) and it is not one of yours; if this wasn't you, run `moochy keys revoke {device_id}`"
        ),
        Alert::KeyHijack {
            idx,
            device_id,
            pseudonym,
        } => format!(
            "keylog: SECURITY: rogue key: your signing key was logged for device {device_id} of another account {pseudonym} (log #{idx})"
        ),
        Alert::NotSignedByMe {
            idx,
            kind,
            repo_id,
            signer,
        } => format!(
            "keylog: SECURITY: unsigned {} for your {} {repo_id}: signed by owner key {signer}, which is not one of yours (log #{idx})",
            kind.name(),
            target(repo_id)
        ),
        Alert::RepoClaimedByOther {
            idx,
            repo_id,
            owner,
        } => {
            format!(
                "keylog: SECURITY: your {} {repo_id} was claimed by another account {owner} (log #{idx})",
                target(repo_id)
            )
        }
        Alert::Rejected { idx, kind, code } => format!(
            "keylog: SECURITY: unsigned or invalid {} at log #{idx} ({}): the relay appended an entry no valid signer made; it is ignored",
            kind.name(),
            code.as_str()
        ),
        Alert::UnknownOwnerKey { idx, owner_key } => format!(
            "keylog: SECURITY: unknown_owner_key: an owner key {owner_key} you did not create was registered on your account (log #{idx}); approvals it signs are not yours"
        ),
        Alert::OwnerKeyRevoked { idx, owner_key } => format!(
            "keylog: SECURITY: your owner key {owner_key} was revoked (log #{idx}); if you did not ask for it, your account may be under takeover"
        ),
        Alert::Invalid { idx } => {
            format!("keylog: SECURITY: malformed entry at log #{idx}; it is ignored")
        }
        Alert::UnknownPasskey {
            idx,
            owner_key,
            rp_id,
            email_proof,
        } => format!(
            "keylog: SECURITY: unknown_owner_key: a passkey {owner_key} for {rp_id} you did not create was registered on your account (log #{idx}){}; approvals it signs are not yours",
            if *email_proof {
                " as its first owner key on the relay's word that your email was confirmed: if this wasn't you, your mailbox or the relay is compromised"
            } else {
                ""
            }
        ),
        Alert::UnprovenOwnerKey {
            idx,
            owner_key,
            known,
        } => {
            if *known {
                format!(
                    "keylog: unproven_owner_key: your owner key {owner_key} was bound before the email-proof rule (log #{idx}), on the relay's word alone; it is yours, nothing to do"
                )
            } else {
                format!(
                    "keylog: SECURITY: unproven_owner_key: an owner key {owner_key} you did not create was bound on your account with no email proof and no authorization (log #{idx}); approvals it signs are not yours"
                )
            }
        }
        Alert::BoxEnrolled {
            idx,
            device_id,
            repo_id,
            box_id,
            expires_at_ms,
        } => format!(
            "keylog: box_enrolled: box device {device_id} (token {box_id}) was enrolled on your account for repo {repo_id}, gateway only, until {expires_at_ms} ms (log #{idx}); if this wasn't you, run `moochy box revoke {device_id}`"
        ),
        Alert::BoxOutsideRepo {
            idx,
            device_id,
            repo_id,
        } => format!(
            "keylog: SECURITY: box_outside_repo: box device {device_id} on your account is scoped to repo {repo_id}, which you neither own nor are a member of (log #{idx}); it was not enrolled by a token of yours"
        ),
        Alert::PasskeyCounter { idx, owner_key } => format!(
            "keylog: SECURITY: passkey_counter: an assertion of your passkey {owner_key} reused or lowered its sign counter (log #{idx}): a cloned authenticator or a replayed signature; the entry is ignored"
        ),
    }
}

#[derive(Debug)]
struct Shared {
    mirror: Mirror,
    fork: Option<String>,
    /// When the relay's current checkpoint last verified against the mirror.
    confirmed_at: Option<Instant>,
    /// The relay served an older checkpoint than it served before (until a newer
    /// consistent one arrives).
    stale: bool,
}

/// How long a verified checkpoint keeps the sealing gate open without a fresh
/// confirmation (the relay pushes a checkpoint on growth; the Node also polls
/// `GetLogTile("checkpoint")` every [`POLL_EVERY`] when no push arrived).
pub const MAX_LOG_AGE: Duration = Duration::from_secs(10 * 60);
/// Suggested polling period of the relay checkpoint when nothing was pushed.
pub const POLL_EVERY: Duration = Duration::from_secs(60);

/// The sealing gate's state (CONTRACT §15.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// No checkpoint verified yet: nothing may be sealed (outside `--dev`).
    NoCheckpoint,
    /// Verified and confirmed within [`MAX_LOG_AGE`]: seal to `sealable` workers only.
    Verified { size: u64 },
    /// The last confirmation is too old, or the relay served an older checkpoint.
    Stale { size: u64 },
    /// A fork was seen: nothing may be sealed, ever, until the user resolves it.
    Forked,
}

/// A cheap, cloneable, thread-safe handle on the verified key-log state. Every
/// answer is `Err(Code::LogForked)` once a fork was seen.
#[derive(Clone, Debug)]
pub struct View(Arc<RwLock<Shared>>);

impl View {
    fn with<R>(&self, f: impl FnOnce(&Mirror) -> Result<R, Code>) -> Result<R, Code> {
        let g = self.0.read().map_err(|_| Code::Unavailable)?;
        if g.fork.is_some() {
            return Err(Code::LogForked);
        }
        f(&g.mirror)
    }

    /// The user just created this device key (e.g. after `moochy keys rotate`): stop
    /// reporting it as unknown. Persist it in the Node's config for the next `open`.
    pub fn acknowledge_device_key(&self, sign_pub: [u8; 32]) {
        if let Ok(mut g) = self.0.write() {
            g.mirror.acknowledge_device_key(sign_pub);
        }
    }

    /// The user just created this owner key (`moochy owner init` / `rotate`).
    pub fn acknowledge_owner_key(&self, owner_pub: [u8; 32]) {
        if let Ok(mut g) = self.0.write() {
            g.mirror.acknowledge_owner_key(owner_pub);
        }
    }

    /// Verifies a projection fetched by reference (E63) against the verified state:
    /// see [`crate::projection::verify`].
    pub fn verify_projection(
        &self,
        projection: &[u8],
        sig: &[u8],
        worker_device: &str,
        key_log_index: u64,
    ) -> Result<crate::projection::Verified, Code> {
        self.with(|m| {
            crate::projection::verify(m.state(), projection, sig, worker_device, key_log_index)
        })
    }

    /// Mirrored tree size (0 when unavailable).
    #[must_use]
    pub fn size(&self) -> u64 {
        self.0.read().map_or(0, |g| g.mirror.size())
    }

    #[must_use]
    pub fn forked(&self) -> bool {
        self.0.read().map_or(true, |g| g.fork.is_some())
    }

    /// The sealing gate now.
    #[must_use]
    pub fn gate(&self) -> Gate {
        self.gate_at(Instant::now())
    }

    #[must_use]
    pub fn gate_at(&self, now: Instant) -> Gate {
        let Ok(g) = self.0.read() else {
            return Gate::Forked;
        };
        let size = g.mirror.size();
        match (&g.fork, g.confirmed_at) {
            (Some(_), _) => Gate::Forked,
            (None, None) => Gate::NoCheckpoint,
            (None, Some(at)) if g.stale || now.saturating_duration_since(at) > MAX_LOG_AGE => {
                Gate::Stale { size }
            }
            (None, Some(_)) => Gate::Verified { size },
        }
    }

    /// THE sealing rule (Gateway, for each pool worker, on the submit path): the gate
    /// must be [`Gate::Verified`], the worker sealable for `repo` in the verified log,
    /// and the relay's `key_log_index` / `approval_log_index` exactly the mirrored
    /// ones. Errors: `log_forked`, `no_checkpoint`, `stale_log`, `index_mismatch`, or a
    /// [`State::sealable`] denial. Only `--dev` may fall back to the relay's pool on
    /// `no_checkpoint`. Cost: one read lock + three hash lookups, no allocation.
    pub fn seal_check(
        &self,
        worker: &str,
        repo: &str,
        key_log_index: u64,
        approval_log_index: u64,
    ) -> Result<Sealable, Code> {
        self.seal_check_at(
            Instant::now(),
            worker,
            repo,
            key_log_index,
            approval_log_index,
        )
    }

    pub fn seal_check_at(
        &self,
        now: Instant,
        worker: &str,
        repo: &str,
        key_log_index: u64,
        approval_log_index: u64,
    ) -> Result<Sealable, Code> {
        let g = self.0.read().map_err(|_| Code::Unavailable)?;
        match (&g.fork, g.confirmed_at) {
            (Some(_), _) => return Err(Code::LogForked),
            (None, None) => return Err(Code::NoCheckpoint),
            (None, Some(at)) if g.stale || now.saturating_duration_since(at) > MAX_LOG_AGE => {
                return Err(Code::StaleLog);
            }
            _ => {}
        }
        let s = g.mirror.state().sealable(worker, repo)?;
        if s.key_idx != key_log_index || s.approval_idx != approval_log_index {
            return Err(Code::IndexMismatch);
        }
        Ok(s)
    }

    /// Gateway, before sealing to `worker` for `repo` (06 §10.1). Prefer
    /// [`View::seal_check`], which also enforces the gate.
    pub fn sealable(&self, worker: &str, repo: &str) -> Result<Sealable, Code> {
        self.with(|m| m.state().sealable(worker, repo))
    }

    /// Gateway, for each `PoolSync.workers[]` entry: the worker must be sealable AND
    /// the relay's `key_log_index` / `approval_log_index` must be exactly the mirrored
    /// ones (a relay pointing at someone else's approval gets `IndexMismatch`).
    pub fn check_pool_worker(
        &self,
        worker: &str,
        repo: &str,
        key_log_index: u64,
        approval_log_index: u64,
    ) -> Result<Sealable, Code> {
        let s = self.sealable(worker, repo)?;
        if s.key_idx != key_log_index || s.approval_idx != approval_log_index {
            return Err(Code::IndexMismatch);
        }
        Ok(s)
    }

    /// Worker, before acking a task from `gateway` for `repo` (03 §7.2 checks 1–2);
    /// verify the task signature with the returned device's `sign_pub`.
    pub fn gateway_allowed(&self, gateway: &str, repo: &str) -> Result<Device, Code> {
        self.with(|m| m.state().gateway_allowed(gateway, repo).cloned())
    }

    /// Any other read of the verified state (owner, device, catalog hash, …).
    pub fn state<R>(&self, f: impl FnOnce(&State) -> R) -> Result<R, Code> {
        self.with(|m| Ok(f(m.state())))
    }
}

/// The monitor. One per relay; see the module docs.
#[derive(Debug)]
pub struct Monitor {
    cfg: Config,
    view: View,
    /// Largest checkpoint size the relay has served (for rollback vs the anchor).
    served: u64,
}

fn io_err(e: impl std::fmt::Display) -> Error {
    Error::Io(e.to_string())
}

impl Monitor {
    /// Opens the monitor, restoring the persisted mirror (no network; signatures are
    /// checked again and the hashes must reproduce the stored checkpoint) and any persisted
    /// fork evidence.
    pub fn open(cfg: Config) -> Result<Self, Error> {
        let mut mirror = Mirror::new(&cfg.origin, cfg.key.clone());
        let mut fork = None;
        if let Some(dir) = &cfg.dir {
            fs::create_dir_all(dir).map_err(io_err)?;
            if let (Ok(recs), Ok(note)) = (
                fs::read(dir.join("records")),
                fs::read(dir.join("checkpoint")),
            ) {
                let cp = mirror.open_checkpoint(&note)?;
                let list = parse_records_file(&recs, cp.size)?;
                mirror = Mirror::restore(&cfg.origin, cfg.key.clone(), list, &cp)?;
            }
            if dir.join("fork-evidence").exists() {
                fork = Some("persisted fork evidence".to_owned());
            }
        }
        mirror.set_me(cfg.me.clone());
        mirror.set_owner_keys(cfg.known_owner_keys.clone());
        let served = mirror.size();
        Ok(Self {
            cfg,
            view: View(Arc::new(RwLock::new(Shared {
                mirror,
                fork,
                confirmed_at: None,
                stale: false,
            }))),
            served,
        })
    }

    /// The shared view for Gateways and Workers.
    #[must_use]
    pub fn view(&self) -> View {
        self.view.clone()
    }

    /// The loop: check every checkpoint the link yields, then the anchor when due.
    /// Returns when `next_checkpoint` returns `None`.
    pub async fn run<L: LogLink>(&mut self, link: &mut L, mut on_event: impl FnMut(&Event) + Send) {
        if self.fail_open(link) {
            on_event(&Event::FailOpen);
        }
        while let Some(note) = link.next_checkpoint().await {
            for e in self.on_checkpoint(link, &note).await {
                on_event(&e);
            }
            if let Some(a) = link.anchor().await {
                for e in self.on_anchor(&a) {
                    on_event(&e);
                }
            }
        }
    }

    /// True when this monitor cannot detect a split view (A204): no witness
    /// cosignatures required and no Git anchor wired on the link.
    #[must_use]
    pub fn fail_open<L: LogLink>(&self, link: &L) -> bool {
        self.cfg.min_cosignatures == 0 && !link.anchor_configured()
    }

    /// Checks one checkpoint note served by the relay and grows the mirror to it.
    pub async fn on_checkpoint<L: LogLink>(&mut self, link: &mut L, note: &[u8]) -> Vec<Event> {
        if self.view.forked() {
            return Vec::new();
        }
        let (cp, size) = {
            let Ok(g) = self.view.0.read() else {
                return vec![Event::Error("mirror unavailable".into())];
            };
            match g.mirror.open_checkpoint(note) {
                Ok(cp) => (cp, g.mirror.size()),
                Err(e) => return vec![Event::Error(format!("checkpoint refused: {e}"))],
            }
        };
        if self.cfg.min_cosignatures > 0 {
            match cosignatures(note, &self.cfg.witnesses) {
                Ok(c) if c.len() >= self.cfg.min_cosignatures => {}
                Ok(c) => {
                    return vec![Event::Unwitnessed {
                        size: cp.size,
                        cosignatures: c.len(),
                    }];
                }
                Err(e) => return vec![Event::Error(format!("bad cosignature: {e}"))],
            }
        }
        if cp.size < size {
            let st = self.view.0.read().map(|g| g.mirror.check(&cp));
            return match st {
                Ok(AnchorStatus::Consistent) => {
                    if let Ok(mut g) = self.view.0.write() {
                        g.stale = true;
                    }
                    vec![Event::Stale {
                        served: cp.size,
                        mirrored: size,
                    }]
                }
                Ok(_) => vec![self.fork(
                    cp.size,
                    "older checkpoint does not match the mirrored history",
                    note,
                )],
                Err(_) => vec![Event::Error("mirror unavailable".into())],
            };
        }
        self.served = self.served.max(cp.size);
        let mut records: Vec<Vec<u8>> = Vec::new();
        for b in bundles(size, cp.size) {
            let data = match link.get_tile(&b.path()).await {
                Ok(d) if d.len() <= MAX_BUNDLE_BYTES => d,
                Ok(_) => return vec![Event::Error("entry bundle too large".into())],
                Err(e) => return vec![Event::Error(format!("tile {}: {e}", b.path()))],
            };
            let recs = match parse_bundle(&data, b.width) {
                Ok(r) => r,
                Err(e) => return vec![Event::Error(format!("tile {}: {e}", b.path()))],
            };
            records.extend(
                recs.into_iter()
                    .skip(usize::try_from(b.skip).unwrap_or(usize::MAX))
                    .map(<[u8]>::to_vec),
            );
        }
        let slices: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
        let res = match self.view.0.write() {
            Ok(mut g) => {
                let out = g.mirror.update(&cp, &slices);
                if out.is_ok() {
                    g.confirmed_at = Some(Instant::now());
                    g.stale = false;
                }
                out
            }
            Err(_) => return vec![Event::Error("mirror unavailable".into())],
        };
        match res {
            Ok(alerts) => {
                let mut ev = Vec::with_capacity(alerts.len().saturating_add(2));
                if let Err(e) = self.persist(&records, note) {
                    ev.push(Event::Error(format!("persist: {e}")));
                }
                if cp.size > size {
                    ev.push(Event::Synced { size: cp.size });
                }
                ev.extend(alerts.into_iter().map(Event::Alert));
                ev
            }
            Err(Error::Fork { size }) => {
                vec![self.fork(size, "checkpoint does not match the mirrored history", note)]
            }
            Err(e) => vec![Event::Error(format!("sync: {e}"))],
        }
    }

    /// Compares the newest public Git-anchor checkpoint with the mirror.
    pub fn on_anchor(&mut self, note: &[u8]) -> Vec<Event> {
        let st = match self.view.0.read() {
            Ok(g) => g
                .mirror
                .open_checkpoint(note)
                .map(|cp| (cp, g.mirror.check(&cp))),
            Err(_) => return vec![Event::Error("mirror unavailable".into())],
        };
        match st {
            Err(e) => vec![Event::Error(format!("anchor refused: {e}"))],
            Ok((cp, AnchorStatus::Consistent)) => vec![Event::AnchorConsistent { size: cp.size }],
            Ok((cp, AnchorStatus::Fork)) => vec![self.fork(
                cp.size,
                "public Git anchor differs from the relay's history",
                note,
            )],
            Ok((cp, AnchorStatus::Behind)) => vec![Event::Rollback {
                anchored: cp.size,
                served: self.served,
            }],
        }
    }

    fn fork(&self, size: u64, detail: &str, evidence: &[u8]) -> Event {
        if let Ok(mut g) = self.view.0.write() {
            g.fork = Some(detail.to_owned());
        }
        if let Some(dir) = &self.cfg.dir {
            // Keep the conflicting signed note: it is proof of relay misbehavior.
            let _ = fs::write(dir.join("fork-evidence"), evidence);
        }
        Event::Fork {
            size,
            detail: detail.to_owned(),
        }
    }

    /// Appends new records (u16-BE length-prefixed) then replaces the checkpoint note.
    /// A crash in between leaves extra records, which `open` ignores.
    fn persist(&self, records: &[Vec<u8>], note: &[u8]) -> Result<(), Error> {
        let Some(dir) = &self.cfg.dir else {
            return Ok(());
        };
        if !records.is_empty() {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("records"))
                .map_err(io_err)?;
            let mut buf = Vec::new();
            for r in records {
                buf.extend_from_slice(
                    &u16::try_from(r.len())
                        .map_err(|_| Error::TooLarge)?
                        .to_be_bytes(),
                );
                buf.extend_from_slice(r);
            }
            f.write_all(&buf).map_err(io_err)?;
            f.sync_data().map_err(io_err)?;
        }
        let tmp = dir.join("checkpoint.tmp");
        fs::write(&tmp, note).map_err(io_err)?;
        fs::rename(&tmp, dir.join("checkpoint")).map_err(io_err)
    }
}

/// Splits the persisted records file into its first `n` records.
fn parse_records_file(b: &[u8], n: u64) -> Result<Vec<&[u8]>, Error> {
    let mut out = Vec::new();
    let mut rest = b;
    while u64::try_from(out.len()).unwrap_or(u64::MAX) < n {
        let (len, r) = rest
            .split_first_chunk::<2>()
            .ok_or(Error::Format("records file truncated"))?;
        let len = usize::from(u16::from_be_bytes(*len));
        if len > r.len() {
            return Err(Error::Format("records file truncated"));
        }
        let (rec, r) = r.split_at(len);
        out.push(rec);
        rest = r;
    }
    Ok(out)
}

/// Fetches and verifies the relay's current checkpoint over the link (fallback when no
/// push is available, e.g. a one-shot `moochy verify`).
pub async fn fetch_checkpoint<L: LogLink>(link: &mut L) -> Result<Vec<u8>, Error> {
    let n = link.get_tile("checkpoint").await?;
    if n.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(n)
}

/// Fetches `GetLogTile("projection/<receipt_ref>")` (E63): the relay's JSON reply
/// `{"projection_b64","sig_b64","worker_device","key_log_index"}`, size-capped. The
/// caller parses it with its strict JSON parser and checks it with
/// [`View::verify_projection`]; nothing in it is trusted.
pub async fn fetch_projection<L: LogLink>(
    link: &mut L,
    receipt_ref: &str,
) -> Result<Vec<u8>, Error> {
    if !crate::projection::valid_ref(receipt_ref) {
        return Err(Error::Format("receipt_ref"));
    }
    let b = link.get_tile(&format!("projection/{receipt_ref}")).await?;
    if b.len() > crate::projection::MAX_REPLY {
        return Err(Error::TooLarge);
    }
    Ok(b)
}
