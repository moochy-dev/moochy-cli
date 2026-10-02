//! Key-log monitor (06 §10, spec/KEYLOG.md, `moochy-keylog/WIRING.md`).
//!
//! One [`moochy_keylog::Monitor`] per relay origin, persisted under `<home>/state/keylog-<tag>/`
//! (records, checkpoint, fork evidence). It is fed by the relay's checkpoints
//! (`Hello.log_checkpoint`, pushed `LogCheckpoint`, else a poll every minute), fetches tiles
//! through `NodeLink.GetLogTile`, checks the public Git anchor hourly when configured, and
//! raises the own-key / owner alerts. The shared [`View`] answers the two trust questions:
//! which worker keys a Gateway may seal to ([`KeyLog::seal`], CONTRACT §15.4) and which Gateway
//! keys a Worker accepts ([`KeyLog::gateway_key`], 03 §7.2).
//!
//! Requires the log's note key (`config set log_key`). Without it, or before the first verified
//! checkpoint, nothing is sealed and no task is accepted, except under `MOOCHY_INSECURE_DEV=1`
//! (D14, relay-asserted, tests and development only).

use crate::config::{Config, Home};
use crate::node::{Node, PoolWorker, lock};
use crate::pb::link::LogTileRequest;
use crate::util::{clean, log};
use moochy_keylog::monitor::{self, Event, Gate, Monitor, View};
use moochy_keylog::{Alert, Code, Me, NoteKey};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

const TILE_TIMEOUT: Duration = Duration::from_secs(10);
const ANCHOR_EVERY: Duration = Duration::from_secs(3600);

/// The default relay's key-log verifier key, compiled into release builds
/// (`MOOCHY_DEFAULT_LOG_VKEY` at build time, CONTRACT §6).
pub const DEFAULT_LOG_VKEY: Option<&str> = option_env!("MOOCHY_DEFAULT_LOG_VKEY");

/// The key this node verifies the log with: the configured `log_key` (`login --log-key`,
/// `config set log_key`), else the compiled-in key when talking to the default relay. Never
/// anything the relay says.
pub fn effective_log_key(cfg: &Config) -> Option<String> {
    cfg.log_key.clone().or_else(|| {
        DEFAULT_LOG_VKEY.filter(|k| default_relay(cfg) && !k.is_empty()).map(str::to_owned)
    })
}

/// The default relay's public Git anchor of the key log (raw-file base URL), compiled into
/// release builds (`MOOCHY_DEFAULT_LOG_ANCHOR`, T-C06-015).
pub const DEFAULT_LOG_ANCHOR: Option<&str> = option_env!("MOOCHY_DEFAULT_LOG_ANCHOR");

fn default_relay(cfg: &Config) -> bool {
    cfg.relay.as_deref().is_none_or(|r| crate::tls::Origin::parse(r).is_ok_and(|o| o.url() == crate::config::DEFAULT_RELAY))
}

/// The anchor this node checks hourly: `log_anchor_url`, else the compiled-in default for the
/// default relay (https only).
pub fn effective_anchor(cfg: &Config) -> Option<String> {
    cfg.log_anchor_url
        .clone()
        .or_else(|| DEFAULT_LOG_ANCHOR.filter(|u| default_relay(cfg) && u.starts_with("https://")).map(str::to_owned))
}

pub struct KeyLog {
    view: Mutex<View>,
    /// Taken by [`KeyLog::start`].
    monitor: Mutex<Option<Monitor>>,
    state: std::path::PathBuf,
    /// Newest checkpoint note served by the relay (latest wins).
    notes: watch::Sender<Option<Vec<u8>>>,
}

/// Own keys created while the node runs (`<state>/owner_keys`, `<state>/device_keys`): one
/// base64url key per line, deduplicated.
fn read_keys(path: &std::path::Path) -> Vec<[u8; 32]> {
    let mut v: Vec<[u8; 32]> = std::fs::read_to_string(path).map(|s| s.lines().filter_map(|l| crate::util::b64d32(l.trim())).take(64).collect()).unwrap_or_default();
    v.sort_unstable();
    v.dedup();
    v
}

fn add_key(path: &std::path::Path, k: &[u8; 32]) {
    if read_keys(path).contains(k) {
        return;
    }
    let mut all = std::fs::read_to_string(path).unwrap_or_default();
    all.push_str(&crate::util::b64e(k));
    all.push('\n');
    let _ = crate::config::write_private(path, all.as_bytes());
}

/// The `ok_…` id of a passkey owner key from its digest (`owner_key_id(cose)` = the first 16
/// bytes of `passkey_digest(cose)`, hex).
fn passkey_id(digest: &[u8; 32]) -> String {
    std::iter::once("ok_".to_owned()).chain(digest.iter().take(16).map(|b| format!("{b:02x}"))).collect()
}

/// One box device of this account, from the key log (`KeyLog::boxes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxRow {
    pub device_id: String,
    /// Its enrollment token (`bt_…`).
    pub box_id: String,
    /// The one repo it may use.
    pub repo_id: String,
    pub expires_at_ms: u64,
    pub revoked: bool,
    /// `now ≥ expires_at_ms`.
    pub expired: bool,
}

impl KeyLog {
    /// `None` when no log key is configured (or it is unusable): nothing is trusted then.
    pub fn open(home: &Home, cfg: &Config, sign_pub: Option<[u8; 32]>) -> Option<Arc<Self>> {
        let vkey = effective_log_key(cfg)?;
        let key = match NoteKey::parse(&vkey) {
            Ok(k) => k,
            Err(e) => {
                log("error", "key log disabled: bad log_key", &json!({"error": e.to_string()}));
                return None;
            }
        };
        let origin = cfg.log_origin.clone().unwrap_or_else(|| key.name().to_owned());
        let tag = crate::config::origin_tag(cfg.relay.as_deref().unwrap_or(""));
        let state = home.state_dir();
        // A box (§17.1) runs the monitor for the gate only: its owner's other boxes and keys are
        // not its business (WIRING §9b).
        let me = match (cfg.pseudonym.clone(), sign_pub) {
            (Some(pseudonym), Some(pk)) if cfg.box_device.is_none() => {
                let mut known_keys = read_keys(&state.join("device_keys"));
                known_keys.push(pk);
                Some(Me { pseudonym, known_keys })
            }
            _ => None,
        };
        let mc = monitor::Config {
            origin,
            key,
            dir: Some(home.state_dir().join(format!("keylog-{tag}"))),
            me,
            known_owner_keys: read_keys(&state.join("owner_keys")),
            witnesses: Vec::new(),
            min_cosignatures: 0,
        };
        match Monitor::open(mc) {
            Ok(m) => Some(Arc::new(Self {
                view: Mutex::new(m.view()),
                monitor: Mutex::new(Some(m)),
                state,
                notes: watch::channel(None).0,
            })),
            Err(e) => {
                log("error", "key log disabled: mirror cannot be opened", &json!({"error": e.to_string()}));
                None
            }
        }
    }

    /// Foreground CLI: this node's persisted mirror, read from disk — independent of `node.sock`,
    /// and trustworthy: the records must reproduce a checkpoint signed by the pinned log key
    /// (`Monitor::open`). `None`: no key log on this node.
    fn mirror(home: &Home, cfg: &Config) -> Option<View> {
        let key = NoteKey::parse(&effective_log_key(cfg)?).ok()?;
        let origin = cfg.log_origin.clone().unwrap_or_else(|| key.name().to_owned());
        let tag = crate::config::origin_tag(cfg.relay.as_deref().unwrap_or(""));
        let mc = monitor::Config {
            origin,
            key,
            dir: Some(home.state_dir().join(format!("keylog-{tag}"))),
            me: None,
            known_owner_keys: Vec::new(),
            witnesses: Vec::new(),
            min_cosignatures: 0,
        };
        Monitor::open(mc).ok().map(|m| m.view())
    }

    /// Owner commands: the pseudonym that owns `device` in the mirror. Outer `None`: no key log
    /// on this node; inner `None`: the device is not in the log.
    pub fn device_owner(home: &Home, cfg: &Config, device: &str) -> Option<Option<String>> {
        Some(Self::mirror(home, cfg)?.state(|s| s.device(device).filter(|d| !d.revoked).map(|d| d.pseudonym.clone())).ok().flatten())
    }

    /// Owner commands (A224): the account's active Ed25519 owner key id in the mirror. Outer
    /// `None`: no key log on this node; inner `None`: none logged (yet).
    pub fn active_owner_key(home: &Home, cfg: &Config, pseudonym: &str) -> Option<Option<String>> {
        Some(Self::mirror(home, cfg)?.state(|s| s.active_owner_key(pseudonym).map(|k| k.id.clone())).ok().flatten())
    }

    /// `moochy owner trust` (A224): an owner key of `pseudonym` as the mirror shows it:
    /// `(log index, revoked, Some(email_proof) for a passkey)`. Outer `None`: no key log.
    pub fn owner_key_row(home: &Home, cfg: &Config, pseudonym: &str, id: &str) -> Option<Option<(u64, bool, Option<bool>)>> {
        Some(
            Self::mirror(home, cfg)?
                .state(|s| s.owner_key(id).filter(|k| k.pseudonym == pseudonym).map(|k| (k.idx, k.revoked, k.passkey.as_ref().map(|p| p.email_proof))))
                .ok()
                .flatten(),
        )
    }

    /// `moochy box list` (§17.1, WIRING §9b): this account's boxes in the mirror, in log order,
    /// revoked and expired ones included. `None`: no key log on this node (or not logged in).
    pub fn boxes(home: &Home, cfg: &Config) -> Option<Vec<BoxRow>> {
        let ps = cfg.pseudonym.as_deref()?;
        let now = crate::util::now_ms();
        Self::mirror(home, cfg)?
            .state(|s| {
                s.boxes(ps)
                    .into_iter()
                    .map(|(id, d)| BoxRow {
                        device_id: id.to_owned(),
                        box_id: d.box_id.clone().unwrap_or_default(),
                        repo_id: d.repo_scope.clone().unwrap_or_default(),
                        expires_at_ms: d.expires_at_ms,
                        revoked: d.revoked,
                        expired: d.expires_at_ms != 0 && now >= d.expires_at_ms,
                    })
                    .collect()
            })
            .ok()
    }

    /// `moochy owner init` on an account with passkeys (KEYLOG §4b): an active passkey owner key
    /// of `pseudonym` that the human already trusted on this device (`moochy owner trust`, which
    /// records its digest; a passkey's id is the first half of that digest). Never one the relay
    /// names. Outer `None`: no key log.
    pub fn passkey_authorizer(home: &Home, cfg: &Config, pseudonym: &str) -> Option<Option<String>> {
        let trusted = read_keys(&home.state_dir().join("owner_keys"));
        Some(
            Self::mirror(home, cfg)?
                .state(|s| {
                    trusted.iter().find_map(|d| {
                        s.owner_key(&passkey_id(d)).filter(|k| k.passkey.is_some() && !k.revoked && k.pseudonym == pseudonym && k.owner_pub == *d).map(|k| k.id.clone())
                    })
                })
                .ok()
                .flatten(),
        )
    }

    /// Run the monitor for the node's lifetime (once).
    pub fn start(self: &Arc<Self>, node: &Arc<Node>) {
        let Some(mut m) = lock(&self.monitor).take() else { return };
        let mut link = Link { node: node.clone(), notes: self.notes.subscribe(), anchor_due: Instant::now() };
        tokio::spawn(async move {
            m.run(&mut link, |e| {
                let (level, msg, mut fields) = event_fields(e);
                if let Some(o) = fields.as_object_mut() {
                    o.insert("keylog".into(), json!(e.message()));
                }
                log(level, &msg, &fields);
            })
            .await;
        });
    }

    /// A key this user just created (owner key, or a rotated device key), relayed by this node:
    /// remember it so the monitor does not report it as someone else's (`unknown_*`).
    pub fn acknowledge(&self, owner_key: Option<&[u8; 32]>, device_key: Option<&[u8; 32]>) {
        let view = self.view();
        if let Some(k) = owner_key {
            add_key(&self.state.join("owner_keys"), k);
            view.acknowledge_owner_key(*k);
        }
        if let Some(k) = device_key {
            add_key(&self.state.join("device_keys"), k);
            view.acknowledge_device_key(*k);
        }
    }

    fn view(&self) -> View {
        lock(&self.view).clone()
    }

    /// A checkpoint note from the relay (`Hello.log_checkpoint` or a push).
    pub fn push(&self, note: Vec<u8>) {
        if !note.is_empty() && note.len() <= moochy_keylog::note::MAX_NOTE {
            self.notes.send_replace(Some(note));
        }
    }

    /// A fresh verified checkpoint exists: the log, not the relay, decides trust.
    pub fn verified(&self) -> bool {
        matches!(self.view().gate(), Gate::Verified { .. })
    }

    /// Wording of the sealing gate (status, logs).
    pub fn gate_name(&self) -> &'static str {
        match self.view().gate() {
            Gate::NoCheckpoint => "no_checkpoint",
            Gate::Verified { .. } => "verified",
            Gate::Stale { .. } => "stale_log",
            Gate::Forked => "log_forked",
        }
    }

    /// The logged device whose signing key this is (`moochy verify`, mo-node).
    pub fn device_by_key(&self, sign_pub: &[u8; 32]) -> Option<String> {
        self.view().state(|st| st.device_by_key(sign_pub).map(str::to_owned)).ok().flatten()
    }

    /// `moochy owner trust <ok_id>`: an owner key of THIS account (e.g. a passkey registered on
    /// the web) becomes known: no more `unknown_*` alerts for it, now and after restarts.
    /// Returns `(log index, revoked)`; `None` when it is not this account's.
    pub fn trust_owner_key(&self, id: &str, me: &str, dry_run: bool) -> Option<(u64, bool)> {
        let view = self.view();
        let info = view.state(|s| s.owner_key(id).filter(|k| k.pseudonym == me).map(|k| (k.owner_pub, k.idx, k.revoked))).ok().flatten()?;
        if !dry_run {
            self.acknowledge(Some(&info.0), None);
        }
        Some((info.1, info.2))
    }

    /// Worker side (T-03-088): this donor device holds an owner-signed DONOR_APPROVED for
    /// `repo_id` in a fresh verified log.
    pub fn donor_approved(&self, device: &str, repo_id: &str) -> bool {
        self.verified() && self.view().sealable(device, repo_id).is_ok()
    }

    /// Worker side (03 §7.2 1–2): the logged signing key of a Gateway device allowed to use
    /// `repo_id`. Only from a fresh verified log.
    pub fn gateway_key(&self, device: &str, repo_id: &str) -> Option<[u8; 32]> {
        if !self.verified() {
            return None;
        }
        self.view().gateway_allowed(device, repo_id).ok().map(|d| d.sign_pub)
    }

    /// Gateway sealing rule (CONTRACT §15.4, A174, A184): the gate is verified, the worker is
    /// logged, unrevoked and owner-approved for `repo_id` at exactly the relay's indexes, and the
    /// relay-advertised keys are the logged ones. Returns the LOGGED signing key (receipts and
    /// progress checkpoints are verified with it, never with a relay-supplied one).
    pub fn seal(&self, repo_id: &str, w: &PoolWorker) -> Result<[u8; 32], Code> {
        let view = self.view();
        let s = view.seal_check(&w.worker_device, repo_id, w.key_log_index, w.approval_log_index)?;
        let sign_pub = view.state(|st| st.device(&w.worker_device).map(|d| d.sign_pub))?.ok_or(Code::UnknownDevice)?;
        let same_sign = w.sign_pub.is_none_or(|p| crate::util::ct_eq(&p, &sign_pub));
        if !crate::util::ct_eq(&s.enc_pub, &w.enc_pub) || !same_sign {
            return Err(Code::IndexMismatch);
        }
        Ok(sign_pub)
    }
}

/// Log level + stable machine fields of a monitor event (the message carries the keywords
/// `unknown_key`, `rogue`, `unsigned`, `fork`, `stale`, `rollback` that tooling greps).
/// Messages: `key log` (routine), `key log alert` (monitor rules; `detail` names the rule and
/// its ids, e.g. `UnknownKey { idx, device_id }`, all validated ASCII), `KEY LOG FORK: …`.
fn event_fields(e: &Event) -> (&'static str, String, serde_json::Value) {
    let routine = |v| ("info", "key log".to_owned(), v);
    match e {
        Event::Synced { size } => routine(json!({"event": "synced", "size": size})),
        Event::AnchorConsistent { size } => routine(json!({"event": "anchor_consistent", "size": size})),
        Event::Error(_) => ("warn", "key log".into(), json!({"event": "error"})),
        Event::Alert(a) => {
            let mut f = alert_fields(a);
            if let Some(o) = f.as_object_mut() {
                o.insert("detail".into(), json!(format!("{a:?}")));
                // §16.6: a passkey bound on the relay's word that the mailbox was proven is a
                // takeover path if the mailbox or the relay is compromised: say so plainly.
                if let Alert::UnknownPasskey { owner_key, email_proof: true, .. } = a {
                    o.insert(
                        "warning".into(),
                        json!(format!(
                            "a passkey was registered as an owner key of your account using only an emailed link (email_proof). If it was not you, your mailbox or the server may be compromised: do not trust it. If it was you: moochy owner trust {}",
                            clean(owner_key)
                        )),
                    );
                }
            }
            // §17.1: a box of this account is news, not a threat (BoxOutsideRepo is the threat).
            if matches!(a, Alert::BoxEnrolled { .. }) {
                return ("info", "key log: box enrolled".into(), f);
            }
            // A224: a first CLI owner key without proof is a reminder when it is this device's own.
            if matches!(a, Alert::UnprovenOwnerKey { known: true, .. }) {
                return ("info", "key log: your first owner key was registered without an email proof".into(), f);
            }
            ("error", "key log alert".into(), f)
        }
        Event::Fork { size, .. } => ("error", format!("KEY LOG FORK: {}", e.message()), json!({"event": "fork", "size": size})),
        Event::Stale { served, mirrored } => ("error", "key log alert".into(), json!({"event": "stale", "served": served, "mirrored": mirrored})),
        Event::Rollback { anchored, served } => ("error", "KEY LOG FORK: rollback vs the public anchor".into(), json!({"event": "rollback", "anchored": anchored, "served": served})),
        Event::Unwitnessed { size, cosignatures } => ("error", "key log alert".into(), json!({"event": "unwitnessed", "size": size, "cosignatures": cosignatures})),
        Event::FailOpen => ("warn", e.message(), json!({"event": "fail_open"})),
    }
}

/// Stable machine fields for a mirror alert (codes, wire kind names), never Rust `Debug` text.
fn alert_fields(a: &Alert) -> serde_json::Value {
    match a {
        Alert::Invalid { idx } => json!({"alert": "invalid_record", "idx": idx}),
        Alert::Rejected { idx, kind, code } => json!({"alert": "rejected", "idx": idx, "kind": kind.name(), "code": code.as_str()}),
        Alert::UnknownKey { idx, device_id } => json!({"alert": "unknown_key", "idx": idx, "kind": "KEY_ADDED", "device_id": clean(device_id)}),
        Alert::KeyHijack { idx, device_id, pseudonym } => json!({"alert": "key_hijack", "idx": idx, "device_id": clean(device_id), "pseudonym": clean(pseudonym)}),
        Alert::NotSignedByMe { idx, kind, repo_id, signer } => json!({"alert": "unsigned", "idx": idx, "kind": kind.name(), "repo_id": clean(repo_id), "signer": clean(signer)}),
        Alert::RepoClaimedByOther { idx, repo_id, owner } => json!({"alert": "repo_claimed_by_other", "idx": idx, "repo_id": clean(repo_id), "owner": clean(owner)}),
        Alert::UnknownOwnerKey { idx, owner_key } => json!({"alert": "unknown_owner_key", "idx": idx, "kind": "OWNER_KEY_ADDED", "owner_key": clean(owner_key)}),
        Alert::OwnerKeyRevoked { idx, owner_key } => json!({"alert": "owner_key_revoked", "idx": idx, "kind": "OWNER_KEY_REVOKED", "owner_key": clean(owner_key)}),
        Alert::UnknownPasskey { idx, owner_key, rp_id, email_proof } => json!({"alert": "unknown_passkey", "idx": idx, "kind": "OWNER_KEY_ADDED", "owner_key": clean(owner_key), "rp_id": clean(rp_id), "email_proof": email_proof}),
        Alert::PasskeyCounter { idx, owner_key } => json!({"alert": "passkey_counter", "idx": idx, "code": "counter", "owner_key": clean(owner_key)}),
        Alert::BoxEnrolled { idx, device_id, repo_id, box_id, expires_at_ms } => json!({"alert": "box_enrolled", "idx": idx, "kind": "KEY_ADDED", "device_id": clean(device_id), "repo_id": clean(repo_id), "box_id": clean(box_id), "expires_at_ms": expires_at_ms}),
        Alert::BoxOutsideRepo { idx, device_id, repo_id } => json!({"alert": "box_outside_repo", "idx": idx, "kind": "KEY_ADDED", "device_id": clean(device_id), "repo_id": clean(repo_id)}),
        Alert::UnprovenOwnerKey { idx, owner_key, known } => json!({"alert": "unproven_owner_key", "idx": idx, "kind": "OWNER_KEY_ADDED", "owner_key": clean(owner_key), "known": known}),
    }
}

/// The monitor's view of the relay link: the node's current authenticated channel.
struct Link {
    node: Arc<Node>,
    notes: watch::Receiver<Option<Vec<u8>>>,
    anchor_due: Instant,
}

impl moochy_keylog::LogLink for Link {
    fn anchor_configured(&self) -> bool {
        effective_anchor(&self.node.cfg).is_some()
    }

    async fn get_tile(&mut self, path: &str) -> Result<Vec<u8>, moochy_keylog::Error> {
        let mut c = self.node.link().ok_or_else(|| moochy_keylog::Error::Io("relay link down".into()))?.client;
        let r = tokio::time::timeout(TILE_TIMEOUT, c.get_log_tile(LogTileRequest { path: path.into() }))
            .await
            .map_err(|_| moochy_keylog::Error::Io("tile timeout".into()))?
            .map_err(|s| moochy_keylog::Error::Io(clean(s.message()).into_owned()))?;
        Ok(r.into_inner().data.to_vec())
    }

    async fn next_checkpoint(&mut self) -> Option<Vec<u8>> {
        let mut stop = self.node.shutdown.subscribe();
        loop {
            tokio::select! {
                r = self.notes.changed() => {
                    r.ok()?;
                    if let Some(n) = self.notes.borrow_and_update().clone() {
                        return Some(n);
                    }
                }
                // Nothing pushed for a while: poll so the gate stays fresh (MAX_LOG_AGE).
                () = tokio::time::sleep(monitor::POLL_EVERY) => {
                    if let Ok(n) = self.get_tile("checkpoint").await {
                        return Some(n);
                    }
                }
                r = stop.changed() => {
                    if r.is_err() || *stop.borrow() {
                        return None;
                    }
                }
            }
        }
    }

    async fn anchor(&mut self) -> Option<Vec<u8>> {
        let url = effective_anchor(&self.node.cfg)?;
        if Instant::now() < self.anchor_due {
            return None;
        }
        self.anchor_due = Instant::now().checked_add(ANCHOR_EVERY)?;
        let got = tokio::task::spawn_blocking(move || moochy_keylog::fetch::Fetcher::new(&url, TILE_TIMEOUT).and_then(|f| f.get("checkpoint", moochy_keylog::note::MAX_NOTE))).await;
        if let Ok(Ok(note)) = got {
            return Some(note);
        }
        log("warn", "key-log anchor fetch failed", &json!({}));
        None
    }
}

/// `moochy verify <receipt_ref>` (E63): fetch the public projection over the link and check the
/// donor's signature against the device key logged at `key_log_index` in this node's verified
/// mirror, then that the projection names the requested reference. Without a key log, only in
/// insecure dev mode, the relay-advertised pool key is used and the answer says so.
pub async fn verify_ref(node: &Arc<Node>, receipt_ref: &str) -> Result<serde_json::Value, String> {
    if !moochy_keylog::projection::valid_ref(receipt_ref) {
        return Err("not a receipt reference".into());
    }
    if node.link_now(Duration::from_secs(5)).await.is_none() {
        return Err("not connected to the Moochy server".into());
    }
    let mut link = Link { node: node.clone(), notes: watch::channel(None).1, anchor_due: Instant::now() };
    let reply = monitor::fetch_projection(&mut link, receipt_ref).await.map_err(|e| format!("no public receipt {receipt_ref}: {e}"))?;
    let v = crate::json::parse_object(&reply).map_err(|e| format!("malformed answer: {e}"))?;
    let field = |k: &str| v.get(k).and_then(serde_json::Value::as_str).ok_or_else(|| format!("answer lacks {k}"));
    let projection = crate::util::b64d(field("projection_b64")?).ok_or("bad projection_b64")?;
    let sig = crate::util::b64d(field("sig_b64")?).ok_or("bad sig_b64")?;
    let worker = field("worker_device")?;
    let idx = v.get("key_log_index").and_then(serde_json::Value::as_u64).ok_or("answer lacks key_log_index")?;
    let p: moochy_proto::msg::Projection = serde_json::from_slice(&projection).map_err(|_| "the projection is not a valid projection".to_owned())?;
    if crate::util::b64e(&p.receipt_ref.0) != receipt_ref {
        return Err("the server answered with another receipt".into());
    }
    let (donor, revoked, trust) = match &node.keylog {
        Some(l) => {
            let ok = l.view().verify_projection(&projection, &sig, worker, idx).map_err(|c| format!("signature does not verify against the key log: {}", c.as_str()))?;
            (ok.donor_pseudonym, ok.revoked, "key_log")
        }
        None if node.insecure_dev => {
            let pk = lock(&node.pools).values().flat_map(|p| p.workers.iter()).find(|w| w.worker_device == worker).and_then(|w| w.sign_pub).ok_or("signer unknown (no key log; MOOCHY_INSECURE_DEV)")?;
            let sig: [u8; 64] = sig.as_slice().try_into().map_err(|_| "bad signature length".to_owned())?;
            moochy_proto::crypto::open_projection(&pk, &projection, &sig).map_err(|_| "signature does not verify".to_owned())?;
            (p.donor.clone().unwrap_or_default(), false, "relay_asserted_dev")
        }
        None => return Err("no key-log key: cannot verify (`moochy login --log-key …`)".into()),
    };
    Ok(serde_json::json!({"verified": true, "receipt_ref": receipt_ref, "donor": clean(&donor), "revoked": revoked, "repo_id": p.repo_id.text(),
        "model": clean(&p.model), "cost_uusd": p.cost_uusd, "day": clean(&p.day), "trust": trust}))
}

/// The default relay's receipt-log verifier key, compiled into release builds
/// (`MOOCHY_DEFAULT_RECEIPTS_VKEY`, KEYLOG §8).
pub const DEFAULT_RECEIPTS_VKEY: Option<&str> = option_env!("MOOCHY_DEFAULT_RECEIPTS_VKEY");

fn receipts_key(cfg: &Config) -> Option<NoteKey> {
    let vkey = cfg.receipts_log_key.clone().or_else(|| {
        DEFAULT_RECEIPTS_VKEY.filter(|k| default_relay(cfg) && !k.is_empty()).map(str::to_owned)
    })?;
    NoteKey::parse(&vkey).ok()
}

/// T-KL-007 (KEYLOG §8): a `ReceiptAck` proves our settled receipt is in the public receipt log:
/// `(index, inclusion proof)` against a signed receipt-log checkpoint. Verified against the pinned
/// receipt-log key; kept next to the receipt (`<state>/receipt-proofs/`); any failure is a
/// security alert (the relay could be hiding settled receipts). Without a key: not checked.
pub fn check_receipt_ack(node: &Node, receipt: &[u8], ack: &crate::pb::link::ReceiptAck) {
    let Some(key) = receipts_key(&node.cfg) else { return };
    let ids = json!({"task": clean(&ack.task), "attempt": ack.attempt});
    if ack.receipt_log_checkpoint.is_empty() {
        log("warn", "receipt log: the server acknowledged a receipt without its inclusion proof", &ids);
        return;
    }
    let alert = |why: &str| {
        let mut f = ids.clone();
        if let Some(o) = f.as_object_mut() {
            o.insert("alert".into(), json!("receipt_log"));
            o.insert("why".into(), json!(why));
        }
        log("error", "key log alert", &f);
    };
    let Ok(cp) = moochy_keylog::note::open_checkpoint(&ack.receipt_log_checkpoint, key.name(), &key) else {
        return alert("receipt-log checkpoint does not verify");
    };
    let proof: Option<Vec<moochy_keylog::Hash>> =
        (ack.receipt_log_proof.len() <= 64).then(|| ack.receipt_log_proof.iter().map(|h| <[u8; 32]>::try_from(h.as_ref()).ok()).collect()).flatten();
    let Some(proof) = proof else { return alert("malformed inclusion proof") };
    if !moochy_keylog::receipts::verify(receipt, ack.receipt_log_index, &cp, &proof) {
        return alert("our receipt is not at the claimed place in the receipt log");
    }
    let rec = json!({"index": ack.receipt_log_index, "proof": proof.iter().map(|h| crate::util::b64e(h)).collect::<Vec<_>>(),
        "checkpoint": crate::util::b64e(&ack.receipt_log_checkpoint), "tree_size": cp.size});
    let dir = node.home.state_dir().join("receipt-proofs");
    let name = format!("{}-{}.json", ack.task.chars().filter(char::is_ascii_alphanumeric).collect::<String>(), ack.attempt);
    tokio::task::spawn_blocking(move || {
        let _ = std::fs::create_dir_all(&dir);
        let _ = crate::config::write_private(&dir.join(name), rec.to_string().as_bytes());
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn passkey_ids_from_digests() {
        let cose = b"\xa5\x01\x02\x03\x26";
        assert_eq!(super::passkey_id(&moochy_keylog::state::passkey_digest(cose)), moochy_keylog::entry::owner_key_id(cose));
    }
}
