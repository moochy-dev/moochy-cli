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

pub struct KeyLog {
    view: View,
    /// Taken by [`KeyLog::start`].
    monitor: Mutex<Option<Monitor>>,
    /// Newest checkpoint note served by the relay (latest wins).
    notes: watch::Sender<Option<Vec<u8>>>,
}

impl KeyLog {
    /// `None` when no log key is configured (or it is unusable): nothing is trusted then.
    pub fn open(home: &Home, cfg: &Config, sign_pub: Option<[u8; 32]>, owner_keys: Vec<[u8; 32]>) -> Option<Arc<Self>> {
        let key = match NoteKey::parse(cfg.log_key.as_deref()?) {
            Ok(k) => k,
            Err(e) => {
                log("error", "key log disabled: bad log_key", &json!({"error": e.to_string()}));
                return None;
            }
        };
        let origin = cfg.log_origin.clone().unwrap_or_else(|| key.name().to_owned());
        let tag = crate::config::origin_tag(cfg.relay.as_deref().unwrap_or(""));
        let me = match (cfg.pseudonym.clone(), sign_pub) {
            (Some(pseudonym), Some(pk)) => Some(Me { pseudonym, known_keys: vec![pk] }),
            _ => None,
        };
        let mc = monitor::Config {
            origin,
            key,
            dir: Some(home.state_dir().join(format!("keylog-{tag}"))),
            me,
            known_owner_keys: owner_keys,
            witnesses: Vec::new(),
            min_cosignatures: 0,
        };
        match Monitor::open(mc) {
            Ok(m) => Some(Arc::new(Self { view: m.view(), monitor: Mutex::new(Some(m)), notes: watch::channel(None).0 })),
            Err(e) => {
                log("error", "key log disabled: mirror cannot be opened", &json!({"error": e.to_string()}));
                None
            }
        }
    }

    /// Run the monitor for the node's lifetime (once).
    pub fn start(self: &Arc<Self>, node: &Arc<Node>) {
        let Some(mut m) = lock(&self.monitor).take() else { return };
        let mut link = Link { node: node.clone(), notes: self.notes.subscribe(), anchor_due: Instant::now() };
        tokio::spawn(async move {
            m.run(&mut link, |e| {
                let (level, mut fields) = event_fields(e);
                if let Some(o) = fields.as_object_mut() {
                    o.insert("keylog".into(), json!(e.message()));
                }
                log(level, "key log", &fields);
            })
            .await;
        });
    }

    /// A checkpoint note from the relay (`Hello.log_checkpoint` or a push).
    pub fn push(&self, note: Vec<u8>) {
        if !note.is_empty() && note.len() <= moochy_keylog::note::MAX_NOTE {
            self.notes.send_replace(Some(note));
        }
    }

    /// A fresh verified checkpoint exists: the log, not the relay, decides trust.
    pub fn verified(&self) -> bool {
        matches!(self.view.gate(), Gate::Verified { .. })
    }

    /// Wording of the sealing gate (status, logs).
    pub fn gate_name(&self) -> &'static str {
        match self.view.gate() {
            Gate::NoCheckpoint => "no_checkpoint",
            Gate::Verified { .. } => "verified",
            Gate::Stale { .. } => "stale_log",
            Gate::Forked => "log_forked",
        }
    }

    /// Worker side (03 §7.2 1–2): the logged signing key of a Gateway device allowed to use
    /// `repo_id`. Only from a fresh verified log.
    pub fn gateway_key(&self, device: &str, repo_id: &str) -> Option<[u8; 32]> {
        if !self.verified() {
            return None;
        }
        self.view.gateway_allowed(device, repo_id).ok().map(|d| d.sign_pub)
    }

    /// Gateway sealing rule (CONTRACT §15.4, A174, A184): the gate is verified, the worker is
    /// logged, unrevoked and owner-approved for `repo_id` at exactly the relay's indexes, and the
    /// relay-advertised keys are the logged ones. Returns the LOGGED signing key (receipts and
    /// progress checkpoints are verified with it, never with a relay-supplied one).
    pub fn seal(&self, repo_id: &str, w: &PoolWorker) -> Result<[u8; 32], Code> {
        let s = self.view.seal_check(&w.worker_device, repo_id, w.key_log_index, w.approval_log_index)?;
        let sign_pub = self.view.state(|st| st.device(&w.worker_device).map(|d| d.sign_pub))?.ok_or(Code::UnknownDevice)?;
        let same_sign = w.sign_pub.is_none_or(|p| crate::util::ct_eq(&p, &sign_pub));
        if !crate::util::ct_eq(&s.enc_pub, &w.enc_pub) || !same_sign {
            return Err(Code::IndexMismatch);
        }
        Ok(sign_pub)
    }
}

/// Log level + stable machine fields of a monitor event (the message carries the keywords
/// `unknown_key`, `rogue`, `unsigned`, `fork`, `stale`, `rollback` that tooling greps).
fn event_fields(e: &Event) -> (&'static str, serde_json::Value) {
    match e {
        Event::Synced { size } => ("info", json!({"event": "synced", "size": size})),
        Event::AnchorConsistent { size } => ("info", json!({"event": "anchor_consistent", "size": size})),
        Event::Error(_) => ("warn", json!({"event": "error"})),
        Event::Alert(a) => ("error", alert_fields(a)),
        Event::Fork { size, .. } => ("error", json!({"event": "fork", "size": size})),
        Event::Stale { served, mirrored } => ("error", json!({"event": "stale", "served": served, "mirrored": mirrored})),
        Event::Rollback { anchored, served } => ("error", json!({"event": "rollback", "anchored": anchored, "served": served})),
        Event::Unwitnessed { size, cosignatures } => ("error", json!({"event": "unwitnessed", "size": size, "cosignatures": cosignatures})),
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
    }
}

/// The monitor's view of the relay link: the node's current authenticated channel.
struct Link {
    node: Arc<Node>,
    notes: watch::Receiver<Option<Vec<u8>>>,
    anchor_due: Instant,
}

impl moochy_keylog::LogLink for Link {
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
        let url = self.node.cfg.log_anchor_url.clone()?;
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
