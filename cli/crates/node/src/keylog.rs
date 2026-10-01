//! Key-log mirror (06 §10, spec/KEYLOG.md) on `moochy-keylog`.
//!
//! One mirror per relay origin, persisted under `<home>/state/keylog-<tag>/` (`records`:
//! u16-BE length-prefixed records; `checkpoint`: the last verified signed note). Synced from the
//! relay's checkpoints (`Hello.log_checkpoint`, `LogCheckpoint`) with tiles fetched through
//! `NodeLink.GetLogTile`; checked hourly against the public Git anchor when configured. Once a
//! verified checkpoint exists it answers the two trust questions: which worker keys a Gateway may
//! seal to (`sealable`) and which Gateway keys a Worker accepts (`gateway_allowed`).
//! Requires the log's note key (`config set log_key`): without it the node stays relay-asserted
//! (D14) and says so.

use crate::config::{Config, Home};
use crate::node::lock;
use crate::pb::link::{LogTileRequest, node_link_client::NodeLinkClient};
use crate::util::{clean, log};
use moochy_keylog::{AnchorStatus, Me, Mirror, NoteKey, tiles};
use serde_json::json;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tonic::transport::Channel;

pub struct LogMirror {
    m: Mutex<Mirror>,
    dir: PathBuf,
    syncing: AtomicBool,
}

fn read_records(b: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<2>()?;
        let (rec, tail) = tail.split_at_checked(usize::from(u16::from_be_bytes(*len)))?;
        out.push(rec);
        rest = tail;
    }
    Some(out)
}

impl LogMirror {
    /// `None` when no log key is configured (relay-asserted mode).
    pub fn open(home: &Home, cfg: &Config, sign_pub: Option<[u8; 32]>) -> Option<Arc<Self>> {
        let key = match NoteKey::parse(cfg.log_key.as_deref()?) {
            Ok(k) => k,
            Err(e) => {
                log("error", "key log disabled: bad log_key", &json!({"error": e.to_string()}));
                return None;
            }
        };
        let origin = cfg.log_origin.clone().unwrap_or_else(|| key.name().to_owned());
        let tag = crate::config::origin_tag(cfg.relay.as_deref().unwrap_or(""));
        let dir = home.state_dir().join(format!("keylog-{tag}"));
        let restored = std::fs::read(dir.join("checkpoint")).ok().and_then(|note| {
            let cp = moochy_keylog::note::open_checkpoint(&note, &origin, &key).ok()?;
            let raw = std::fs::read(dir.join("records")).ok()?;
            Mirror::restore(&origin, key.clone(), read_records(&raw)?, &cp).ok()
        });
        let mut m = restored.unwrap_or_else(|| Mirror::new(&origin, key));
        if let (Some(ps), Some(pk)) = (cfg.pseudonym.clone(), sign_pub) {
            m.set_me(Some(Me { pseudonym: ps, known_keys: vec![pk] }));
        }
        Some(Arc::new(Self { m: Mutex::new(m), dir, syncing: AtomicBool::new(false) }))
    }

    /// A verified checkpoint exists: the log, not the relay, decides trust.
    pub fn active(&self) -> bool {
        lock(&self.m).checkpoint().is_some()
    }

    /// Worker side: the signing key of a Gateway device allowed to use `repo_id` (03 §7.2 1–2).
    pub fn gateway_key(&self, device: &str, repo_id: &str) -> Option<[u8; 32]> {
        lock(&self.m).state().gateway_allowed(device, repo_id).ok().map(|d| d.sign_pub)
    }

    /// Gateway side: the logged encryption key of an owner-approved worker for `repo_id`.
    pub fn sealable(&self, worker: &str, repo_id: &str) -> Option<[u8; 32]> {
        lock(&self.m).state().sealable(worker, repo_id).ok().map(|s| s.enc_pub)
    }

    /// Bring the mirror up to a relay checkpoint. Tiles come over the authenticated link.
    pub async fn sync(self: &Arc<Self>, mut client: NodeLinkClient<Channel>, note: Vec<u8>) {
        if self.syncing.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Err(e) = self.sync_inner(&mut client, &note).await {
            log("warn", "key log sync failed", &json!({"error": clean(&e)}));
        }
        self.syncing.store(false, Ordering::Release);
    }

    async fn sync_inner(&self, client: &mut NodeLinkClient<Channel>, note: &[u8]) -> Result<(), String> {
        let (cp, from) = {
            let m = lock(&self.m);
            (m.open_checkpoint(note).map_err(|e| format!("checkpoint: {e}"))?, m.size())
        };
        if cp.size <= from {
            return Ok(());
        }
        let mut recs: Vec<Vec<u8>> = Vec::new();
        for b in tiles::bundles(from, cp.size) {
            let r = tokio::time::timeout(Duration::from_secs(10), client.get_log_tile(LogTileRequest { path: b.path() }))
                .await
                .map_err(|_| "tile timeout".to_owned())?
                .map_err(|s| format!("tile {}: {}", b.path(), s.message()))?
                .into_inner();
            let parsed = tiles::parse_bundle(&r.data, b.width).map_err(|e| format!("tile {}: {e}", b.path()))?;
            recs.extend(parsed.into_iter().skip(usize::try_from(b.skip).unwrap_or(usize::MAX)).map(<[u8]>::to_vec));
        }
        let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
        let alerts = match lock(&self.m).update(&cp, &refs) {
            Ok(a) => a,
            Err(moochy_keylog::Error::Fork { size }) => {
                log("error", "KEY LOG FORK: the relay served a history inconsistent with the mirror; not trusting new entries", &json!({"size": size}));
                return Err("fork".into());
            }
            Err(e) => return Err(format!("update: {e}")),
        };
        self.persist(&recs, note).map_err(|e| format!("persist: {e}"))?;
        for a in &alerts {
            log("error", "public key log alert", &alert_fields(a));
        }
        Ok(())
    }

    fn persist(&self, recs: &[Vec<u8>], note: &[u8]) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.dir.join("records"))?;
        for r in recs {
            let len = u16::try_from(r.len()).map_err(|_| std::io::Error::other("record too large"))?;
            f.write_all(&len.to_be_bytes())?;
            f.write_all(r)?;
        }
        f.sync_all()?;
        crate::config::write_private(&self.dir.join("checkpoint"), note).map_err(|e| std::io::Error::other(e.msg))
    }

    /// Hourly: compare with the public Git anchor (`log_anchor_url`).
    pub async fn anchor_loop(self: Arc<Self>, url: String, mut stop: tokio::sync::watch::Receiver<bool>) {
        loop {
            let u = url.clone();
            let note = tokio::task::spawn_blocking(move || {
                moochy_keylog::fetch::Fetcher::new(&u, Duration::from_secs(10)).and_then(|f| f.get("checkpoint", moochy_keylog::note::MAX_NOTE))
            })
            .await;
            match note {
                Ok(Ok(note)) => {
                    let st = {
                        let m = lock(&self.m);
                        m.open_checkpoint(&note).map(|cp| m.check(&cp))
                    };
                    match st {
                        Ok(AnchorStatus::Fork) => log("error", "KEY LOG FORK vs the public anchor: stop trusting the relay's log", &json!({})),
                        Ok(AnchorStatus::Behind) => log("warn", "key log mirror behind the public anchor (relay may be hiding entries)", &json!({})),
                        Ok(AnchorStatus::Consistent) => {}
                        Err(e) => log("warn", "anchor checkpoint invalid", &json!({"error": e.to_string()})),
                    }
                }
                _ => log("warn", "anchor fetch failed", &json!({})),
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(3600)) => {}
                _ = stop.changed() => return,
            }
        }
    }
}

/// Stable machine fields for a mirror alert (codes, wire kind names), never Rust `Debug` text.
fn alert_fields(a: &moochy_keylog::mirror::Alert) -> serde_json::Value {
    use moochy_keylog::mirror::Alert;
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

#[cfg(test)]
mod tests {
    #[test]
    fn records_framing() {
        let raw = [0u8, 2, b'a', b'b', 0, 0, 0, 1, b'c'];
        let r = super::read_records(&raw).unwrap();
        assert_eq!(r, vec![&b"ab"[..], &b""[..], &b"c"[..]]);
        assert!(super::read_records(&[0, 5, b'a']).is_none(), "truncated");
    }
}
