//! Durable local journal (E62, 07 §2 `moochy journal`): every task this device consumed or served,
//! metadata only (request/response text only with the `journal_full_text` opt-in), on disk so it
//! survives restarts and feeds `moochy audit`.
//!
//! `<state>/journal/YYYY-MM-DD.jsonl`, one JSON object per line, one file per UTC day (rotation);
//! files older than 90 days are deleted (retention); a day stops growing at 64 MiB. Writes go
//! through a bounded channel to one writer thread (never blocking I/O on the async runtime; a full
//! channel drops the entry from disk, it stays in memory).

use crate::pb::local::JournalEntry;
use crate::util::{b64d, b64e};
use serde_json::{Value, json};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::mpsc::{SyncSender, sync_channel};

pub const RETENTION_DAYS: u64 = 90;
const MAX_DAY_BYTES: u64 = 64 << 20;
const QUEUE: usize = 1024;
const DAY_MS: u64 = 86_400_000;

static WRITER: OnceLock<SyncSender<JournalEntry>> = OnceLock::new();

/// `<state>/journal`.
pub fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("journal")
}

/// Start the writer (once per process). Applies retention now and at every day change.
pub fn start(state_dir: &Path) {
    let d = dir(state_dir);
    if std::fs::create_dir_all(&d).is_err() {
        return;
    }
    let (tx, rx) = sync_channel::<JournalEntry>(QUEUE);
    if WRITER.set(tx).is_err() {
        return;
    }
    prune(&d, crate::util::now_ms());
    let _ = std::thread::Builder::new().name("moochy-journal".into()).spawn(move || {
        let mut day = String::new();
        while let Ok(e) = rx.recv() {
            let today = utc_day(crate::util::now_ms());
            if today != day {
                prune(&d, crate::util::now_ms());
                day.clone_from(&today);
            }
            let p = d.join(format!("{today}.jsonl"));
            if std::fs::metadata(&p).map_or(0, |m| m.len()) >= MAX_DAY_BYTES {
                continue;
            }
            let mut line = encode(&e).to_string();
            line.push('\n');
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
                let _ = f.write_all(line.as_bytes());
            }
        }
    });
}

/// Queue an entry for disk (non-blocking).
pub fn append(e: &JournalEntry) {
    if let Some(tx) = WRITER.get() {
        let _ = tx.try_send(e.clone());
    }
}

fn encode(e: &JournalEntry) -> Value {
    let mut v = json!({"t_ms": e.t_ms, "role": e.role, "task": e.task, "repo": e.repo, "model": e.model, "status": e.status, "cost_uusd": e.cost_uusd, "ms": e.ms, "tokens_in": e.tokens_in, "tokens_out": e.tokens_out,
        "receipt_ref": e.receipt_ref, "receipt_check": e.receipt_check, "pledge_id": e.pledge_id});
    if let Some(o) = v.as_object_mut() {
        if !e.request.is_empty() {
            o.insert("request_b64".into(), json!(b64e(&e.request)));
        }
        if !e.response.is_empty() {
            o.insert("response_b64".into(), json!(b64e(&e.response)));
        }
    }
    v
}

fn decode(line: &str) -> Option<JournalEntry> {
    let v: Value = serde_json::from_str(line).ok()?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
    let b = |k: &str| v.get(k).and_then(Value::as_str).and_then(b64d).unwrap_or_default();
    Some(JournalEntry {
        t_ms: v.get("t_ms")?.as_i64()?,
        role: s("role"),
        task: s("task"),
        repo: s("repo"),
        model: s("model"),
        status: s("status"),
        cost_uusd: v.get("cost_uusd").and_then(Value::as_i64).unwrap_or(0),
        ms: v.get("ms").and_then(Value::as_u64).and_then(|m| u32::try_from(m).ok()).unwrap_or(0),
        request: b("request_b64"),
        response: b("response_b64"),
        tokens_in: v.get("tokens_in").and_then(Value::as_u64).unwrap_or(0),
        tokens_out: v.get("tokens_out").and_then(Value::as_u64).unwrap_or(0),
        receipt_ref: s("receipt_ref"),
        receipt_check: s("receipt_check"),
        pledge_id: s("pledge_id"),
    })
}

/// Day files, oldest first (names are `YYYY-MM-DD.jsonl`, so lexical = chronological).
fn day_files(d: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .map(|it| it.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(is_day_file)).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn is_day_file(n: &str) -> bool {
    n.len() == 16 && n.get(10..) == Some(".jsonl") && n.bytes().take(10).enumerate().all(|(i, c)| if i == 4 || i == 7 { c == b'-' } else { c.is_ascii_digit() })
}

/// The newest `n` entries (oldest first), across day files.
pub fn load_recent(state_dir: &Path, n: usize) -> Vec<JournalEntry> {
    let mut out: Vec<JournalEntry> = Vec::new();
    for p in day_files(&dir(state_dir)).iter().rev() {
        let Ok(text) = std::fs::read_to_string(p) else { continue };
        let mut day: Vec<JournalEntry> = text.lines().filter_map(decode).collect();
        day.append(&mut out);
        out = day;
        if out.len() >= n {
            break;
        }
    }
    let skip = out.len().saturating_sub(n);
    out.into_iter().skip(skip).collect()
}

/// Every entry since `since_ms` (for `moochy audit`).
pub fn since(state_dir: &Path, since_ms: u64) -> Vec<JournalEntry> {
    let first = utc_day(since_ms);
    day_files(&dir(state_dir))
        .iter()
        .filter(|p| p.file_stem().and_then(|s| s.to_str()).is_some_and(|s| s >= first.as_str()))
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| t.lines().filter_map(decode).collect::<Vec<_>>())
        .filter(|e| u64::try_from(e.t_ms).is_ok_and(|t| t >= since_ms))
        .collect()
}

/// Delete day files older than the retention window.
fn prune(d: &Path, now: u64) {
    let cutoff = utc_day(now.saturating_sub(RETENTION_DAYS.saturating_mul(DAY_MS)));
    for p in day_files(d) {
        if p.file_stem().and_then(|s| s.to_str()).is_some_and(|s| s < cutoff.as_str()) {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// `YYYY-MM-DD` (UTC) of a Unix-ms instant.
pub fn utc_day(ms: u64) -> String {
    crate::worker::utc_day(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_retention() {
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(1_790_919_646_000), "2026-10-02");
        assert_eq!(utc_day(951_782_400_000), "2000-02-29");
        let base = std::env::temp_dir().join(format!("moochy-journal-{}", std::process::id()));
        let d = dir(&base);
        std::fs::create_dir_all(&d).unwrap();
        let now = 1_790_919_646_000u64;
        let old = utc_day(now - 91 * DAY_MS);
        let recent = utc_day(now - 89 * DAY_MS);
        let e = |t: u64, task: &str| JournalEntry { t_ms: i64::try_from(t).unwrap(), role: "worker".into(), task: task.into(), status: "ok".into(), ..JournalEntry::default() };
        std::fs::write(d.join(format!("{old}.jsonl")), format!("{}\n", encode(&e(now - 91 * DAY_MS, "old")))).unwrap();
        std::fs::write(d.join(format!("{recent}.jsonl")), format!("{}\n{}\n", encode(&e(now - 89 * DAY_MS, "a")), encode(&e(now - 89 * DAY_MS + 1, "b")))).unwrap();
        std::fs::write(d.join("notes.txt"), "x").unwrap();
        prune(&d, now);
        assert!(!d.join(format!("{old}.jsonl")).exists(), "older than 90 days is deleted");
        assert!(d.join("notes.txt").exists(), "only day files are touched");
        let got: Vec<String> = load_recent(&base, 1).into_iter().map(|e| e.task).collect();
        assert_eq!(got, vec!["b".to_owned()], "newest first n, in order");
        assert_eq!(since(&base, now - 90 * DAY_MS).len(), 2);
        let _ = std::fs::remove_dir_all(&base);
    }
}
