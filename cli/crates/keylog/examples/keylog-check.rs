//! `keylog-check`: sync a mirror from a relay's tile endpoints, run the monitor rules,
//! and compare with the Git anchor. Used by the Go fork test (relay/internal/tlog) and
//! handy for operators. Prints one JSON line; exit 0 = consistent, 1 = fork, 2 = error.
//!
//! keylog-check --base URL --origin O --vkey VKEY [--anchor FILE] [--state DIR]
//!              [--me PSEUDONYM --known HEX32[,HEX32…]]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    clippy::format_collect
)]

use moochy_keylog::{
    AnchorStatus, Error, Me, Mirror, NoteKey,
    fetch::Fetcher,
};
use serde_json::json;
use std::{collections::HashMap, fs, path::Path, process::ExitCode, time::Duration};

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex key");
    }
    out
}

fn report(v: &serde_json::Value, code: u8) -> ExitCode {
    println!("{v}");
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut a = HashMap::new();
    for kv in args.chunks(2) {
        if let [k, v] = kv {
            a.insert(k.trim_start_matches("--").to_owned(), v.clone());
        }
    }
    let need = |k: &str| a.get(k).cloned().unwrap_or_else(|| panic!("missing --{k}"));
    let (base, origin) = (need("base"), need("origin"));
    let key = NoteKey::parse(&need("vkey")).expect("vkey");

    // Restore the persisted mirror (records file + checkpoint note), if any.
    let state = a.get("state").map(Path::new);
    let mut m = match state.and_then(|d| Some((fs::read(d.join("records")).ok()?, fs::read(d.join("checkpoint")).ok()?))) {
        Some((recs, note)) => {
            let fresh = Mirror::new(&origin, key.clone());
            let cp = fresh.open_checkpoint(&note).expect("stored checkpoint");
            // records file: (u16_be(len) || record)*, the entry-bundle encoding.
            let mut list = Vec::new();
            let mut b = &recs[..];
            while !b.is_empty() {
                let n = u16::from_be_bytes([b[0], b[1]]) as usize;
                list.push(&b[2..2 + n]);
                b = &b[2 + n..];
            }
            Mirror::restore(&origin, key.clone(), list, &cp).expect("restore")
        }
        None => Mirror::new(&origin, key.clone()),
    };
    if let Some(ps) = a.get("me") {
        let known = a.get("known").map(|k| k.split(',').map(hex32).collect()).unwrap_or_default();
        m.set_me(Some(Me { pseudonym: ps.clone(), known_keys: known }));
    }

    let f = Fetcher::new(&base, Duration::from_secs(10)).expect("base url");
    let synced = match f.sync(&mut m) {
        Ok(v) => v,
        Err(e @ Error::Fork { .. }) => return report(&json!({"fork": true, "error": e.to_string()}), 1),
        Err(e) => return report(&json!({"error": e.to_string()}), 2),
    };

    // Persist new records and the checkpoint.
    if let Some(d) = state {
        fs::create_dir_all(d).unwrap();
        let mut recs = fs::read(d.join("records")).unwrap_or_default();
        for r in &synced.records {
            recs.extend_from_slice(&(r.len() as u16).to_be_bytes());
            recs.extend_from_slice(r);
        }
        fs::write(d.join("records"), recs).unwrap();
        fs::write(d.join("checkpoint"), &synced.note).unwrap();
    }
    let (cp, alerts) = (synced.checkpoint, synced.alerts);

    let anchor = match a.get("anchor") {
        None => "none",
        Some(p) => match fs::read(p).map_err(|e| Error::Io(e.to_string())).and_then(|n| m.open_checkpoint(&n)) {
            Err(e) => return report(&json!({"error": format!("anchor: {e}")}), 2),
            Ok(acp) => match m.check(&acp) {
                AnchorStatus::Consistent => "consistent",
                AnchorStatus::Behind => "behind",
                AnchorStatus::Fork => "fork",
            },
        },
    };
    let alerts: Vec<String> = alerts.iter().map(|x| format!("{x:?}")).collect();
    let root: String = cp.root.iter().map(|b| format!("{b:02x}")).collect();
    let fork = anchor == "fork";
    report(&json!({"size": cp.size, "root": root, "alerts": alerts, "anchor": anchor, "fork": fork}), u8::from(fork))
}
