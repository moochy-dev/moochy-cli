//! `keylog-check`: one monitor round against a relay's tile endpoints (HTTP), with the
//! same `Monitor` the Node runs over its gRPC link: sync + verify, monitor rules,
//! persistence, Git-anchor comparison. Used by the Go E2E test in relay/internal/tlog
//! and handy for operators. Prints one JSON line:
//! `{"size","gate","events":[messages],"fork","rollback","stale"}`; exit 0 = no fork,
//! rollback or stale checkpoint, 1 = one of those, 2 = usage.
//!
//! keylog-check --base URL --origin O --vkey VKEY [--anchor FILE] [--state DIR]
//!              [--me PSEUDONYM --known HEX32,… --known-owner HEX32,…]
//!              [--witness VKEY --min-cosigs N]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unused_async_trait_impl
)]

use moochy_keylog::{
    Error, Event, LogLink, Me, Monitor, NoteKey,
    cosig::CosignerKey,
    fetch::Fetcher,
    monitor::Config,
    tiles::{MAX_BUNDLE_BYTES, MAX_CHECKPOINT_BYTES},
};
use serde_json::json;
use std::{
    collections::HashMap,
    future::Future,
    path::PathBuf,
    pin::pin,
    process::ExitCode,
    task::{Context, Poll, Waker},
    time::Duration,
};

/// HTTP stand-in for the Node's gRPC link: one checkpoint, then the anchor file.
struct HttpLink {
    f: Fetcher,
    once: bool,
    anchor: Option<PathBuf>,
}

impl LogLink for HttpLink {
    async fn get_tile(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        self.f.get(path, MAX_BUNDLE_BYTES) // blocking: fine for a one-shot CLI
    }
    async fn next_checkpoint(&mut self) -> Option<Vec<u8>> {
        if std::mem::replace(&mut self.once, false) {
            self.f.get("checkpoint", MAX_CHECKPOINT_BYTES).ok()
        } else {
            None
        }
    }
    async fn anchor(&mut self) -> Option<Vec<u8>> {
        self.anchor.take().and_then(|p| std::fs::read(p).ok())
    }
}

fn block_on<F: Future>(f: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn hex32s(s: &str) -> Vec<[u8; 32]> {
    s.split(',')
        .filter(|k| !k.is_empty())
        .map(|k| {
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&k[2 * i..2 * i + 2], 16).expect("hex key");
            }
            out
        })
        .collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut a = HashMap::new();
    for kv in args.chunks(2) {
        if let [k, v] = kv {
            a.insert(k.trim_start_matches("--").to_owned(), v.clone());
        }
    }
    let (Some(base), Some(origin), Some(vkey)) = (a.get("base"), a.get("origin"), a.get("vkey"))
    else {
        eprintln!(
            "usage: keylog-check --base URL --origin O --vkey VKEY [--anchor FILE] [--state DIR] [--me PS --known HEX,… --known-owner HEX,…] [--witness VKEY --min-cosigs N]"
        );
        return ExitCode::from(2);
    };
    let me = a.get("me").map(|ps| Me {
        pseudonym: ps.clone(),
        known_keys: a.get("known").map(|k| hex32s(k)).unwrap_or_default(),
        known_owner_keys: a.get("known-owner").map(|k| hex32s(k)).unwrap_or_default(),
    });
    let cfg = Config {
        origin: origin.clone(),
        key: NoteKey::parse(vkey).expect("vkey"),
        dir: a.get("state").map(PathBuf::from),
        me,
        witnesses: a
            .get("witness")
            .map(|w| vec![CosignerKey::parse(w).expect("witness vkey")])
            .unwrap_or_default(),
        min_cosignatures: a
            .get("min-cosigs")
            .map_or(0, |n| n.parse().expect("min-cosigs")),
    };
    let mut m = Monitor::open(cfg).expect("open monitor");
    let mut link = HttpLink {
        f: Fetcher::new(base, Duration::from_secs(10)).expect("base url"),
        once: true,
        anchor: a.get("anchor").map(PathBuf::from),
    };
    let mut events: Vec<Event> = Vec::new();
    block_on(m.run(&mut link, |e| events.push(e.clone())));
    let has = |f: fn(&Event) -> bool| events.iter().any(f);
    let fork = has(|e| matches!(e, Event::Fork { .. })) || m.view().forked();
    let rollback = has(|e| matches!(e, Event::Rollback { .. }));
    let stale = has(|e| matches!(e, Event::Stale { .. }));
    let msgs: Vec<String> = events.iter().map(Event::message).collect();
    let gate = format!("{:?}", m.view().gate());
    println!(
        "{}",
        json!({"size": m.view().size(), "gate": gate, "events": msgs, "fork": fork, "rollback": rollback, "stale": stale})
    );
    ExitCode::from(u8::from(fork || rollback || stale))
}
