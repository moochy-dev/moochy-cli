//! Monitor loop against a fake relay link serving the Go-generated vectors.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use moochy_keylog::{
    Error, Event, LogLink, Me, Monitor, NoteKey,
    cosig::CosignerKey,
    monitor::Config,
    state::Code,
    tiles::{TILE_WIDTH, tile_path},
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    future::Future,
    path::Path,
    pin::pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

fn load(name: &str) -> Value {
    let p = format!("{}/../../../spec/vectors/keylog/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// Minimal std-only executor: the futures here never wait on I/O.
struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// The relay side: 300 records (entries.json + filler), notes to push, an anchor.
struct FakeLink {
    records: Vec<Vec<u8>>,
    notes: VecDeque<Vec<u8>>,
    anchor: Option<Vec<u8>>,
    fetched: Vec<String>,
}

impl LogLink for FakeLink {
    async fn get_tile(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        self.fetched.push(path.to_owned());
        for n in 0..=(self.records.len() as u64 / TILE_WIDTH) {
            for w in 1..=TILE_WIDTH {
                if tile_path(None, n, w) == path {
                    let mut out = Vec::new();
                    for r in self.records.iter().skip((n * TILE_WIDTH) as usize).take(w as usize) {
                        out.extend_from_slice(&(r.len() as u16).to_be_bytes());
                        out.extend_from_slice(r);
                    }
                    return Ok(out);
                }
            }
        }
        Err(Error::Io(format!("no tile {path}")))
    }
    async fn next_checkpoint(&mut self) -> Option<Vec<u8>> {
        self.notes.pop_front()
    }
    async fn anchor(&mut self) -> Option<Vec<u8>> {
        self.anchor.take()
    }
}

struct Fx {
    link: FakeLink,
    n23: Vec<u8>,
    n300: Vec<u8>,
    fork23: Vec<u8>,
    cosigned300: Vec<u8>,
    origin: String,
    key: NoteKey,
    me: Me,
    witnesses: Vec<CosignerKey>,
}

fn fx() -> Fx {
    let (e, t, c, w) = (load("entries.json"), load("tree.json"), load("checkpoint.json"), load("cosignatures.json"));
    let mut records: Vec<Vec<u8>> = e["entries"].as_array().unwrap().iter().map(|x| unhex(x["record_hex"].as_str().unwrap())).collect();
    records.extend(t["filler_records_hex"].as_array().unwrap().iter().map(|x| unhex(x.as_str().unwrap())));
    let s = |v: &Value| v.as_str().unwrap().as_bytes().to_vec();
    let m = &e["monitor"];
    Fx {
        link: FakeLink { records, notes: VecDeque::new(), anchor: None, fetched: Vec::new() },
        n23: s(&c["valid"][0]["note"]),
        n300: s(&c["valid"][1]["note"]),
        fork23: s(&c["fork"]["note"]),
        cosigned300: s(&w["cases"][0]["note"]),
        origin: c["origin"].as_str().unwrap().to_owned(),
        key: NoteKey::parse(c["vkey"].as_str().unwrap()).unwrap(),
        me: Me {
            pseudonym: m["me"].as_str().unwrap().to_owned(),
            known_keys: m["known_keys"].as_array().unwrap().iter().map(|k| unhex(k.as_str().unwrap()).try_into().unwrap()).collect(),
        },
        witnesses: w["witnesses"].as_array().unwrap().iter().map(|k| CosignerKey::parse(k.as_str().unwrap()).unwrap()).collect(),
    }
}

fn monitor(f: &Fx, dir: Option<&Path>, min_cosignatures: usize) -> Monitor {
    Monitor::open(Config {
        origin: f.origin.clone(),
        key: f.key.clone(),
        dir: dir.map(Path::to_path_buf),
        me: Some(f.me.clone()),
        witnesses: f.witnesses.clone(),
        min_cosignatures,
    })
    .unwrap()
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("moochy-keylog-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn run_sync_alerts_persist_stale_fork() {
    let mut f = fx();
    let dir = tmpdir("run");
    let mut m = monitor(&f, Some(&dir), 0);
    let view = m.view();
    f.link.notes.extend([f.n23.clone(), f.n300.clone(), f.n23.clone()]);
    f.link.anchor = Some(f.n23.clone());
    let mut events = Vec::new();
    block_on(m.run(&mut f.link, |e| events.push(e.clone())));

    let msgs: Vec<String> = events.iter().map(Event::message).collect();
    let all = msgs.join("\n");
    assert!(matches!(events[0], Event::Synced { size: 23 }), "{all}");
    for needle in ["unknown_key", "unsigned DONOR_APPROVED for your repo", "unsigned or invalid MEMBER_ADDED", "public Git anchor at 23 is consistent", "stale checkpoint"] {
        assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
    }
    assert!(events.contains(&Event::Synced { size: 300 }));
    assert!(events.contains(&Event::Stale { served: 23, mirrored: 300 }));
    assert!(events.iter().filter(|e| e.is_security()).count() >= 12);
    // Incremental: 23 → 300 fetched bundle 0 (partial then full) and bundle 1 partial.
    assert_eq!(f.link.fetched, vec!["tile/entries/000.p/23", "tile/entries/000", "tile/entries/001.p/44"]);

    // The view answers from the verified state (same as the vectors' queries).
    let q = &load("entries.json")["queries"];
    for x in q.as_array().unwrap() {
        let (d, r, want) = (x["device"].as_str().unwrap(), x["repo"].as_str().unwrap(), x["code"].as_str().unwrap());
        let got = if x["q"] == "sealable" {
            view.sealable(d, r).err().map_or("", Code::as_str)
        } else {
            view.gateway_allowed(d, r).err().map_or("", Code::as_str)
        };
        assert_eq!(got, want, "{x}");
    }

    // Restart: restored from disk, no network, same answers.
    drop(m);
    let m2 = monitor(&f, Some(&dir), 0);
    assert_eq!(m2.view().size(), 300);
    assert_eq!(m2.view().sealable(q[1]["device"].as_str().unwrap(), q[1]["repo"].as_str().unwrap()).is_ok(), q[1]["code"] == "");

    // A forked checkpoint: fork event, the view fails closed, and it stays so after a restart.
    let mut m3 = m2;
    let ev = block_on(m3.on_checkpoint(&mut f.link, &f.fork23));
    assert!(matches!(&ev[..], [Event::Fork { size: 23, .. }]), "{ev:?}");
    assert!(ev[0].message().contains("fork"));
    assert_eq!(m3.view().sealable("d_x", "r_x"), Err(Code::LogForked));
    drop(m3);
    let m4 = monitor(&f, Some(&dir), 0);
    assert!(m4.view().forked());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fork_vs_anchor_and_rollback() {
    let mut f = fx();
    let mut m = monitor(&f, None, 0);
    block_on(m.on_checkpoint(&mut f.link, &f.n23));
    // The relay serves 23, the public anchor already has 300: rollback / withholding.
    assert_eq!(m.on_anchor(&f.n300), vec![Event::Rollback { anchored: 300, served: 23 }]);
    // An anchor with another root at 23: fork.
    assert!(matches!(&m.on_anchor(&f.fork23)[..], [Event::Fork { .. }]));
    assert!(m.view().forked());
    // Garbage anchors are errors, not forks.
    let mut m = monitor(&f, None, 0);
    assert!(matches!(&m.on_anchor(b"junk")[..], [Event::Error(_)]));
    assert!(!m.view().forked());
}

#[test]
fn witness_threshold() {
    let mut f = fx();
    let mut m = monitor(&f, None, 2);
    let ev = block_on(m.on_checkpoint(&mut f.link, &f.n300));
    assert_eq!(ev, vec![Event::Unwitnessed { size: 300, cosignatures: 0 }]);
    assert_eq!(m.view().size(), 0);
    let ev = block_on(m.on_checkpoint(&mut f.link, &f.cosigned300));
    assert!(ev.contains(&Event::Synced { size: 300 }), "{ev:?}");
    let mut m3 = monitor(&f, None, 3);
    assert_eq!(block_on(m3.on_checkpoint(&mut f.link, &f.cosigned300)), vec![Event::Unwitnessed { size: 300, cosignatures: 2 }]);
}

#[test]
fn hostile_link() {
    struct Evil(u8);
    impl LogLink for Evil {
        async fn get_tile(&mut self, _: &str) -> Result<Vec<u8>, Error> {
            Ok(match self.0 {
                0 => vec![0u8; moochy_keylog::tiles::MAX_BUNDLE_BYTES + 1],
                1 => vec![0, 5, 1],
                _ => vec![0, 1, 7],
            })
        }
        async fn next_checkpoint(&mut self) -> Option<Vec<u8>> {
            None
        }
    }
    let f = fx();
    for mode in 0..3 {
        let mut m = monitor(&f, None, 0);
        let ev = block_on(m.on_checkpoint(&mut Evil(mode), &f.n23));
        assert!(matches!(&ev[..], [Event::Error(_)] | [Event::Fork { .. }]), "{mode}: {ev:?}");
        assert_eq!(m.view().size(), 0);
    }
    // A note signed by another key is refused.
    let mut m = monitor(&f, None, 0);
    let bad = load("checkpoint.json")["invalid"]["other key only"].as_str().unwrap().as_bytes().to_vec();
    assert!(matches!(&block_on(m.on_checkpoint(&mut Evil(2), &bad))[..], [Event::Error(_)]));
}

// The monitor future must be Send (the Node spawns it on a multi-threaded runtime).
#[allow(dead_code)]
fn assert_send<L: LogLink>(m: &mut Monitor, l: &mut L) {
    fn is_send<T: Send>(_: T) {}
    is_send(m.run(l, |_| {}));
}
