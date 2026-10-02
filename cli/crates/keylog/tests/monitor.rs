//! Monitor loop against a fake relay link serving the Go-generated vectors.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::unused_async_trait_impl,
    clippy::many_single_char_names,
    clippy::unnested_or_patterns
)]

use moochy_keylog::{
    Error, Event, LogLink, Me, Monitor, NoteKey,
    cosig::CosignerKey,
    monitor::Config,
    state::Code,
    tiles::{TILE_WIDTH, tile_path},
};
use serde_json::Value;
use sha2::Digest;
use std::{
    collections::VecDeque,
    future::Future,
    path::Path,
    pin::pin,
    task::{Context, Poll, Waker},
};

fn load(name: &str) -> Value {
    let p = format!(
        "{}/../../../spec/vectors/keylog/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
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
                    for r in self
                        .records
                        .iter()
                        .skip((n * TILE_WIDTH) as usize)
                        .take(w as usize)
                    {
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
    fn anchor_configured(&self) -> bool {
        self.anchor.is_some()
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
    owner_keys: Vec<[u8; 32]>,
    witnesses: Vec<CosignerKey>,
}

fn fx() -> Fx {
    let (e, t, c, w) = (
        load("entries.json"),
        load("tree.json"),
        load("checkpoint.json"),
        load("cosignatures.json"),
    );
    let mut records: Vec<Vec<u8>> = e["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| unhex(x["record_hex"].as_str().unwrap()))
        .collect();
    records.extend(
        t["filler_records_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| unhex(x.as_str().unwrap())),
    );
    let s = |v: &Value| v.as_str().unwrap().as_bytes().to_vec();
    let m = &e["monitor"];
    Fx {
        link: FakeLink {
            records,
            notes: VecDeque::new(),
            anchor: None,
            fetched: Vec::new(),
        },
        n23: s(&c["valid"][0]["note"]),
        n300: s(&c["valid"][1]["note"]),
        fork23: s(&c["fork"]["note"]),
        cosigned300: s(&w["cases"][0]["note"]),
        origin: c["origin"].as_str().unwrap().to_owned(),
        key: NoteKey::parse(c["vkey"].as_str().unwrap()).unwrap(),
        me: Me {
            pseudonym: m["me"].as_str().unwrap().to_owned(),
            known_keys: m["known_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| unhex(k.as_str().unwrap()).try_into().unwrap())
                .collect(),
        },
        owner_keys: m["known_owner_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| unhex(k.as_str().unwrap()).try_into().unwrap())
            .collect(),
        witnesses: w["witnesses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| CosignerKey::parse(k.as_str().unwrap()).unwrap())
            .collect(),
    }
}

fn monitor(f: &Fx, dir: Option<&Path>, min_cosignatures: usize) -> Monitor {
    Monitor::open(Config {
        origin: f.origin.clone(),
        key: f.key.clone(),
        dir: dir.map(Path::to_path_buf),
        me: Some(f.me.clone()),
        known_owner_keys: f.owner_keys.clone(),
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
    f.link
        .notes
        .extend([f.n23.clone(), f.n300.clone(), f.n23.clone()]);
    f.link.anchor = Some(f.n23.clone());
    let mut events = Vec::new();
    block_on(m.run(&mut f.link, |e| events.push(e.clone())));

    let msgs: Vec<String> = events.iter().map(Event::message).collect();
    let all = msgs.join("\n");
    assert!(matches!(events[0], Event::Synced { size: 27 }), "{all}");
    for needle in [
        "unknown_key",
        "unsigned DONOR_APPROVED for your repo",
        "unsigned or invalid MEMBER_ADDED",
        "public Git anchor at 27 is consistent",
        "stale checkpoint",
        "unknown_owner_key",
        "your owner key ok_",
    ] {
        assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
    }
    assert!(events.contains(&Event::Synced { size: 300 }));
    assert!(events.contains(&Event::Stale {
        served: 27,
        mirrored: 300
    }));
    assert!(events.iter().filter(|e| e.is_security()).count() >= 12);
    // Incremental: 27 → 300 fetched bundle 0 (partial then full) and bundle 1 partial.
    assert_eq!(
        f.link.fetched,
        vec![
            "tile/entries/000.p/27",
            "tile/entries/000",
            "tile/entries/001.p/44"
        ]
    );

    // The view answers from the verified state (same as the vectors' queries).
    let q = &load("entries.json")["queries"];
    for x in q.as_array().unwrap() {
        let (d, r, want) = (
            x["device"].as_str().unwrap(),
            x["repo"].as_str().unwrap(),
            x["code"].as_str().unwrap(),
        );
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
    assert_eq!(
        m2.view()
            .sealable(
                q[1]["device"].as_str().unwrap(),
                q[1]["repo"].as_str().unwrap()
            )
            .is_ok(),
        q[1]["code"] == ""
    );

    // A forked checkpoint: fork event, the view fails closed, and it stays so after a restart.
    let mut m3 = m2;
    let ev = block_on(m3.on_checkpoint(&mut f.link, &f.fork23));
    assert!(matches!(&ev[..], [Event::Fork { size: 27, .. }]), "{ev:?}");
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
    assert_eq!(
        m.on_anchor(&f.n300),
        vec![Event::Rollback {
            anchored: 300,
            served: 27
        }]
    );
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
    assert_eq!(
        ev,
        vec![Event::Unwitnessed {
            size: 300,
            cosignatures: 0
        }]
    );
    assert_eq!(m.view().size(), 0);
    let ev = block_on(m.on_checkpoint(&mut f.link, &f.cosigned300));
    assert!(ev.contains(&Event::Synced { size: 300 }), "{ev:?}");
    let mut m3 = monitor(&f, None, 3);
    assert_eq!(
        block_on(m3.on_checkpoint(&mut f.link, &f.cosigned300)),
        vec![Event::Unwitnessed {
            size: 300,
            cosignatures: 2
        }]
    );
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
        assert!(
            matches!(&ev[..], [Event::Error(_)] | [Event::Fork { .. }]),
            "{mode}: {ev:?}"
        );
        assert_eq!(m.view().size(), 0);
    }
    // A note signed by another key is refused.
    let mut m = monitor(&f, None, 0);
    let bad = load("checkpoint.json")["invalid"]["other key only"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(matches!(
        &block_on(m.on_checkpoint(&mut Evil(2), &bad))[..],
        [Event::Error(_)]
    ));
}

// The monitor future must be Send (the Node spawns it on a multi-threaded runtime).
#[allow(dead_code)]
fn assert_send<L: LogLink>(m: &mut Monitor, l: &mut L) {
    fn is_send<T: Send>(_: T) {}
    is_send(m.run(l, |_| {}));
}

#[test]
fn sealing_gate() {
    use moochy_keylog::monitor::{Gate, MAX_LOG_AGE};
    use std::time::{Duration, Instant};
    let mut f = fx();
    let mut m = monitor(&f, None, 0);
    let v = m.view();
    let q = &load("entries.json")["queries"];
    // The donor that the vectors' state can seal to (approval by the rogue owner key).
    let ok = q
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["q"] == "sealable" && x["code"] == "")
        .unwrap();
    let (w, r) = (ok["device"].as_str().unwrap(), ok["repo"].as_str().unwrap());
    let ai = ok["approval_idx"].as_u64().unwrap();
    assert_eq!(v.gate(), Gate::NoCheckpoint);
    assert_eq!(v.seal_check(w, r, 17, ai), Err(Code::NoCheckpoint));
    block_on(m.on_checkpoint(&mut f.link, &f.n23));
    assert_eq!(v.gate(), Gate::Verified { size: 27 });
    let s = v.state(|st| st.sealable(w, r)).unwrap().unwrap();
    assert_eq!(v.seal_check(w, r, s.key_idx, ai), Ok(s));
    assert_eq!(
        v.seal_check(w, r, s.key_idx, ai - 1),
        Err(Code::IndexMismatch)
    );
    assert_eq!(
        v.seal_check(w, r, s.key_idx + 1, ai),
        Err(Code::IndexMismatch)
    );
    // Old confirmation: stale; a fresh one reopens the gate.
    let later = Instant::now() + MAX_LOG_AGE + Duration::from_secs(1);
    assert_eq!(v.gate_at(later), Gate::Stale { size: 27 });
    assert_eq!(
        v.seal_check_at(later, w, r, s.key_idx, ai),
        Err(Code::StaleLog)
    );
    block_on(m.on_checkpoint(&mut f.link, &f.n300));
    assert_eq!(v.gate(), Gate::Verified { size: 300 });
    // An older checkpoint closes the gate until a newer consistent one.
    block_on(m.on_checkpoint(&mut f.link, &f.n23));
    assert_eq!(v.seal_check(w, r, s.key_idx, ai), Err(Code::StaleLog));
    block_on(m.on_checkpoint(&mut f.link, &f.n300));
    assert_eq!(v.seal_check(w, r, s.key_idx, ai), Ok(s));

    // Cost on the submit path.
    let t = Instant::now();
    let n = 200_000u32;
    for _ in 0..n {
        assert!(v.seal_check(w, r, s.key_idx, ai).is_ok());
    }
    let per = t.elapsed() / n;
    eprintln!("seal_check: {per:?} per call");
    assert!(
        per < Duration::from_micros(20),
        "seal_check too slow: {per:?}"
    );

    // Fork: closed for good.
    block_on(m.on_checkpoint(&mut f.link, &f.fork23));
    assert_eq!(v.gate(), Gate::Forked);
    assert_eq!(v.seal_check(w, r, s.key_idx, ai), Err(Code::LogForked));
}

// A204: with no witnesses required and no anchor, the monitor says loudly that it
// fails open; with either protection it stays quiet.
#[test]
fn fail_open_is_loud() {
    let mut f = fx();
    let mut m = monitor(&f, None, 0);
    f.link.notes.extend([f.n23.clone()]);
    let mut events = Vec::new();
    block_on(m.run(&mut f.link, |e| events.push(e.clone())));
    assert_eq!(events[0], Event::FailOpen);
    assert!(events[0].is_security() && events[0].message().contains("fail-open"));
    assert_eq!(events.iter().filter(|e| **e == Event::FailOpen).count(), 1);
    // An anchor wired: no warning.
    let mut f = fx();
    let m = monitor(&f, None, 0);
    f.link.anchor = Some(f.n23.clone());
    assert!(!m.fail_open(&f.link));
    // Witnesses required: no warning either.
    let m = monitor(&f, None, 1);
    f.link.anchor = None;
    assert!(!m.fail_open(&f.link));
}

// mo-node: a key the user just created stops being "unknown" without reopening.
#[test]
fn acknowledge_keys_at_runtime() {
    let mut f = fx();
    let mut m = monitor(&f, None, 0);
    m.view().acknowledge_owner_key([7; 32]);
    // The vectors' rogue owner key (UnknownOwnerKey:21) is unknown until acknowledged.
    let entries = load("entries.json");
    let rogue_ok = entries["entries"][21]["record_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let rec = unhex(&rogue_ok);
    let e = moochy_keylog::entry::parse_record(&rec).unwrap();
    let moochy_keylog::entry::Body::OwnerKey { owner_pub, .. } = e.body else {
        panic!()
    };
    m.view().acknowledge_owner_key(*owner_pub);
    let ev = block_on(m.on_checkpoint(&mut f.link, &f.n23));
    let msgs: Vec<String> = ev.iter().map(Event::message).collect();
    assert!(
        !msgs.iter().any(|x| x.contains("unknown_owner_key: an owner key")),
        "{msgs:?}"
    );
    // The device-key alert still fires for the rogue device until acknowledged.
    assert!(msgs.iter().any(|x| x.contains("unknown_key: a new device")), "{msgs:?}");
}

#[test]
fn projection_verify() {
    use moochy_keylog::projection::{valid_ref, verify};
    let mut f = fx();
    let mut m = monitor(&f, None, 0);
    block_on(m.on_checkpoint(&mut f.link, &f.n23));
    // A device logged in the vectors with a known seed: newDev(1) = sha256("dev-1").
    let seed: [u8; 32] = sha2::Sha256::digest(b"dev-1").into();
    let sk = ed25519_zebra::SigningKey::from(seed);
    let pj = br#"{"v":1,"receipt_ref":"abc"}"#;
    let sig: [u8; 64] = sk
        .sign(&moochy_keylog::entry::lp(&[b"moochy/v1/projection", pj]))
        .into();
    let dev = "d_01HZX000000000000000000001";
    let idx = m.view().state(|s| s.device(dev).unwrap().idx).unwrap();
    let ok = m.view().verify_projection(pj, &sig, dev, idx).unwrap();
    assert!(ok.donor_pseudonym.starts_with("ps_"));
    assert_eq!(
        m.view().verify_projection(br#"{"v":1}"#, &sig, dev, idx),
        Err(Code::BadSig)
    );
    assert_eq!(
        m.view().verify_projection(pj, &sig, dev, idx + 1),
        Err(Code::IndexMismatch)
    );
    assert_eq!(
        m.view()
            .verify_projection(pj, &sig, "d_01HZX000000000000000000099", idx),
        Err(Code::UnknownDevice)
    );
    assert!(
        m.view()
            .state(|s| verify(s, pj, &sig[..63], dev, idx))
            .unwrap()
            .is_err()
    );
    for r in ["", "a/b", "..", &"A".repeat(65)] {
        assert!(!valid_ref(r), "{r}");
    }
    assert!(valid_ref("4k5BnpfZq4wPOCCDMZvRGA"));
    // fetch_projection refuses a bad ref before any I/O and caps the reply.
    assert!(
        block_on(moochy_keylog::monitor::fetch_projection(
            &mut f.link,
            "../x"
        ))
        .is_err()
    );
}
