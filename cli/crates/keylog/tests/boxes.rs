//! boxes.json (produced by Go, relay/internal/tlog/boxes_test.go): box devices (§17.1),
//! KEY_ADDED with a box token id and an expiry; state, queries at a time, monitor alerts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names
)]

use moochy_keylog::{Alert, Me, Mirror, NoteKey, State, entry::parse_record};
use serde_json::Value;

fn load() -> Value {
    let p = format!(
        "{}/../../../spec/vectors/keylog/boxes.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn records(v: &Value) -> Vec<Vec<u8>> {
    v["log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| unhex(s["record_hex"].as_str().unwrap()))
        .collect()
}

#[test]
fn box_state_and_queries() {
    let v = load();
    let mut st = State::default();
    for (i, (s, rec)) in v["log"]
        .as_array()
        .unwrap()
        .iter()
        .zip(records(&v))
        .enumerate()
    {
        let e = parse_record(&rec).unwrap();
        let got = st
            .apply(i as u64, &e, true)
            .err()
            .map_or("", |c| c.as_str());
        assert_eq!(got, s["want"].as_str().unwrap(), "log[{i}] {}", s["note"]);
    }
    for q in v["queries"].as_array().unwrap() {
        let (dev, repo, now) = (
            q["device"].as_str().unwrap(),
            q["repo"].as_str().unwrap(),
            q["now_ms"].as_u64().unwrap(),
        );
        let got = if q["q"] == "sealable" {
            st.sealable_at(dev, repo, now).err()
        } else {
            st.gateway_allowed_at(dev, repo, now).err()
        };
        assert_eq!(
            got.map_or("", |c| c.as_str()),
            q["code"].as_str().unwrap(),
            "{q}"
        );
    }
    // Listed apart: the owner's four accepted boxes, in log order, revoked one included.
    let me = v["me"].as_str().unwrap();
    let boxes: Vec<(u64, bool)> = st
        .boxes(me)
        .iter()
        .map(|(_, d)| (d.idx, d.revoked))
        .collect();
    assert_eq!(boxes, [(8, true), (10, false), (11, false), (14, false)]);
    for (name, h) in v["invalid_records"].as_object().unwrap() {
        assert!(parse_record(&unhex(h.as_str().unwrap())).is_err(), "{name}");
    }
}

#[test]
fn box_monitor_alerts() {
    let v = load();
    let recs = records(&v);
    let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
    let mut m = Mirror::new(
        "keylog.test/v1",
        NoteKey::parse(v["vkey"].as_str().unwrap()).unwrap(),
    );
    m.set_me(Some(Me {
        pseudonym: v["me"].as_str().unwrap().to_owned(),
        known_keys: v["known_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| unhex(h.as_str().unwrap()).try_into().unwrap())
            .collect(),
    }));
    let cp = m
        .open_checkpoint(v["checkpoint"].as_str().unwrap().as_bytes())
        .unwrap();
    let got: Vec<String> = m
        .update(&cp, &refs)
        .unwrap()
        .iter()
        .filter_map(|a| match a {
            Alert::BoxEnrolled { idx, .. } => Some(format!("BoxEnrolled:{idx}")),
            Alert::BoxOutsideRepo { idx, .. } => Some(format!("BoxOutsideRepo:{idx}")),
            Alert::UnknownKey { idx, .. } => Some(format!("UnknownKey:{idx}")),
            _ => None,
        })
        .collect();
    // Boxes never raise UnknownKey; the ones for r2 (someone else's) and r3 (unclaimed)
    // are flagged; the member's box is not the owner's business here.
    assert_eq!(
        got,
        [
            "BoxEnrolled:8",
            "BoxEnrolled:10",
            "BoxOutsideRepo:10",
            "BoxEnrolled:11",
            "BoxOutsideRepo:11",
            "BoxEnrolled:14",
        ]
    );
}
