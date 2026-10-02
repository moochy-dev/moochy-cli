//! owner-proof.json (produced by Go, relay/internal/tlog/ownerproof_test.go): an account's
//! first CLI owner key needs the confirmed-email proof or an authorizer (spec/KEYLOG.md §4c,
//! A224); proofless first keys before the cutover stay valid; monitors flag them.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names
)]

use moochy_keylog::{
    Alert, Me, Mirror, NoteKey, State,
    entry::parse_record,
    state::{OWNER_KEY_PROOF_FROM_MS, OwnerKeyProof},
};
use serde_json::Value;

fn load() -> Value {
    let p = format!(
        "{}/../../../spec/vectors/keylog/owner-proof.json",
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
fn proof_rule_state_machine() {
    let v = load();
    assert_eq!(v["cutover_ms"].as_u64().unwrap(), OWNER_KEY_PROOF_FROM_MS);
    let mut st = State::default();
    for (i, (s, rec)) in v["log"]
        .as_array()
        .unwrap()
        .iter()
        .zip(records(&v))
        .enumerate()
    {
        let e = parse_record(&rec).unwrap_or_else(|e| panic!("{}: {e}", s["note"]));
        let got = st
            .apply(i as u64, &e, true)
            .err()
            .map_or("", |c| c.as_str());
        assert_eq!(got, s["want"].as_str().unwrap(), "log[{i}] {}", s["note"]);
    }
    for (id, want) in v["proof"].as_object().unwrap() {
        let got = match st.owner_key(id).unwrap().proof {
            OwnerKeyProof::None => "none",
            OwnerKeyProof::Email => "email",
            OwnerKeyProof::Authorizer => "authorizer",
            OwnerKeyProof::Rotation => "rotation",
        };
        assert_eq!(got, want.as_str().unwrap(), "{id}");
    }
    for (name, h) in v["invalid_records"].as_object().unwrap() {
        assert!(parse_record(&unhex(h.as_str().unwrap())).is_err(), "{name}");
    }
    // With the cutover at 0 (a dev log that always requires the proof), the legacy key
    // at #0 is refused too, and the email-proved one is still accepted.
    let mut strict = State::with_owner_key_proof_from(0);
    let recs = records(&v);
    let e0 = parse_record(&recs[0]).unwrap();
    assert_eq!(
        strict
            .apply(0, &e0, true)
            .map_err(moochy_keylog::Code::as_str),
        Err("owner_key_proof")
    );
    assert!(
        strict
            .apply(3, &parse_record(&recs[3]).unwrap(), true)
            .is_ok()
    );
}

#[test]
fn proof_monitor_alerts() {
    let v = load();
    let recs = records(&v);
    let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
    let run = |me: &str, owner_keys: Vec<[u8; 32]>| -> Vec<String> {
        let mut m = Mirror::new(
            "keylog.test/v1",
            NoteKey::parse(v["vkey"].as_str().unwrap()).unwrap(),
        );
        m.set_me(Some(Me {
            pseudonym: me.to_owned(),
            known_keys: Vec::new(),
        }));
        m.set_owner_keys(owner_keys);
        let cp = m
            .open_checkpoint(v["checkpoint"].as_str().unwrap().as_bytes())
            .unwrap();
        m.update(&cp, &refs)
            .unwrap()
            .iter()
            .filter_map(|a| match a {
                Alert::UnprovenOwnerKey { idx, known, .. } => {
                    Some(format!("UnprovenOwnerKey:{idx}:{known}"))
                }
                Alert::UnknownOwnerKey { idx, .. } => Some(format!("UnknownOwnerKey:{idx}")),
                _ => None,
            })
            .collect()
    };
    let me = v["me"].as_str().unwrap();
    let known: Vec<[u8; 32]> = v["known_owner_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| unhex(h.as_str().unwrap()).try_into().unwrap())
        .collect();
    // My legacy key: flagged even when known (a reminder); unknown, it is an intrusion.
    assert_eq!(
        run(me, known),
        ["UnprovenOwnerKey:0:true", "UnknownOwnerKey:7"]
    );
    assert_eq!(
        run(me, Vec::new()),
        [
            "UnprovenOwnerKey:0:false",
            "UnknownOwnerKey:0",
            "UnknownOwnerKey:7"
        ]
    );
}
