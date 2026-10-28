//! personal.json (produced by Go, relay/internal/tlog/personal_test.go): the personal target
//! (plan 15, the recipient's own use), DONOR_APPROVED / DONOR_REVOKED on a pseudonym signed by
//! that pseudonym's own owner key; the personal sealing predicate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names
)]

use moochy_keylog::{State, entry::parse_record};
use serde_json::Value;

const NOW: u64 = 1_790_000_000_000;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn code<T>(r: Result<T, moochy_keylog::Code>) -> &'static str {
    r.err().map_or("", moochy_keylog::Code::as_str)
}

#[test]
fn personal_state_and_sealable() {
    let p = format!(
        "{}/../../../spec/vectors/keylog/personal.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let mut st = State::default();
    for (i, s) in v["log"].as_array().unwrap().iter().enumerate() {
        let rec = unhex(s["record_hex"].as_str().unwrap());
        let e = parse_record(&rec).unwrap();
        assert_eq!(
            code(st.apply(i as u64, &e, true)),
            s["want"].as_str().unwrap(),
            "log[{i}] {}",
            s["note"]
        );
    }
    let qs = v["personal_sealable"].as_array().unwrap();
    assert_eq!(qs.len(), 11);
    for q in qs {
        let got = st.personal_sealable_at(
            q["worker"].as_str().unwrap(),
            q["gateway"].as_str().unwrap(),
            NOW,
        );
        assert_eq!(code(got), q["code"].as_str().unwrap(), "{q}");
        if let Ok(s) = got {
            assert_eq!(s.approval_idx, q["approval_idx"].as_u64().unwrap(), "{q}");
        }
        // A personal approval never satisfies the repo/org/person rules.
        let g = q["gateway"].as_str().unwrap();
        if let Some(ps) = st.device(g).map(|d| d.pseudonym.clone()) {
            assert!(
                st.sealable_at(q["worker"].as_str().unwrap(), &ps, NOW)
                    .is_err(),
                "{q}"
            );
            assert!(
                st.person_sealable_at(q["worker"].as_str().unwrap(), &ps, g, NOW)
                    .is_err(),
                "{q}"
            );
            assert!(st.gateway_allowed_at(g, &ps, NOW).is_err(), "{q}");
        }
    }
    for q in v["personal_gateway_allowed"].as_array().unwrap() {
        let got = st.personal_gateway_allowed_at(
            q["gateway"].as_str().unwrap(),
            q["target"].as_str().unwrap(),
            NOW,
        );
        assert_eq!(code(got), q["code"].as_str().unwrap(), "{q}");
    }
    for q in v["donor_approved"].as_array().unwrap() {
        assert_eq!(
            st.donor_approved(
                q["target"].as_str().unwrap(),
                q["pseudonym"].as_str().unwrap()
            ),
            q["want"].as_bool().unwrap(),
            "{q}"
        );
    }
    for (name, h) in v["invalid_records"].as_object().unwrap() {
        assert!(
            parse_record(&unhex(h.as_str().unwrap())).is_err(),
            "invalid_records {name} accepted"
        );
    }
}

/// With P's owner key unknown to P's monitor, every approval on P's personal target alerts
/// (`NotSignedByMe`), the first one included (no claim precedes it); E's own target never does.
#[test]
fn personal_monitor_alerts() {
    use moochy_keylog::{Alert, Me, Mirror, NoteKey};
    let p = format!(
        "{}/../../../spec/vectors/keylog/personal.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let recs: Vec<Vec<u8>> = v["log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| unhex(s["record_hex"].as_str().unwrap()))
        .collect();
    let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
    let mut st = State::default();
    for (i, r) in recs.iter().enumerate() {
        let _ = st.apply(i as u64, &parse_record(r).unwrap(), true);
    }
    let me = st
        .device(v["personal_sealable"][0]["gateway"].as_str().unwrap())
        .unwrap()
        .pseudonym
        .clone();
    let mut m = Mirror::new(
        "keylog.test/v1",
        NoteKey::parse(v["vkey"].as_str().unwrap()).unwrap(),
    );
    m.set_me(Some(Me {
        pseudonym: me,
        known_keys: Vec::new(),
    }));
    m.set_owner_keys(Vec::new());
    let cp = m
        .open_checkpoint(v["checkpoint"].as_str().unwrap().as_bytes())
        .unwrap();
    let got: Vec<u64> = m
        .update(&cp, &refs)
        .unwrap()
        .iter()
        .filter_map(|a| match a {
            Alert::NotSignedByMe { idx, kind, .. } if kind.name().starts_with("DONOR_") => {
                Some(*idx)
            }
            _ => None,
        })
        .collect();
    assert_eq!(got, [9, 15, 16]);
}
