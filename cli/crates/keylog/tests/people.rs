//! people.json (produced by Go, relay/internal/tlog/people_test.go): people (CONTRACT §24),
//! PERSON_CLAIMED / PERSON_REPO_ADDED / PERSON_REPO_REMOVED and DONOR_APPROVED on an `m_` id;
//! state, the person sealing predicate, monitor alerts.
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
    entry::{Kind, parse_body, parse_record, person_claim_body, person_repo_body},
};
use serde_json::Value;

fn load() -> Value {
    let p = format!(
        "{}/../../../spec/vectors/keylog/people.json",
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

fn keys(v: &Value, field: &str) -> Vec<[u8; 32]> {
    v[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| unhex(h.as_str().unwrap()).try_into().unwrap())
        .collect()
}

fn code<T>(r: Result<T, moochy_keylog::Code>) -> &'static str {
    r.err().map_or("", moochy_keylog::Code::as_str)
}

#[test]
fn people_state_and_sealable() {
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
        assert_eq!(
            code(st.apply(i as u64, &e, true)),
            s["want"].as_str().unwrap(),
            "log[{i}] {}",
            s["note"]
        );
    }
    let qs = v["person_sealable"].as_array().unwrap();
    assert_eq!(qs.len(), 18);
    for q in qs {
        let (w, r, g) = (
            q["worker"].as_str().unwrap(),
            q["repo"].as_str().unwrap(),
            q["gateway"].as_str().unwrap(),
        );
        for (got, c, i) in [
            (
                st.person_sealable_at(w, r, g, 1_790_000_000_000),
                "code",
                "approval_idx",
            ),
            (
                st.sealable_for_at(w, r, g, 1_790_000_000_000),
                "for_code",
                "for_approval_idx",
            ),
        ] {
            assert_eq!(code(got), q[c].as_str().unwrap(), "{c} {q}");
            if let Ok(s) = got {
                assert_eq!(s.approval_idx, q[i].as_u64().unwrap(), "{i} {q}");
            }
        }
    }
    // A person approval never satisfies the repo/org rule (r2 is claimed by E, D is approved
    // only on the person).
    assert_eq!(
        code(st.sealable_at(
            qs[7]["worker"].as_str().unwrap(),
            qs[7]["repo"].as_str().unwrap(),
            1_790_000_000_000
        )),
        "not_approved"
    );
    for (who, want) in v["owned_people"].as_object().unwrap() {
        let mut got = serde_json::Map::new();
        for (m, repos) in st.owned_people(who) {
            got.insert(m.to_owned(), repos.into());
        }
        assert_eq!(Value::Object(got), *want, "owned_people({who})");
    }
    assert_eq!(
        v["owned_people"][v["me"].as_str().unwrap()]["m_01HZH000000000000000000001"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for q in v["donor_approved"].as_array().unwrap() {
        assert_eq!(
            st.donor_approved(
                q["target"].as_str().unwrap(),
                q["pseudonym"].as_str().unwrap()
            ),
            q["want"].as_bool().unwrap(),
            "donor_approved {q}"
        );
    }
    assert_eq!(
        st.owner("m_01HZH000000000000000000001"),
        Some(v["me"].as_str().unwrap())
    );
    for (name, h) in v["invalid_records"].as_object().unwrap() {
        assert!(parse_record(&unhex(h.as_str().unwrap())).is_err(), "{name}");
    }
}

#[test]
fn people_builders_round_trip() {
    let ok = "ok_00112233445566778899aabbccddeeff";
    let m = "m_01HZH000000000000000000001";
    let b = person_claim_body(m, "gitlab", "77", "ps_0wner00000000000", ok, 5);
    assert!(parse_body(Kind::PersonClaimed, &b).is_ok());
    assert!(
        parse_body(Kind::OrgClaimed, &b).is_err(),
        "an m_ id is never an org"
    );
    assert!(parse_body(Kind::RepoClaimed, &b).is_err());
    let b = person_repo_body(m, "r_01HZY000000000000000000001", ok, 5);
    assert!(parse_body(Kind::PersonRepoAdded, &b).is_ok());
    assert!(parse_body(Kind::OrgRepoAdded, &b).is_err());
    assert!(
        parse_body(Kind::DonorApproved, &b).is_err(),
        "subject is not a pseudonym"
    );
    for k in [
        Kind::PersonClaimed,
        Kind::PersonRepoAdded,
        Kind::PersonRepoRemoved,
    ] {
        assert!(k.owner_signed());
        assert_eq!(Kind::from_name(k.name()), Some(k));
        assert_eq!(Kind::from_u32(k as u32), Some(k));
    }
    assert_eq!(Kind::from_u32(19), None);
}

fn alerts(v: &Value, owner_keys: Vec<[u8; 32]>) -> Vec<String> {
    let recs = records(v);
    let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
    let mut m = Mirror::new(
        "keylog.test/v1",
        NoteKey::parse(v["vkey"].as_str().unwrap()).unwrap(),
    );
    m.set_me(Some(Me {
        pseudonym: v["me"].as_str().unwrap().to_owned(),
        known_keys: keys(v, "known_keys"),
    }));
    m.set_owner_keys(owner_keys);
    let cp = m
        .open_checkpoint(v["checkpoint"].as_str().unwrap().as_bytes())
        .unwrap();
    m.update(&cp, &refs)
        .unwrap()
        .iter()
        .filter_map(|a| match a {
            Alert::NotSignedByMe {
                idx, kind, repo_id, ..
            } => Some(format!(
                "NotSignedByMe:{idx}:{}:{}",
                kind.name(),
                &repo_id[..2]
            )),
            Alert::Rejected { .. } | Alert::UnprovenOwnerKey { .. } => None,
            other => Some(format!("{other:?}")),
        })
        .collect()
}

#[test]
fn people_monitor_alerts() {
    let v = load();
    // My owner key known: nothing (a takeover is refused, never logged as accepted).
    assert_eq!(
        alerts(&v, keys(&v, "known_owner_keys")),
        Vec::<String>::new()
    );
    // My owner key unknown (a rogue owner key on my account): every person entry it signed
    // for me alerts; E's own profile (m3) never does.
    let got = alerts(&v, Vec::new());
    for want in [
        "NotSignedByMe:12:PERSON_CLAIMED:m_",
        "NotSignedByMe:18:PERSON_REPO_ADDED:m_",
        "NotSignedByMe:24:DONOR_APPROVED:m_",
        "NotSignedByMe:26:PERSON_REPO_REMOVED:m_",
        "NotSignedByMe:37:PERSON_CLAIMED:m_",
    ] {
        assert!(got.iter().any(|g| g == want), "{want} missing from {got:?}");
    }
    assert!(
        !got.iter()
            .any(|g| g.starts_with("NotSignedByMe:29") || g.starts_with("NotSignedByMe:30")),
        "E's own profile is not my business: {got:?}"
    );
}
