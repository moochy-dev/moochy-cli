//! orgs.json (produced by Go, relay/internal/tlog/orgs_test.go): organisations (CONTRACT
//! §19), ORG_CLAIMED / ORG_REPO_ADDED / ORG_REPO_REMOVED and DONOR_APPROVED on an `o_` id;
//! state, the org-aware sealing predicate, monitor alerts.
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
        "{}/../../../spec/vectors/keylog/orgs.json",
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

#[test]
fn org_state_and_sealable() {
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
    for q in v["sealable"].as_array().unwrap() {
        let got = st.sealable_at(
            q["device"].as_str().unwrap(),
            q["repo"].as_str().unwrap(),
            1_790_000_000_000,
        );
        match got {
            Ok(s) => {
                assert_eq!(q["code"], "", "{q}");
                assert_eq!(s.approval_idx, q["approval_idx"].as_u64().unwrap(), "{q}");
            }
            Err(c) => assert_eq!(c.as_str(), q["code"].as_str().unwrap(), "{q}"),
        }
    }
    assert_eq!(
        st.owner("o_01HZG000000000000000000001"),
        Some(v["me"].as_str().unwrap())
    );
    // owned_orgs (the `moochy owner status` accessor): an org taken over leaves the old
    // owner's list and starts the new owner's with only the repos they re-added.
    for (who, want) in v["owned_orgs"].as_object().unwrap() {
        let mut got = serde_json::Map::new();
        for (org, repos) in st.owned_orgs(who) {
            got.insert(org.to_owned(), repos.into());
        }
        assert_eq!(Value::Object(got), *want, "owned_orgs({who})");
    }
    assert_eq!(v["owned_orgs"].as_object().unwrap().len(), 3);
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
    assert_eq!(v["donor_approved"].as_array().unwrap().len(), 10);
    for (name, h) in v["invalid_records"].as_object().unwrap() {
        assert!(parse_record(&unhex(h.as_str().unwrap())).is_err(), "{name}");
    }
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
            Alert::NotSignedByMe { idx, kind, .. } => {
                Some(format!("NotSignedByMe:{idx}:{}", kind.name()))
            }
            Alert::RepoClaimedByOther { idx, repo_id, .. } => {
                Some(format!("ClaimedByOther:{idx}:{}", &repo_id[..2]))
            }
            Alert::Rejected { .. } | Alert::UnprovenOwnerKey { .. } => None,
            other => Some(format!("{other:?}")),
        })
        .collect()
}

#[test]
fn org_monitor_alerts() {
    let v = load();
    // My owner key known: the takeovers of my repos r5, r7, r6, r8 and my orgs o4, o6, o7 by another account.
    assert_eq!(
        alerts(&v, keys(&v, "known_owner_keys")),
        [
            "ClaimedByOther:26:r_",
            "ClaimedByOther:39:o_",
            "ClaimedByOther:49:r_",
            "ClaimedByOther:50:o_",
            "ClaimedByOther:51:r_",
            "ClaimedByOther:63:r_",
            "ClaimedByOther:64:o_"
        ]
    );
    // My owner key unknown (a rogue owner key on my account): every claim, org entry and
    // approval it signed for my repos and orgs alerts, org ones included.
    let got = alerts(&v, Vec::new());
    for want in [
        "NotSignedByMe:11:ORG_CLAIMED",
        "NotSignedByMe:12:ORG_REPO_ADDED",
        "NotSignedByMe:20:DONOR_APPROVED",
        "NotSignedByMe:24:ORG_REPO_REMOVED",
        "NotSignedByMe:36:ORG_CLAIMED",
        "ClaimedByOther:39:o_",
    ] {
        assert!(got.iter().any(|g| g == want), "{want} missing from {got:?}");
    }
    assert!(
        !got.iter()
            .any(|g| g.starts_with("NotSignedByMe:27") || g.starts_with("NotSignedByMe:29")),
        "E's own org is not my business: {got:?}"
    );
}
