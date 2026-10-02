//! Cross-language vectors produced by Go (relay/internal/tlog/vectors_test.go).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::similar_names
)]

use moochy_keylog::{
    Alert, AnchorStatus, Error, Me, Mirror, NoteKey, State,
    entry::{self, parse_record},
    merkle::{Hash, empty_root, leaf_hash, root_of, verify_consistency, verify_inclusion},
    note::open_checkpoint,
    tiles::{parse_bundle, tile_path},
};
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = format!(
        "{}/../../../spec/vectors/keylog/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn h32(v: &Value) -> Hash {
    unhex(v.as_str().unwrap()).try_into().unwrap()
}

fn records() -> Vec<Vec<u8>> {
    load("entries.json")["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| unhex(e["record_hex"].as_str().unwrap()))
        .collect()
}

fn alert_str(a: &Alert) -> String {
    match a {
        Alert::Invalid { idx } => format!("Invalid:{idx}"),
        Alert::Rejected { idx, code, .. } => format!("Rejected:{idx}:{}", code.as_str()),
        Alert::UnknownKey { idx, .. } => format!("UnknownKey:{idx}"),
        Alert::KeyHijack { idx, .. } => format!("KeyHijack:{idx}"),
        Alert::NotSignedByMe { idx, .. } => format!("NotSignedByMe:{idx}"),
        Alert::RepoClaimedByOther { idx, .. } => format!("RepoClaimedByOther:{idx}"),
        Alert::UnknownOwnerKey { idx, .. } => format!("UnknownOwnerKey:{idx}"),
        Alert::OwnerKeyRevoked { idx, .. } => format!("OwnerKeyRevoked:{idx}"),
        Alert::UnknownPasskey {
            idx, email_proof, ..
        } => format!("UnknownPasskey:{idx}:{email_proof}"),
        Alert::PasskeyCounter { idx, .. } => format!("PasskeyCounter:{idx}"),
        Alert::BoxEnrolled { idx, .. } => format!("BoxEnrolled:{idx}"),
        Alert::BoxOutsideRepo { idx, .. } => format!("BoxOutsideRepo:{idx}"),
    }
}

#[test]
fn entries_and_state_machine() {
    let v = load("entries.json");
    let mut st = State::default();
    for (i, e) in v["entries"].as_array().unwrap().iter().enumerate() {
        let rec = unhex(e["record_hex"].as_str().unwrap());
        assert_eq!(
            leaf_hash(&rec).to_vec(),
            unhex(e["leaf_hash_hex"].as_str().unwrap()),
            "leaf {i}"
        );
        let p = parse_record(&rec).unwrap_or_else(|err| panic!("entry {i}: {err}"));
        assert_eq!(p.kind.name(), e["kind"].as_str().unwrap());
        assert_eq!(
            entry::record(p.kind, p.logged_at_ms, p.raw_body, p.sig),
            rec,
            "re-encode {i}"
        );
        if let Some(m) = e["signed_message_hex"].as_str() {
            let msg = match p.body {
                entry::Body::Key {
                    sign_pub,
                    enc_pub,
                    suite,
                    ..
                } => entry::pop_message(sign_pub, enc_pub, suite),
                _ => entry::sig_message(p.kind, p.raw_body),
            };
            assert_eq!(msg, unhex(m), "signed message {i}");
        }
        let got = st.apply(i as u64, &p, true);
        let want = e["code"].as_str().unwrap_or("");
        assert_eq!(
            got.err().map_or("", |c| c.as_str()),
            want,
            "entry {i}: {}",
            e["note"]
        );
        assert_eq!(e["accepted"].as_bool().unwrap(), want.is_empty());
    }
    for q in v["queries"].as_array().unwrap() {
        let (dev, repo, want) = (
            q["device"].as_str().unwrap(),
            q["repo"].as_str().unwrap(),
            q["code"].as_str().unwrap(),
        );
        if q["q"] == "sealable" {
            match st.sealable(dev, repo) {
                Ok(s) => {
                    assert_eq!(want, "", "{q}");
                    assert_eq!(Some(s.approval_idx), q["approval_idx"].as_u64(), "{q}");
                }
                Err(c) => assert_eq!(c.as_str(), want, "{q}"),
            }
        } else {
            assert_eq!(
                st.gateway_allowed(dev, repo)
                    .err()
                    .map_or("", |c| c.as_str()),
                want,
                "{q}"
            );
        }
    }
    for (name, rec) in v["invalid_records"].as_object().unwrap() {
        assert!(
            parse_record(&unhex(rec.as_str().unwrap())).is_err(),
            "invalid record accepted: {name}"
        );
    }
}

#[test]
fn tree_roots_and_proofs() {
    let t = load("tree.json");
    let mut leaves: Vec<Hash> = records().iter().map(|r| leaf_hash(r)).collect();
    leaves.extend(
        t["filler_records_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| leaf_hash(&unhex(r.as_str().unwrap()))),
    );
    assert_eq!(leaves.len(), 300);
    let roots = t["roots"].as_object().unwrap();
    let root = |n: u64| h32(&roots[&n.to_string()]);
    assert_eq!(empty_root(), h32(&t["empty_root"]));
    for n in 1..=300u64 {
        assert_eq!(root_of(&leaves[..n as usize]), root(n), "root {n}");
    }
    for c in t["inclusion"].as_array().unwrap() {
        let (i, n) = (c["index"].as_u64().unwrap(), c["size"].as_u64().unwrap());
        let proof: Vec<Hash> = c["proof"].as_array().unwrap().iter().map(h32).collect();
        assert!(
            verify_inclusion(i, n, &leaves[i as usize], &proof, &root(n)),
            "inclusion {i}/{n}"
        );
        // Any tampering fails.
        assert!(
            !verify_inclusion(i, n, &leaves[(i as usize + 1) % 300], &proof, &root(n))
                || leaves[(i as usize + 1) % 300] == leaves[i as usize]
        );
        if let Some(first) = proof.first() {
            let mut bad = proof.clone();
            bad[0][0] ^= 1;
            assert!(
                !verify_inclusion(i, n, &leaves[i as usize], &bad, &root(n)),
                "tampered inclusion {i}/{n} {first:?}"
            );
            assert!(!verify_inclusion(
                i,
                n,
                &leaves[i as usize],
                &proof[1..],
                &root(n)
            ));
        }
        assert!(!verify_inclusion(
            n,
            n,
            &leaves[i as usize],
            &proof,
            &root(n)
        ));
    }
    for c in t["consistency"].as_array().unwrap() {
        let (m, n) = (c["size1"].as_u64().unwrap(), c["size2"].as_u64().unwrap());
        let proof: Vec<Hash> = c["proof"].as_array().unwrap().iter().map(h32).collect();
        assert!(
            verify_consistency(m, n, &root(m), &root(n), &proof),
            "consistency {m}->{n}"
        );
        if m != n {
            let mut fork = root(m);
            fork[0] ^= 1;
            assert!(
                !verify_consistency(m, n, &fork, &root(n), &proof),
                "forked old root {m}->{n}"
            );
            let mut bad = proof.clone();
            bad.last_mut().unwrap()[31] ^= 1;
            assert!(
                !verify_consistency(m, n, &root(m), &root(n), &bad),
                "tampered {m}->{n}"
            );
        }
    }
}

#[test]
fn checkpoints() {
    let c = load("checkpoint.json");
    let (origin, key) = (
        c["origin"].as_str().unwrap(),
        NoteKey::parse(c["vkey"].as_str().unwrap()).unwrap(),
    );
    for v in c["valid"].as_array().unwrap() {
        let cp = open_checkpoint(v["note"].as_str().unwrap().as_bytes(), origin, &key).unwrap();
        assert_eq!(cp.size, v["size"].as_u64().unwrap());
        assert_eq!(cp.root, h32(&v["root_hex"]));
    }
    for (name, n) in c["invalid"].as_object().unwrap() {
        assert!(
            open_checkpoint(n.as_str().unwrap().as_bytes(), origin, &key).is_err(),
            "accepted invalid checkpoint: {name}"
        );
    }
    assert!(NoteKey::parse(&c["vkey"].as_str().unwrap().replace('+', "x+")).is_err());
}

#[test]
fn mirror_monitor_and_fork() {
    let (c, v) = (load("checkpoint.json"), load("entries.json"));
    let (origin, key) = (
        c["origin"].as_str().unwrap(),
        NoteKey::parse(c["vkey"].as_str().unwrap()).unwrap(),
    );
    let recs = records();
    let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
    let mon = &v["monitor"];
    let me = Me {
        pseudonym: mon["me"].as_str().unwrap().to_owned(),
        known_keys: mon["known_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(h32)
            .collect(),
    };

    let mut m = Mirror::new(origin, key.clone());
    m.set_me(Some(me));
    m.set_owner_keys(
        mon["known_owner_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(h32)
            .collect(),
    );
    let cp = m
        .open_checkpoint(c["valid"][0]["note"].as_str().unwrap().as_bytes())
        .unwrap();
    let fork = m
        .open_checkpoint(c["fork"]["note"].as_str().unwrap().as_bytes())
        .unwrap();

    // A forked checkpoint over the same records is refused and changes nothing.
    assert_eq!(m.update(&fork, &refs), Err(Error::Fork { size: fork.size }));
    assert_eq!(m.size(), 0);

    // Incremental: first 10 records via an intermediate (unsigned, here) tree head.
    let mid = moochy_keylog::Checkpoint {
        size: 10,
        root: root_of(&recs[..10].iter().map(|r| leaf_hash(r)).collect::<Vec<_>>()),
    };
    let mut alerts = m.update(&mid, &refs[..10]).unwrap();
    alerts.extend(m.update(&cp, &refs[10..]).unwrap());
    let got: Vec<String> = alerts.iter().map(alert_str).collect();
    let want: Vec<String> = mon["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(got, want);
    assert_eq!(m.check(&cp), AnchorStatus::Consistent);
    assert_eq!(m.check(&mid), AnchorStatus::Consistent);
    assert_eq!(m.check(&fork), AnchorStatus::Fork);
    let ahead = m
        .open_checkpoint(c["valid"][1]["note"].as_str().unwrap().as_bytes())
        .unwrap();
    assert_eq!(m.check(&ahead), AnchorStatus::Behind);
    // An old checkpoint is fine; a forked old one is a fork.
    assert_eq!(m.update(&mid, &[]), Ok(vec![]));
    let mut bad_mid = mid;
    bad_mid.root[3] ^= 1;
    assert_eq!(m.update(&bad_mid, &[]), Err(Error::Fork { size: 10 }));

    // Same answers as the state-machine vectors.
    assert_eq!(
        m.state()
            .sealable(
                v["queries"][1]["device"].as_str().unwrap(),
                v["queries"][1]["repo"].as_str().unwrap()
            )
            .is_err(),
        v["queries"][1]["code"] != ""
    );

    // Restore from persisted records: same root, no signature checks needed.
    let r = Mirror::restore(origin, key.clone(), refs.iter().copied(), &cp).unwrap();
    assert_eq!(r.check(&cp), AnchorStatus::Consistent);
    assert!(Mirror::restore(origin, key, refs[..22].iter().copied(), &cp).is_err());
}

#[test]
fn tiles() {
    let t = load("tiles.json");
    for p in t["paths"].as_array().unwrap() {
        let level = p["level"].as_u64().map(|l| u8::try_from(l).unwrap());
        assert_eq!(
            tile_path(
                level,
                p["n"].as_u64().unwrap(),
                p["width"].as_u64().unwrap()
            ),
            p["path"].as_str().unwrap()
        );
    }
    let b = unhex(t["bundle_000_p5_hex"].as_str().unwrap());
    let recs = records();
    assert_eq!(
        parse_bundle(&b, 5).unwrap(),
        recs[..5].iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    assert!(parse_bundle(&b, 4).is_err());
    assert!(parse_bundle(&b[..b.len() - 1], 5).is_err());
}

#[test]
fn cosignature_vectors() {
    let c = load("cosignatures.json");
    let ws: Vec<moochy_keylog::cosig::CosignerKey> = c["witnesses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| moochy_keylog::cosig::CosignerKey::parse(k.as_str().unwrap()).unwrap())
        .collect();
    let key = NoteKey::parse(c["log_vkey"].as_str().unwrap()).unwrap();
    for case in c["cases"].as_array().unwrap() {
        let note = case["note"].as_str().unwrap().as_bytes();
        // The log's own signature always verifies; witness lines never break it.
        open_checkpoint(note, c["origin"].as_str().unwrap(), &key).unwrap();
        let want = case["valid"].as_u64().unwrap() as usize;
        match moochy_keylog::cosig::cosignatures(note, &ws) {
            Ok(got) => {
                assert_eq!(got.len(), want, "{}", case["name"]);
                if let Some(ts) = case["timestamps"].as_array() {
                    let ts: Vec<u64> = ts.iter().map(|t| t.as_u64().unwrap()).collect();
                    assert_eq!(got.iter().map(|c| c.timestamp).collect::<Vec<_>>(), ts);
                }
            }
            // A line claiming a pinned witness that does not verify is refused outright.
            Err(e) => assert_eq!((want, e), (0, Error::BadSig), "{}", case["name"]),
        }
    }
    assert!(
        moochy_keylog::cosig::CosignerKey::parse(c["log_vkey"].as_str().unwrap()).is_err(),
        "alg 0x01 key is not a cosigner key"
    );
}

#[test]
fn receipt_log_vectors() {
    let r = load("receipts.json");
    let key = NoteKey::parse(r["vkey"].as_str().unwrap()).unwrap();
    let cp = open_checkpoint(
        r["checkpoint"].as_str().unwrap().as_bytes(),
        r["origin"].as_str().unwrap(),
        &key,
    )
    .unwrap();
    let receipts: Vec<Vec<u8>> = r["receipts_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| unhex(x.as_str().unwrap()))
        .collect();
    for (i, rc) in receipts.iter().enumerate() {
        assert_eq!(
            moochy_keylog::receipts::leaf(rc).to_vec(),
            unhex(r["leaf_hashes"][i].as_str().unwrap())
        );
    }
    for p in r["inclusion"].as_array().unwrap() {
        let i = p["index"].as_u64().unwrap();
        let proof: Vec<Hash> = p["proof"].as_array().unwrap().iter().map(h32).collect();
        assert!(moochy_keylog::receipts::verify(
            &receipts[i as usize],
            i,
            &cp,
            &proof
        ));
        assert!(!moochy_keylog::receipts::verify(
            &receipts[(i as usize + 1) % 5],
            i,
            &cp,
            &proof
        ));
        assert!(!moochy_keylog::receipts::verify(
            b"forged receipt",
            i,
            &cp,
            &proof
        ));
    }
}

#[test]
fn request_vectors() {
    use ed25519_zebra::{Signature, VerificationKey};
    let r = load("requests.json");
    let pubk: [u8; 32] = unhex(r["device_pub_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let vk = VerificationKey::try_from(pubk).unwrap();
    let sig = |k: &str, v: &Value| {
        Signature::from(<[u8; 64]>::try_from(unhex(v[k].as_str().unwrap())).unwrap())
    };
    let lk = &r["lookup"];
    let lm = entry::lookup_request_message(
        lk["handle"].as_str().unwrap(),
        lk["repo_slug"].as_str().unwrap(),
        lk["owner_pseudonym"].as_str().unwrap(),
        lk["issued_at_ms"].as_u64().unwrap(),
    );
    assert_eq!(lm, unhex(lk["message_hex"].as_str().unwrap()));
    let ok_pub: [u8; 32] = unhex(lk["owner_pub_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    assert!(
        VerificationKey::try_from(ok_pub)
            .unwrap()
            .verify(&sig("sig_hex", lk), &lm)
            .is_ok()
    );
    let rv = &r["revoke"];
    let body = unhex(rv["body_hex"].as_str().unwrap());
    let rec = entry::record(moochy_keylog::Kind::KeyRevoked, 0, &body, &[]);
    let p = parse_record(&rec).unwrap();
    let entry::Body::Revoke {
        device_id,
        pseudonym,
        reason,
    } = p.body
    else {
        panic!()
    };
    assert_eq!(entry::revoke_body(device_id, pseudonym, reason), body);
    let msg = entry::revoke_request_message(&body);
    assert_eq!(msg, unhex(rv["message_hex"].as_str().unwrap()));
    vk.verify(&sig("sig_hex", rv), &msg).unwrap();
    // The log-signature label is a different message: refused.
    assert!(vk.verify(&sig("wrong_label_sig_hex", rv), &msg).is_err());
    assert_ne!(
        entry::sig_message(moochy_keylog::Kind::KeyRevoked, &body),
        msg
    );

    let ro = &r["rotate"];
    let kb = unhex(ro["successor_body_hex"].as_str().unwrap());
    let msg = entry::rotate_request_message(&kb);
    assert_eq!(msg, unhex(ro["message_hex"].as_str().unwrap()));
    vk.verify(&sig("sig_hex", ro), &msg).unwrap();
    let entry::Body::Key {
        device_id,
        pseudonym,
        sign_pub,
        enc_pub,
        suite,
        ..
    } = entry::parse_body(moochy_keylog::Kind::KeyAdded, &kb).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        entry::key_body(
            device_id,
            pseudonym,
            sign_pub,
            enc_pub,
            suite,
            "gateway,worker",
            ""
        ),
        kb
    );
    VerificationKey::try_from(*sign_pub)
        .unwrap()
        .verify(
            &sig("pop_sig_hex", ro),
            &entry::pop_message(sign_pub, enc_pub, suite),
        )
        .unwrap();
}
