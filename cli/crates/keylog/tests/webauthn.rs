//! webauthn.json (produced by Go, relay/internal/tlog/webauthn_test.go): passkey
//! assertion checks, invalid COSE keys and records, the passkey log through the state
//! machine, and the monitor alerts it raises.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::similar_names
)]

use moochy_keylog::{
    Alert, Error, Me, Mirror, NoteKey, State,
    entry::{Body, parse_record},
    state::passkey_digest,
    webauthn::{Assertion, Passkey, parse_cose, verify_assertion},
};
use serde_json::Value;

fn load() -> Value {
    let p = format!(
        "{}/../../../spec/vectors/keylog/webauthn.json",
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

fn code_of(e: &Error) -> &'static str {
    match e {
        Error::Format(_) | Error::TooLarge => "format",
        _ => "other",
    }
}

#[test]
fn assertions() {
    let v = load();
    let point = parse_cose(&unhex(v["cose_hex"].as_str().unwrap())).unwrap();
    let k = Passkey {
        point: &point,
        rp_id: v["rp_id"].as_str().unwrap(),
        origins: v["origins"].as_str().unwrap(),
    };
    let cases = v["assertions"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let raw = unhex(c["assertion_hex"].as_str().unwrap());
        let msg = unhex(c["message_hex"].as_str().unwrap());
        let prev = u32::try_from(c["prev_counter"].as_u64().unwrap()).unwrap();
        let got = match Assertion::parse(&raw) {
            Err(e) => Err(code_of(&e)),
            Ok(a) => verify_assertion(&k, &msg, &a, prev).map_err(moochy_keylog::Code::as_str),
        };
        let want = c["want"].as_str().unwrap();
        let counter = c["counter"].as_u64().unwrap_or(0);
        match got {
            Ok(ctr) => assert!(
                want.is_empty() && u64::from(ctr) == counter,
                "{name}: valid with {ctr}, want {want:?}"
            ),
            Err(code) => assert_eq!(code, want, "{name}"),
        }
    }
}

#[test]
fn invalid_cose_and_records() {
    let v = load();
    for (name, h) in v["invalid_cose"].as_object().unwrap() {
        assert!(parse_cose(&unhex(h.as_str().unwrap())).is_err(), "{name}");
    }
    for (name, h) in v["invalid_records"].as_object().unwrap() {
        assert!(parse_record(&unhex(h.as_str().unwrap())).is_err(), "{name}");
    }
}

fn log(v: &Value) -> Vec<(String, Vec<u8>, String)> {
    v["log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["note"].as_str().unwrap().to_owned(),
                unhex(s["record_hex"].as_str().unwrap()),
                s["want"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn passkey_log_state_machine() {
    let v = load();
    let mut st = State::default();
    let mut re = State::default();
    for (i, (note, rec, want)) in log(&v).iter().enumerate() {
        let e = parse_record(rec).unwrap_or_else(|e| panic!("{note}: {e}"));
        let got = st
            .apply(i as u64, &e, true)
            .err()
            .map_or("", |c| c.as_str());
        assert_eq!(got, want, "log[{i}] {note}");
        if want.is_empty() {
            re.apply(i as u64, &e, false).unwrap(); // reload path (verified before)
        }
    }
    // Reload replays the same counters and revocations.
    let p1 = v["known_owner_keys"][0].as_str().unwrap();
    for e in log(&v).iter().map(|(_, r, _)| r) {
        if let Ok(Body::OwnerPasskey { cose, .. }) = parse_record(e).map(|e| e.body) {
            let id = moochy_keylog::entry::owner_key_id(cose);
            let (a, b) = (st.owner_key(&id), re.owner_key(&id));
            if let (Some(a), Some(b)) = (a, b) {
                assert_eq!(a, b, "{id}");
            }
        }
    }
    let first = st
        .owner_key(&moochy_keylog::entry::owner_key_id(&unhex(
            v["cose_hex"].as_str().unwrap(),
        )))
        .unwrap();
    assert_eq!(first.owner_pub.to_vec(), unhex(p1));
    let pk = first.passkey.as_ref().unwrap();
    assert!(pk.email_proof && first.revoked);
    assert_eq!(pk.counter, 5); // its co-signature of the second passkey; replays did not move it
}

#[test]
fn passkey_monitor_alerts() {
    let v = load();
    let recs: Vec<Vec<u8>> = log(&v).into_iter().map(|(_, r, _)| r).collect();
    let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
    let known: Vec<[u8; 32]> = v["known_owner_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| unhex(h.as_str().unwrap()).try_into().unwrap())
        .collect();
    assert_eq!(
        known[0],
        passkey_digest(&unhex(v["cose_hex"].as_str().unwrap()))
    );
    let run = |owner_keys: Vec<[u8; 32]>| -> Vec<String> {
        let mut m = Mirror::new(
            "keylog.test/v1",
            NoteKey::parse(v["vkey"].as_str().unwrap()).unwrap(),
        );
        m.set_me(Some(Me {
            pseudonym: v["me"].as_str().unwrap().to_owned(),
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
                Alert::UnknownPasskey {
                    idx, email_proof, ..
                } => Some(format!("UnknownPasskey:{idx}:{email_proof}")),
                Alert::PasskeyCounter { idx, .. } => Some(format!("PasskeyCounter:{idx}")),
                Alert::OwnerKeyRevoked { idx, .. } => Some(format!("OwnerKeyRevoked:{idx}")),
                Alert::NotSignedByMe { idx, .. } => Some(format!("NotSignedByMe:{idx}")),
                _ => None,
            })
            .collect()
    };
    // Unknown passkeys: the email-proof registration is flagged as such.
    assert_eq!(
        run(Vec::new()),
        [
            "UnknownPasskey:0:true",
            "NotSignedByMe:3",
            "NotSignedByMe:4",
            "PasskeyCounter:5",
            "PasskeyCounter:6",
            "NotSignedByMe:7",
            "UnknownPasskey:8:false",
            "NotSignedByMe:9",
            "NotSignedByMe:10",
            "NotSignedByMe:14",
            "OwnerKeyRevoked:15",
            "NotSignedByMe:17",
            "NotSignedByMe:23",
        ]
    );
    // Both passkeys acknowledged (created on this user's devices): only the counter
    // regressions and the revocation remain.
    assert_eq!(
        run(known),
        ["PasskeyCounter:5", "PasskeyCounter:6", "OwnerKeyRevoked:15"]
    );
}
