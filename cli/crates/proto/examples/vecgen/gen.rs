//! Deterministic golden vectors for `spec/vectors/` (plan 03 §17, CONTRACT §1–4, §11).
//! Shared by `examples/vecgen/main.rs` (writes the files) and `tests/vectors.rs` (fails on drift).
//! Every input is a fixed constant; every byte string is lowercase hex unless the key says
//! `_text` (UTF-8) or `_b64` (base64url-no-pad). Integers are JSON numbers.
#![allow(clippy::pedantic, clippy::type_complexity, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use moochy_proto::crypto::{self, ContentKey, EncSecret, RequestOpener, ResponseOpener, ResponseSealer, SaltName, SignKey, TaskContext};
use moochy_proto::enc::{label, u64be};
use moochy_proto::msg::{CacheTtl, Dialect, InnerPayload, Projection, Receipt, ReceiptStatus, RouteHeader, Usage};
use moochy_proto::money::{self, CatalogEntry};
use moochy_proto::{B, DeviceId, Error, RepoId, TaskId, b64, json, lp, unb64, username};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn err(e: Error) -> &'static str {
    match e {
        Error::Malformed => "malformed",
        Error::Json => "json",
        Error::TooLarge => "too_large",
        Error::Decrypt => "decrypt",
        Error::BadSignature => "bad_signature",
        Error::Hash => "hash",
        Error::Sequence => "sequence",
        Error::Overflow => "overflow",
        Error::Rng => "rng",
    }
}

fn outcome<T>(r: Result<T, Error>) -> &'static str {
    r.map_or_else(err, |_| "ok")
}

/// Deterministic SHA-256 stream: `SHA-256(seed || u64_be(i))` blocks.
fn det_bytes(seed: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0u64;
    while out.len() < n {
        out.extend_from_slice(&crypto::sha256(&[seed.as_bytes(), &i.to_be_bytes()].concat()));
        i += 1;
    }
    out.truncate(n);
    out
}

fn det32(seed: &str) -> [u8; 32] {
    det_bytes(seed, 32).try_into().unwrap()
}

/// RNG that replays fixed bytes (HPKE ephemeral key = DeriveKeyPair(first 32 bytes read)).
struct FixedRng(Vec<u8>, usize);
impl rand_core::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for d in dst {
            *d = self.0[self.1];
            self.1 += 1;
        }
    }
}
impl rand_core::CryptoRng for FixedRng {}

/// Raw ChaCha20-Poly1305 open (ct || tag), independent of the library's stream state machine.
fn aead_open(key: &[u8; 32], seq: u32, aad: &[u8], ct: &[u8]) -> bool {
    use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    let k = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap());
    let mut n = [0u8; 12];
    n[8..].copy_from_slice(&seq.to_be_bytes());
    let mut buf = ct.to_vec();
    k.open_in_place(Nonce::assume_unique_for_key(n), Aad::from(aad), &mut buf).is_ok()
}

fn req_aad(task: &TaskId, seq: u32, last: bool) -> Vec<u8> {
    lp(&[label::REQ, &[0x01], &task.0.0, &seq.to_be_bytes(), &[u8::from(last)]]).unwrap()
}

fn resp_aad(task: &TaskId, attempt: u8, r: &[u8; 32], seq: u32, last: bool) -> Vec<u8> {
    lp(&[label::RESP, &task.0.0, &u64be(attempt.into()), r, &seq.to_be_bytes(), &[u8::from(last)]]).unwrap()
}

const TASK: &str = "01K6A0000000000000000000T1";
const TASK2: &str = "01K6A0000000000000000000T2";
const REPO: &str = "r_01K6A0000000000000000000R1";
const GW: &str = "d_01K6A0000000000000000000G1";
const W1: &str = "d_01K6A0000000000000000000W1";
const W2: &str = "d_01K6A0000000000000000000W2";

fn task() -> TaskId {
    TASK.parse().unwrap()
}
fn dev(s: &str) -> DeviceId {
    s.parse().unwrap()
}

pub const SONNET: &str = r#"{"model":"anthropic/claude-sonnet-5.5","provider":"anthropic","provider_model_id":"claude-sonnet-5-5","aliases":["claude-sonnet-5-5"],"dialects":["anthropic.messages"],"in":2000000,"out":10000000,"cache_write_5m":2500000,"cache_write_1h":4000000,"cache_read":200000,"max_image_tokens":1600,"max_page_tokens":3000,"fast_multiplier":6,"default_effort":"high","max_output":64000,"source":"curated"}"#;
const DEEPSEEK: &str = r#"{"model":"deepseek/deepseek-chat","provider":"openrouter","provider_model_id":"deepseek/deepseek-chat","dialects":["openai.chat","anthropic.messages"],"in":270000,"out":1100000,"cache_write_5m":0,"cache_write_1h":0,"cache_read":70000,"max_image_tokens":0,"max_page_tokens":0,"default_effort":"medium","max_output":8192,"source":"openrouter_import"}"#;

fn route_text() -> String {
    format!(
        r#"{{"repo_id":"{REPO}","dialect":"anthropic.messages","model":"anthropic/claude-sonnet-5.5","effort":"high","max_tokens":1024,"est_input_tokens":42,"cache_ttl":"none","stream":true,"affinity":"{}","flags":[]}}"#,
        b64(&[0xA5; 16])
    )
}

pub fn all() -> Vec<(&'static str, Value)> {
    vec![
        ("encoding.json", encoding()),
        ("json_strict.json", json_strict()),
        ("envelope.json", envelope()),
        ("bomb.json", bomb()),
        ("signatures.json", signatures()),
        ("zip215.json", zip215()),
        ("route.json", route()),
        ("money.json", money_vectors()),
        ("usernames.json", usernames()),
    ]
}

// ------------------------------------------------------------------ encoding

fn encoding() -> Value {
    let lp_cases: Vec<Value> = [
        vec![],
        vec![b"".to_vec()],
        vec![b"moochy/v1/task".to_vec(), TASK.as_bytes().to_vec()],
        vec![vec![0x01], vec![0xAB; 16], 7u32.to_be_bytes().to_vec(), vec![1]],
        vec![u64be(3).to_vec(), u64be(u64::MAX).to_vec(), "é✓".as_bytes().to_vec()],
    ]
    .iter()
    .map(|f| {
        let refs: Vec<&[u8]> = f.iter().map(Vec::as_slice).collect();
        json!({"fields": f.iter().map(|x| hex(x)).collect::<Vec<_>>(), "out": hex(&lp(&refs).unwrap())})
    })
    .collect();
    let labels: Vec<Value> = label::ALL
        .iter()
        .map(|l| json!({"label_text": std::str::from_utf8(l).unwrap(), "lp": hex(&lp(&[l]).unwrap())}))
        .collect();
    let ints = json!([
        {"call_site": "u32(7)", "bytes": hex(&7u32.to_be_bytes())},
        {"call_site": "u32(4294967295)", "bytes": hex(&u32::MAX.to_be_bytes())},
        {"call_site": "u64(attempt=2)", "bytes": hex(&u64be(2))},
        {"call_site": "u64(seq=7) (no width written → u64)", "bytes": hex(&u64be(7))},
    ]);
    let b64_valid: Vec<Value> = [&b""[..], b"\x00", b"\xfb\xff", b"\xff\xff\xff", &[0xA5; 16], &[7; 32]]
        .iter()
        .map(|b| json!({"bytes": hex(b), "b64": b64(b)}))
        .collect();
    let b64_invalid = ["-_8=", "+/8", "-_9", "a", " AA", "AA\n", "AAA=", "A==="];
    for s in b64_invalid {
        assert!(unb64(s).is_err(), "{s}");
    }
    let ulid_valid: Vec<Value> = [TASK, "00000000000000000000000000", "7ZZZZZZZZZZZZZZZZZZZZZZZZZ", "01ARZ3NDEKTSV4RRFFQ69G5FAV"]
        .iter()
        .map(|s| {
            let t: TaskId = s.parse().unwrap();
            assert_eq!(t.to_string(), *s);
            json!({"text": s, "bytes": hex(&t.0.0), "timestamp_ms": t.0.timestamp_ms()})
        })
        .collect();
    let ulid_invalid = [
        "01k6a0000000000000000000t1",
        "01K6A0000000000000000000T",
        "01K6A0000000000000000000T11",
        "81K6A0000000000000000000T1",
        "01K6A000000000000000000OT1",
        "01K6A000000000000000000IT1",
        "01K6A000000000000000000LT1",
        "01K6A000000000000000000UT1",
        "",
    ];
    for s in ulid_invalid {
        assert!(s.parse::<TaskId>().is_err(), "{s}");
    }
    let ids_valid = [GW, "u_01K6A0000000000000000000U1", REPO, "p_01K6A0000000000000000000P1"];
    let ids_invalid = [
        ("d_", "01K6A0000000000000000000G1"),
        ("d_", "D_01K6A0000000000000000000G1"),
        ("d_", "u_01K6A0000000000000000000G1"),
        ("d_", "d_01k6a0000000000000000000g1"),
        ("d_", "d__01K6A0000000000000000000G1"),
        ("r_", "r_01K6A0000000000000000000R1 "),
    ];
    for (_, s) in ids_invalid {
        assert!(s.parse::<DeviceId>().is_err() && s.parse::<RepoId>().is_err(), "{s}");
    }
    json!({
        "_schema": "lp: fields[] (hex) → out (hex), each field u32_be(len)||bytes. labels: label_text → lp(label). ints: width rule inside lp (CONTRACT §1 D4). b64_valid: bytes (hex) ↔ b64 (base64url, no padding); b64_invalid: strings a strict decoder MUST reject. ulid_valid: canonical text ↔ 16 bytes (hex) and its 48-bit timestamp; ulid_invalid: MUST be rejected (lowercase, wrong length, first char > '7', I/L/O/U). ids_valid: prefixed ids (d_, u_, r_, p_ + ULID); ids_invalid: [expected_prefix, text] MUST be rejected.",
        "lp": lp_cases,
        "labels": labels,
        "ints": ints,
        "b64_valid": b64_valid,
        "b64_invalid": b64_invalid,
        "task_id_text": {
            "rule": "task ids appear in JSON, in protobuf strings and inside lp() as the canonical ULID text: exactly 26 chars of UPPERCASE Crockford base32 (0-9 A-Z without I L O U), first char 0-7; 16-byte binary form = big-endian 128-bit value. Lowercase or any other spelling is rejected, never normalized.",
            "text": TASK,
            "bytes": hex(&task().0.0),
            "lp_field": hex(&lp(&[TASK.as_bytes()]).unwrap()),
            "lowercase_rejected": TASK.to_ascii_lowercase(),
        },
        "ulid_valid": ulid_valid,
        "ulid_invalid": ulid_invalid,
        "ids_valid": ids_valid,
        "ids_invalid": ids_invalid.iter().map(|(p, s)| json!([p, s])).collect::<Vec<_>>(),
        "task_freshness": {
            "window_ms": moochy_proto::enc::FRESHNESS_MS,
            "rule": "admissible(task, now, boot) = |ts(task) − now| ≤ window AND ts(task) ≥ boot (process start, CONTRACT D18)",
            "cases": [
                {"task": TASK, "now_ms": task().0.timestamp_ms() + 600_000, "boot_ms": 0, "admissible": true},
                {"task": TASK, "now_ms": task().0.timestamp_ms() + 600_001, "boot_ms": 0, "admissible": false},
                {"task": TASK, "now_ms": task().0.timestamp_ms() - 600_001, "boot_ms": 0, "admissible": false},
                {"task": TASK, "now_ms": task().0.timestamp_ms(), "boot_ms": task().0.timestamp_ms(), "admissible": true},
                {"task": TASK, "now_ms": task().0.timestamp_ms(), "boot_ms": task().0.timestamp_ms() + 1, "admissible": false},
            ],
        },
    })
}

// ------------------------------------------------------------------ strict JSON

fn json_strict() -> Value {
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let deep_obj = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty object", b"{}".to_vec()),
        ("nested distinct keys", br#"{"a":1,"b":{"a":2}}"#.to_vec()),
        ("i64 bounds", br#"{"a":-9223372036854775808,"b":9223372036854775807}"#.to_vec()),
        ("float and surrogate pair", br#"{"a":1.5e300,"s":"\ud83d\ude00"}"#.to_vec()),
        ("whitespace", b" {\"a\" : [1, 2, null, true] } \n".to_vec()),
        ("depth 64 arrays", deep(64).into_bytes()),
        ("depth 64 objects", deep_obj(64).into_bytes()),
        ("duplicate key", br#"{"a":1,"a":2}"#.to_vec()),
        ("duplicate key nested", br#"{"x":{"a":1,"a":1}}"#.to_vec()),
        ("duplicate key via escape", br#"[{"a":1,"\u0061":2}]"#.to_vec()),
        ("integer above i64", br#"{"a":9223372036854775808}"#.to_vec()),
        ("integer below i64", br#"{"a":-9223372036854775809}"#.to_vec()),
        ("integer above u64", br#"{"a":18446744073709551616}"#.to_vec()),
        ("big integer in array", br#"[1,-99999999999999999999]"#.to_vec()),
        ("integer-looking text inside a string is fine", br#"{"a":"99999999999999999999","b":"-1e999"}"#.to_vec()),
        ("float beyond i64 range is a float", br#"{"a":1e30,"b":-1.5e20}"#.to_vec()),
        ("float overflow", br#"{"a":1e400}"#.to_vec()),
        ("lone high surrogate", br#"{"a":"\ud800"}"#.to_vec()),
        ("lone low surrogate", br#"{"a":"\udc00x"}"#.to_vec()),
        ("lone surrogate in key", br#"{"\ud800":1}"#.to_vec()),
        ("invalid utf-8", b"{\"a\":\"\xff\"}".to_vec()),
        ("overlong utf-8", b"{\"a\":\"\xc0\xaf\"}".to_vec()),
        ("trailing data", b"{} {}".to_vec()),
        ("trailing comma", b"{\"a\":1,}".to_vec()),
        ("NaN", b"NaN".to_vec()),
        ("empty input", b"".to_vec()),
        ("depth 65 arrays", deep(65).into_bytes()),
        ("depth 65 objects", deep_obj(65).into_bytes()),
    ];
    let out: Vec<Value> = cases.iter().map(|(n, b)| json!({"name": n, "input": hex(b), "valid": json::check(b).is_ok()})).collect();
    json!({
        "_schema": "CONTRACT §1 parser-differential rule. cases[]: name, input (hex of the exact bytes), valid (true = MUST accept, false = MUST reject). Max depth 64 (a scalar inside 64 nested containers is valid, 65 is not). Integers must fit i64; non-integer numbers must be finite f64.",
        "cases": out,
    })
}

// ------------------------------------------------------------------ envelope

fn envelope() -> Value {
    let t = task();
    let ck = ContentKey::from_bytes(det32("ck"));
    let route = route_text().into_bytes();
    RouteHeader::parse(&route).unwrap();
    let repo: RepoId = REPO.parse().unwrap();
    let gw_key = SignKey::from_seed(&det32("gateway-sign"));
    let s_seed = det32("S");

    // Small inner payload, one chunk.
    let body = br#"{"model":"claude-sonnet-5-5","max_tokens":1024,"stream":true,"messages":[{"role":"user","content":"hello"}]}"#.to_vec();
    let mut headers = BTreeMap::new();
    headers.insert("anthropic-version".to_owned(), "2023-06-01".to_owned());
    let ctx = TaskContext { task: &t, repo: &repo, route: &route };
    let inner = InnerPayload::build(&ctx, body, headers, s_seed, dev(GW), &gw_key).unwrap();
    let payload = inner.to_bytes().unwrap();
    let z = zstd::bulk::compress(&payload, 3).unwrap();
    let small = crypto::seal_compressed(&ck, &t, &z).unwrap();
    // Large inner payload (base64 of 100,000 deterministic bytes), several chunks.
    let big_inner = InnerPayload::build(&ctx, det_bytes("big-body", 100_000), BTreeMap::new(), s_seed, dev(GW), &gw_key).unwrap();
    let big_payload = big_inner.to_bytes().unwrap();
    let big_z = zstd::bulk::compress(&big_payload, 3).unwrap();
    let big = crypto::seal_compressed(&ck, &t, &big_z).unwrap();
    assert!(big.chunks.len() >= 2);
    for (sealed, want) in [(&small, &payload), (&big, &big_payload)] {
        let mut o = RequestOpener::new(&ck, &t).unwrap();
        sealed.chunks.iter().for_each(|c| o.push(c).unwrap());
        assert_eq!(&o.finish().unwrap(), want);
    }
    let k_req = crypto::k_req(&ck, &t).unwrap();
    let chunk_json = |c: &moochy_proto::pb::Chunk| json!({"seq": c.seq, "last": c.last, "ct": hex(&c.ct), "aad": hex(&req_aad(&t, c.seq, c.last))});

    // Request tamper cases (open one chunk with these inputs).
    let c0 = &small.chunks[0];
    let mut req_cases = vec![json!({"name": "baseline", "task": TASK, "seq": 0, "last": true, "ct": hex(&c0.ct), "ok": true})];
    let mut flipped = c0.ct.to_vec();
    flipped[0] ^= 1;
    for (name, task_s, seq, last, ct) in [
        ("task changed", TASK2, 0u32, true, c0.ct.to_vec()),
        ("seq changed", TASK, 1, true, c0.ct.to_vec()),
        ("last flag cleared", TASK, 0, false, c0.ct.to_vec()),
        ("ciphertext bit flipped", TASK, 0, true, flipped.clone()),
    ] {
        let tt: TaskId = task_s.parse().unwrap();
        let key = crypto::k_req(&ck, &tt).unwrap();
        let ok = aead_open(key.expose(), seq, &req_aad(&tt, seq, last), &ct);
        assert!(!ok, "{name}");
        req_cases.push(json!({"name": name, "task": task_s, "seq": seq, "last": last, "ct": hex(&ct), "ok": ok}));
    }
    assert!(aead_open(k_req.expose(), 0, &req_aad(&t, 0, true), &c0.ct));

    // Wraps: two recipients, fixed ephemeral IKMs; tampered route header fails.
    let mut wraps = Vec::new();
    for (i, w) in [W1, W2].iter().enumerate() {
        let sk_bytes = det32(&format!("enc-sk-{i}"));
        let sk = EncSecret::from_bytes(&sk_bytes).unwrap();
        let eph = det32(&format!("eph-ikm-{i}"));
        let wr = crypto::wrap_with_rng(&sk.public(), &t, &route, &ck, &mut FixedRng(eph.to_vec(), 0)).unwrap();
        assert_eq!(crypto::unwrap(&sk, &t, &route, &wr).unwrap().expose(), ck.expose());
        let mut tampered = route.clone();
        let pos = tampered.windows(4).position(|x| x == b"1024").unwrap();
        tampered[pos] = b'9';
        assert_eq!(crypto::unwrap(&sk, &t, &tampered, &wr).err(), Some(Error::Decrypt));
        assert_eq!(crypto::unwrap(&sk, &TASK2.parse().unwrap(), &route, &wr).err(), Some(Error::Decrypt));
        wraps.push(json!({
            "worker_device": w, "enc_sk": hex(&sk_bytes), "enc_pub": hex(&sk.public()), "ephemeral_ikm": hex(&eph),
            "info": hex(&lp(&[label::WRAP, crypto::SUITE_ID, TASK.as_bytes()]).unwrap()),
            "wrap": hex(&wr), "route_tampered_text": String::from_utf8(tampered).unwrap(), "route_tampered_ok": false,
            "task_changed": TASK2, "task_changed_ok": false,
        }));
    }

    // Responses: attempt 1 and attempt 2 (same R and same worker) → different RK.
    let r = det32("R-1");
    let r2 = det32("R-2");
    let parts: [&[u8]; 3] = [b"event: message_start\n\n", b"data: {\"text\":\"hi\"}\n\n", b""];
    let mut attempts = Vec::new();
    let mut rks = Vec::new();
    for (attempt, rr, worker) in [(1u8, r, W1), (2, r, W1), (2, r2, W2)] {
        let rk = crypto::rk(&ck, &rr, &t, &dev(worker), attempt).unwrap();
        rks.push(*rk.expose());
        let mut s = ResponseSealer::new(&ck, &rr, &t, &dev(worker), attempt).unwrap();
        let mut o = ResponseOpener::new(&ck, &rr, &t, &dev(worker), attempt).unwrap();
        let chunks: Vec<Value> = parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let c = s.seal(p, i == 2).unwrap();
                assert_eq!(&o.open(c.clone()).unwrap()[..], *p);
                json!({"seq": c.seq, "last": c.last, "pt": hex(p), "ct": hex(&c.ct), "aad": hex(&resp_aad(&t, attempt, &rr, c.seq, c.last))})
            })
            .collect();
        attempts.push(json!({
            "attempt": attempt, "worker_device": worker, "R": hex(&rr),
            "rk_info": hex(&lp(&[label::RESP, TASK.as_bytes(), worker.as_bytes(), &u64be(attempt.into())]).unwrap()),
            "rk": hex(rk.expose()), "chunks": chunks, "running_sha256": hex(&s.running_hash()),
        }));
    }
    assert!(rks[0] != rks[1] && rks[1] != rks[2] && rks[0] != rks[2]);

    // Response tamper cases: each AAD/key input changed once (plus a ct bit).
    let rk1 = crypto::rk(&ck, &r, &t, &dev(W1), 1).unwrap();
    let mut s1 = ResponseSealer::new(&ck, &r, &t, &dev(W1), 1).unwrap();
    let base = s1.seal(parts[0], false).unwrap();
    assert!(aead_open(rk1.expose(), 0, &resp_aad(&t, 1, &r, 0, false), &base.ct));
    let mut resp_cases = vec![json!({"name": "baseline", "task": TASK, "worker_device": W1, "attempt": 1, "R": hex(&r), "seq": 0, "last": false, "ct": hex(&base.ct), "ok": true})];
    let mut bad_ct = base.ct.to_vec();
    bad_ct[3] ^= 0x10;
    for (name, task_s, worker, attempt, rr, seq, last, ct) in [
        ("task changed", TASK2, W1, 1u8, r, 0u32, false, base.ct.to_vec()),
        ("worker changed", TASK, W2, 1, r, 0, false, base.ct.to_vec()),
        ("attempt changed", TASK, W1, 2, r, 0, false, base.ct.to_vec()),
        ("R changed", TASK, W1, 1, r2, 0, false, base.ct.to_vec()),
        ("seq changed", TASK, W1, 1, r, 1, false, base.ct.to_vec()),
        ("last flag set", TASK, W1, 1, r, 0, true, base.ct.to_vec()),
        ("ciphertext bit flipped", TASK, W1, 1, r, 0, false, bad_ct.clone()),
    ] {
        let tt: TaskId = task_s.parse().unwrap();
        let key = crypto::rk(&ck, &rr, &tt, &dev(worker), attempt).unwrap();
        let ok = aead_open(key.expose(), seq, &resp_aad(&tt, attempt, &rr, seq, last), &ct);
        assert!(!ok, "{name}");
        resp_cases.push(json!({"name": name, "task": task_s, "worker_device": worker, "attempt": attempt, "R": hex(&rr), "seq": seq, "last": last, "ct": hex(&ct), "ok": ok}));
    }

    // Sealed refusal detail (CONTRACT §3): K_det from (CK, R, task, worker, attempt), zero nonce.
    let detail = "field `mcp_servers` is not allowed by the donor pool";
    let code = "firewall";
    let kd = crypto::k_det(&ck, &r, &t, &dev(W1), 1).unwrap();
    let sd = crypto::seal_detail(&ck, &r, &t, &dev(W1), 1, code, detail).unwrap();
    let daad = |tt: &TaskId, a: u8, c: &str| lp(&[label::DETAIL, &tt.0.0, &u64be(a.into()), c.as_bytes()]).unwrap();
    assert!(aead_open(kd.expose(), 0, &daad(&t, 1, code), &sd));
    assert_eq!(crypto::open_detail(&ck, &r, &t, &dev(W1), 1, code, &sd).unwrap(), detail);
    let mut detail_cases = vec![json!({"name": "baseline", "task": TASK, "worker_device": W1, "attempt": 1, "R": hex(&r), "code_text": code, "ok": true})];
    for (name, task_s, worker, attempt, rr, c) in [
        ("code changed", TASK, W1, 1u8, r, "busy"),
        ("attempt changed", TASK, W1, 2, r, code),
        ("R changed", TASK, W1, 1, r2, code),
        ("worker changed", TASK, W2, 1, r, code),
        ("task changed", TASK2, W1, 1, r, code),
    ] {
        let tt: TaskId = task_s.parse().unwrap();
        let ok = crypto::open_detail(&ck, &rr, &tt, &dev(worker), attempt, c, &sd).is_ok();
        assert!(!ok, "{name}");
        detail_cases.push(json!({"name": name, "task": task_s, "worker_device": worker, "attempt": attempt, "R": hex(&rr), "code_text": c, "ok": ok}));
    }
    let sealed_detail = json!({
        "worker_device": W1, "attempt": 1, "R": hex(&r), "code_text": code, "detail_text": detail,
        "k_det_info": hex(&lp(&[label::DETAIL, TASK.as_bytes(), W1.as_bytes(), &u64be(1)]).unwrap()),
        "k_det": hex(kd.expose()), "nonce": hex(&[0u8; 12]), "aad": hex(&daad(&t, 1, code)), "sealed": hex(&sd),
        "max_detail_bytes": crypto::MAX_DETAIL, "open_cases": detail_cases,
    });

    let s_req = crypto::salt(&s_seed, SaltName::Req).unwrap();
    let s_resp = crypto::salt(&s_seed, SaltName::Resp).unwrap();
    let s_pid = crypto::salt(&s_seed, SaltName::Pid).unwrap();
    json!({
        "_schema": "Envelope (CONTRACT §3–4). Inputs: ck, task (text; task_id in lp = 26-char text, task_id_16B = ULID bytes), route_text (exact route-header bytes). k_req = HKDF(salt='', ikm=ck, info=k_req_info). request.small/big: compressed (hex zstd frame of the inner payload) → chunks[] {seq, last, ct = ciphertext||tag, aad}; nonce = 8 zero bytes || u32_be(seq); payload_text / payload_sha256 = the decompressed inner payload. request_tamper[]: open ONE chunk with K_req(task), aad(task, seq, last) → ok. wraps[]: HPKE base X25519/HKDF-SHA256/ChaCha20Poly1305, ephemeral = DeriveKeyPair(ephemeral_ikm), info = lp('moochy/v1/wrap', suite_id, task), aad = route bytes; wrap = enc(32)||ct(32)||tag(16); unwrap with route_tampered_text or task_changed MUST fail. responses[]: R, rk = HKDF(salt=R, ikm=ck, info=rk_info); attempts 1 and 2 of one task (same R, same worker) have different rk. response_tamper[]: open one chunk with RK(ck, R, task, worker_device, attempt) and aad(task_16B, u64(attempt), R, u32(seq), last) → ok. salts: S_x = HKDF(salt='', ikm=S, info=lp('moochy/v1/salt', name)). sealed_detail: K_det = HKDF(salt=R, ikm=ck, info=k_det_info = lp('moochy/v1/detail', task, worker_device, u64(attempt))); sealed = ChaCha20-Poly1305(K_det, nonce = 12 zero bytes, aad = lp('moochy/v1/detail', task_16B, u64(attempt), code), detail_text) = ct||tag, detail ≤ max_detail_bytes; open_cases[]: open `sealed` with those inputs → ok.",
        "ck": hex(ck.expose()),
        "task": TASK,
        "task_16b": hex(&t.0.0),
        "route_text": route_text(),
        "suite_id_text": std::str::from_utf8(crypto::SUITE_ID).unwrap(),
        "k_req_info": hex(&lp(&[label::REQ, TASK.as_bytes()]).unwrap()),
        "k_req": hex(k_req.expose()),
        "request": {
            "small": {"payload_text": String::from_utf8(payload.clone()).unwrap(), "payload_sha256": hex(&crypto::sha256(&payload)), "compressed": hex(&z), "body_len": small.body_len, "chunks": small.chunks.iter().map(chunk_json).collect::<Vec<_>>()},
            "big": {"payload_sha256": hex(&crypto::sha256(&big_payload)), "payload_len": big_payload.len(), "compressed_sha256": hex(&crypto::sha256(&big_z)), "body_len": big.body_len, "chunks": big.chunks.iter().map(chunk_json).collect::<Vec<_>>()},
        },
        "request_tamper": req_cases,
        "wraps": wraps,
        "responses": attempts,
        "response_tamper": resp_cases,
        "sealed_detail": sealed_detail,
        "salts": {"S": hex(&s_seed), "S_req": hex(s_req.expose()), "S_resp": hex(s_resp.expose()), "S_pid": hex(s_pid.expose())},
    })
}

// ------------------------------------------------------------------ zstd bomb

fn bomb() -> Value {
    let t = task();
    let ck = ContentKey::from_bytes(det32("bomb-ck"));
    let cap = crypto::MAX_PAYLOAD;
    let mut cases = Vec::new();
    let mut push = |name: &str, z: Vec<u8>, note: &str| {
        let sealed = crypto::seal_compressed(&ck, &t, &z).unwrap();
        let mut o = RequestOpener::new(&ck, &t).unwrap();
        let r = sealed.chunks.iter().try_for_each(|c| o.push(c)).and_then(|()| o.finish());
        let (outcome, len) = match &r {
            Ok(p) => ("ok", Some(p.len())),
            Err(e) => (err(*e), None),
        };
        cases.push(json!({
            "name": name, "note": note, "compressed_len": z.len(),
            "chunks": sealed.chunks.iter().map(|c| json!({"seq": c.seq, "last": c.last, "ct": hex(&c.ct)})).collect::<Vec<_>>(),
            "outcome": outcome, "payload_len": len,
        }));
    };
    push("exactly 32 MiB", zstd::bulk::compress(&vec![b' '; cap], 19).unwrap(), "decompresses to exactly the cap: accepted");
    push("32 MiB + 1", zstd::bulk::compress(&vec![b' '; cap + 1], 19).unwrap(), "one byte over the cap: refused while streaming");
    push("256 MiB bomb", zstd::bulk::compress(&vec![0u8; 256 << 20], 19).unwrap(), "refused without allocating more than the cap");
    let mut tr = zstd::bulk::compress(b"{}", 3).unwrap();
    tr.push(0);
    push("trailing byte after the zstd frame", tr, "exactly one zstd frame, nothing after it");
    let one = zstd::bulk::compress(b"{}", 3).unwrap();
    push("two concatenated zstd frames", [one.clone(), one].concat(), "exactly one zstd frame");
    let full = zstd::bulk::compress(&[7u8; 1000], 3).unwrap();
    push("truncated zstd frame", full[..full.len() - 2].to_vec(), "frame must be complete at the last chunk");
    push("not zstd", b"not zstd at all".to_vec(), "");
    json!({
        "_schema": "Decompression bomb guard (plan 03 §2: 32 MiB decompressed). ck, task; cases[]: chunks to open in order with K_req (as in envelope.json), then zstd-decompress (window ≤ 2^25) with a hard output cap of max_payload bytes; outcome: ok (payload_len given) | too_large | malformed.",
        "ck": hex(ck.expose()),
        "task": TASK,
        "max_payload": cap,
        "cases": cases,
    })
}

// ------------------------------------------------------------------ signatures

fn signatures() -> Value {
    let t = task();
    let k = SignKey::from_seed(&det32("device-sign"));
    let pk = k.public();
    let sig_case = |name: &str, msg: Vec<u8>| {
        let sig = k.sign(&msg);
        crypto::verify(&pk, &msg, &sig).unwrap();
        let mut bad = msg.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(crypto::verify(&pk, &bad, &sig).is_err());
        json!({"name": name, "msg": hex(&msg), "sig": hex(&sig), "msg_last_byte_flipped_valid": false})
    };
    let nonce = det32("hello-nonce");
    let exporter = det32("tls-exporter");
    let origin = "https://relay.moochy.dev:443";
    let route = route_text().into_bytes();
    let repo: RepoId = REPO.parse().unwrap();
    let body_sha = crypto::sha256(b"{\"model\":\"m\"}");
    let mut headers = BTreeMap::new();
    headers.insert("anthropic-beta".to_owned(), "context-1m-2025-08-07".to_owned());
    headers.insert("anthropic-version".to_owned(), "2023-06-01".to_owned());
    let hsha = crypto::headers_sha256(&headers).unwrap();
    let headers_lp = lp(&[b"anthropic-beta", b"context-1m-2025-08-07", b"anthropic-version", b"2023-06-01"]).unwrap();
    assert_eq!(crypto::sha256(&headers_lp), hsha);
    let r1 = det32("R-1");
    let running = det32("running");
    let cp_fields: Vec<(&str, Vec<u8>)> = vec![
        ("label 'moochy/v1/resp-progress'", label::RESP_PROGRESS.to_vec()),
        ("task_id (26-char text)", TASK.as_bytes().to_vec()),
        ("u64(attempt = 1)", u64be(1).to_vec()),
        ("R (32 bytes)", r1.to_vec()),
        ("u64(seq = 7)", u64be(7).to_vec()),
        ("running_sha256 (32 bytes)", running.to_vec()),
    ];
    let cp_refs: Vec<&[u8]> = cp_fields.iter().map(|(_, b)| b.as_slice()).collect();
    assert_eq!(lp(&cp_refs).unwrap(), crypto::checkpoint_msg(&t, 1, &r1, 7, &running).unwrap());
    let receipt = Receipt {
        v: 1,
        task_id: t,
        attempt: 1,
        repo_id: repo,
        pledge_id: "p_01K6A0000000000000000000P1".parse().unwrap(),
        worker_device: dev(W1),
        gateway_device: dev(GW),
        dialect: Dialect::AnthropicMessages,
        provider: "anthropic".into(),
        model_reported: "claude-sonnet-5-5".into(),
        usage: Usage { input: 2000, output: 1800, cache_write_5m: 2000, cache_write_1h: 0, cache_read: 36000, estimated: false, provider_cost_uusd: None },
        catalog_version: 1,
        cost_uusd: 34_200,
        req_commit: B(det32("req-commit")),
        resp_commit: B(det32("resp-commit")),
        provider_req_hash: B(det32("pid")),
        status: ReceiptStatus::Ok,
        t_start: 1_790_000_000_000,
        t_started: 1_790_000_000_300,
        t_end: 1_790_000_005_000,
    };
    let (rbytes, rsig) = crypto::sign_receipt(&k, &receipt).unwrap();
    assert_eq!(crypto::open_receipt(&pk, &rbytes, &rsig).unwrap(), receipt);
    let projection = Projection {
        v: 1,
        receipt_ref: B(det32("ref")[..16].try_into().unwrap()),
        repo_id: repo,
        donor: Some("ps_K7Q2M9XDRB4TWN8E".into()),
        model: "anthropic/claude-sonnet-5.5".into(),
        cost_uusd: 34_200,
        day: "2026-09-21".into(),
        receipt_sha256: B(crypto::sha256(&rbytes)),
    };
    let (pbytes, psig) = crypto::sign_projection(&k, &projection).unwrap();
    // The same bytes signed as a receipt never verify as a projection (domain separation).
    assert!(crypto::open_projection(&pk, &rbytes, &rsig).is_err());
    let s_seed = det32("S");
    let s_req = crypto::salt(&s_seed, SaltName::Req).unwrap();
    let s_resp = crypto::salt(&s_seed, SaltName::Resp).unwrap();
    let s_pid = crypto::salt(&s_seed, SaltName::Pid).unwrap();
    let resp_plain = b"event: message_stop\n\n";
    json!({
        "_schema": "Ed25519 (RFC 8032 signing, ZIP-215 verification). signer.seed → signer.public. cases[]: msg = the exact lp(...) byte string named by `name` (inputs listed), sig over msg; flipping the last byte of msg MUST fail. receipt/projection: *_text = exact signed JSON bytes, signature over lp(label, bytes); a receipt signature MUST NOT verify as a projection. headers_sha256 = SHA-256(headers_lp) where headers_lp = lp(name1, value1, name2, value2, …) over lowercase names sorted ascending by bytes (inputs.headers_lp pins the exact bytes); checkpoint_fields pins every field and width of the progress-signature message (u64 attempt, u64 seq); commitments: req_commit = SHA-256(lp('moochy/v1/req-commit', S_req, body)); resp_commit = SHA-256(lp('moochy/v1/resp-commit', S_resp, SHA-256(response plaintext))); provider_req_hash = SHA-256(lp('moochy/v1/provider-req', S_pid, request_id)).",
        "signer": {"seed": hex(&det32("device-sign")), "public": hex(&pk)},
        "inputs": {
            "nonce": hex(&nonce), "dialed_origin_text": origin, "tls_exporter": hex(&exporter), "device_id": W1,
            "task": TASK, "repo_id": REPO, "route_text": route_text(), "body_sha256": hex(&body_sha),
            "headers": headers, "headers_sha256": hex(&hsha), "attempt": 1, "R": hex(&det32("R-1")), "seq": 7, "running_sha256": hex(&det32("running")),
            "dispute_code_text": "resp_commit",
            "headers_lp": hex(&headers_lp),
        },
        "checkpoint_fields": cp_fields.iter().map(|(n, b)| json!({"field": n, "len": b.len(), "bytes": hex(b)})).collect::<Vec<_>>(),
        "cases": [
            sig_case("auth = lp('moochy/v1/auth', nonce, dialed_origin, tls_exporter, device_id)", crypto::auth_msg(&nonce, origin, &exporter, &dev(W1)).unwrap()),
            sig_case("task = lp('moochy/v1/task', task, repo_id, route, body_sha256, headers_sha256)", crypto::task_msg(&t, &repo, &route, &body_sha, &hsha).unwrap()),
            sig_case("checkpoint = lp('moochy/v1/resp-progress', task, u64(attempt), R, u64(seq), running_sha256)", crypto::checkpoint_msg(&t, 1, &det32("R-1"), 7, &det32("running")).unwrap()),
            sig_case("dispute = lp('moochy/v1/dispute', task, u64(attempt), code)", crypto::dispute_msg(&t, 1, "resp_commit").unwrap()),
        ],
        "receipt": {"text": String::from_utf8(rbytes.clone()).unwrap(), "msg": hex(&crypto::receipt_msg(&rbytes).unwrap()), "sig": hex(&rsig)},
        "projection": {"text": String::from_utf8(pbytes.clone()).unwrap(), "msg": hex(&crypto::projection_msg(&pbytes).unwrap()), "sig": hex(&psig)},
        "commitments": {
            "S": hex(&s_seed),
            "body_text": "{\"model\":\"m\"}",
            "req_commit": hex(&crypto::req_commit(&s_req, b"{\"model\":\"m\"}").unwrap()),
            "response_text": std::str::from_utf8(resp_plain).unwrap(),
            "response_sha256": hex(&crypto::sha256(resp_plain)),
            "resp_commit": hex(&crypto::resp_commit(&s_resp, &crypto::sha256(resp_plain)).unwrap()),
            "provider_request_id_text": "msg_01ABCDEF",
            "provider_req_hash": hex(&crypto::provider_req_hash(&s_pid, "msg_01ABCDEF").unwrap()),
            "empty_headers_sha256": hex(&crypto::headers_sha256(&BTreeMap::new()).unwrap()),
        },
    })
}

// ------------------------------------------------------------------ ZIP-215

fn zip215() -> Value {
    // 8 canonical encodings of the 8-torsion points, then the 6 non-canonical low-order encodings.
    let enc: [&str; 14] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];
    let mut small = Vec::new();
    for a in enc {
        for r in enc {
            let pk: [u8; 32] = unhex(a).try_into().unwrap();
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&unhex(r));
            let valid = crypto::verify(&pk, b"Zcash", &sig).is_ok();
            assert!(valid, "ZIP-215: every small-order (A, R) with S = 0 is valid");
            small.push(json!({"pub": a, "sig": hex(&sig), "valid": valid}));
        }
    }
    // RFC 8032 test 1, and the same signature with S + ℓ (non-canonical S: MUST be rejected).
    let k = SignKey::from_seed(&unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").try_into().unwrap());
    let sig = k.sign(b"");
    assert_eq!(hex(&sig), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    let l = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut s_plus_l = sig;
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(sig[32 + i]) + u16::from(l[i]) + carry;
        s_plus_l[32 + i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    let pk = k.public();
    let mut other = vec![
        json!({"name": "RFC 8032 test 1", "pub": hex(&pk), "msg": "", "sig": hex(&sig), "valid": crypto::verify(&pk, b"", &sig).is_ok()}),
        json!({"name": "RFC 8032 test 1 with S + l (non-canonical S)", "pub": hex(&pk), "msg": "", "sig": hex(&s_plus_l), "valid": crypto::verify(&pk, b"", &s_plus_l).is_ok()}),
        json!({"name": "RFC 8032 test 1, message changed", "pub": hex(&pk), "msg": "00", "sig": hex(&sig), "valid": crypto::verify(&pk, b"\x00", &sig).is_ok()}),
    ];
    // A public key that is not a curve point: invalid.
    let not_point = unhex("0200000000000000000000000000000000000000000000000000000000000000");
    other.push(json!({"name": "public key not on the curve", "pub": hex(&not_point), "msg": "", "sig": hex(&sig), "valid": crypto::verify(&not_point.try_into().unwrap(), b"", &sig).is_ok()}));
    assert_eq!(other.iter().map(|v| v["valid"].as_bool().unwrap()).collect::<Vec<_>>(), [true, false, false, false]);
    json!({
        "_schema": "Ed25519 ZIP-215 verification (CONTRACT §1; Go: ed25519consensus.Verify). small_order[]: all 14×14 pairs of low-order encodings (8 canonical + 6 non-canonical) as A (pub) and R (sig[0:32]) with S = 0, message 'Zcash' (ASCII): all valid under ZIP-215 (cofactored equation, non-canonical A/R accepted). other[]: msg is hex; S must be canonical (< l).",
        "small_order_msg_text": "Zcash",
        "small_order": small,
        "other": other,
    })
}

// ------------------------------------------------------------------ route header + estimate

fn route() -> Value {
    let c: CatalogEntry = json::parse(SONNET.as_bytes()).unwrap();
    let base = route_text();
    let parse_cases: Vec<Value> = [
        ("valid", base.clone()),
        ("duplicate key", base.replacen('{', r#"{"model":"anthropic/claude-haiku-4.5","#, 1)),
        ("unknown field", base.replacen('{', r#"{"extra":1,"#, 1)),
        ("cache_ttl not in enum", base.replace("\"none\"", "\"2h\"")),
        ("dialect not in enum", base.replace("anthropic.messages", "anthropic.complete")),
        ("negative max_tokens", base.replace("1024", "-1")),
        ("affinity wrong length", base.replace(&b64(&[0xA5; 16]), &b64(&[0xA5; 15]))),
        ("affinity padded base64", base.replace(&b64(&[0xA5; 16]), &format!("{}==", b64(&[0xA5; 16])))),
        ("missing field", base.replace(r#""stream":true,"#, "")),
        ("repo id without prefix", base.replace("r_01K6A", "01K6A")),
    ]
    .iter()
    .map(|(n, s)| json!({"name": n, "text": s, "outcome": outcome(RouteHeader::parse(s.as_bytes()))}))
    .collect();

    let pdf = b"%PDF-1.7\n1 0 obj <</Type /Pages /Kids [2 0 R 3 0 R 4 0 R]>>\n2 0 obj <</Type/Page>>\n3 0 obj <</Type\n/Page /Parent 1 0 R>>\n4 0 obj <</Type /Page>>\n5 0 obj <</Type /PageLabel>>";
    use base64::Engine as _;
    let pdf_b64 = base64::engine::general_purpose::STANDARD.encode(pdf);
    let bodies: Vec<(&str, Dialect, String)> = vec![
        ("anthropic text + image + 1h cache", Dialect::AnthropicMessages, r#"{"model":"claude-sonnet-5-5","max_tokens":1024,"stream":true,"system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral","ttl":"1h"}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}]}"#.into()),
        ("anthropic effort + 5m cache default ttl", Dialect::AnthropicMessages, r#"{"model":"anthropic/claude-sonnet-5.5","max_tokens":2048,"output_config":{"effort":"low"},"messages":[{"role":"user","content":[{"type":"text","text":"hello world","cache_control":{"type":"ephemeral"}}]}]}"#.into()),
        ("anthropic pdf document + fast", Dialect::AnthropicMessages, format!(r#"{{"model":"claude-sonnet-5-5","max_tokens":1,"speed":"fast","messages":[{{"role":"user","content":[{{"type":"document","source":{{"type":"base64","media_type":"application/pdf","data":"{pdf_b64}"}}}}]}}]}}"#)),
        ("anthropic image inside tool_result", Dialect::AnthropicMessages, r#"{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}]}"#.into()),
        ("openai data-url and https images", Dialect::OpenAiChat, r#"{"model":"deepseek/deepseek-chat","max_completion_tokens":50,"reasoning_effort":"low","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}},{"type":"image_url","image_url":{"url":"https://x/y.png"}}]}]}"#.into()),
        ("openai max_tokens only, stream", Dialect::OpenAiChat, r#"{"model":"deepseek/deepseek-chat","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#.into()),
        ("openai both max fields equal", Dialect::OpenAiChat, r#"{"model":"m","max_completion_tokens":50,"max_tokens":50,"messages":[]}"#.into()),
        ("error: openai both max fields differ", Dialect::OpenAiChat, r#"{"model":"m","max_completion_tokens":50,"max_tokens":51,"messages":[]}"#.into()),
        ("error: max_tokens missing", Dialect::AnthropicMessages, r#"{"model":"m","messages":[]}"#.into()),
        ("error: max_tokens above u32", Dialect::AnthropicMessages, r#"{"model":"m","max_tokens":4294967296,"messages":[]}"#.into()),
        ("error: duplicate max_tokens", Dialect::AnthropicMessages, r#"{"model":"m","max_tokens":1,"max_tokens":9}"#.into()),
        ("error: unknown cache ttl", Dialect::AnthropicMessages, r#"{"model":"m","max_tokens":1,"x":{"cache_control":{"ttl":"2h"}}}"#.into()),
        ("error: stream not a bool", Dialect::AnthropicMessages, r#"{"model":"m","max_tokens":1,"stream":"yes"}"#.into()),
        ("error: pdf data not base64", Dialect::AnthropicMessages, r#"{"model":"m","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"***"}}]}]}"#.into()),
    ];
    let fact_cases: Vec<Value> = bodies
        .iter()
        .map(|(name, d, body)| match money::body_facts(*d, body.as_bytes()) {
            Ok(f) => json!({
                "name": name, "dialect": d.as_str(), "body_text": body, "outcome": "ok",
                "facts": {
                    "model": f.model, "effort": f.effort, "max_tokens": f.max_tokens, "stream": f.stream,
                    "cache_ttl": serde_json::to_value(f.cache_ttl).unwrap(), "fast": f.fast, "text_bytes": f.text_bytes,
                    "images": f.images, "pages": f.pages, "est_input_tokens": f.est_input_tokens(&c).unwrap(), "flags": f.flags(),
                },
            }),
            Err(e) => json!({"name": name, "dialect": d.as_str(), "body_text": body, "outcome": err(e)}),
        })
        .collect();

    // check_route: body 0 against its derived route, then one field changed at a time.
    let body0 = &bodies[0].2;
    let f = money::body_facts(Dialect::AnthropicMessages, body0.as_bytes()).unwrap();
    let good = f.route(&c, Dialect::AnthropicMessages, REPO.parse().unwrap(), [0; 16]).unwrap();
    let muts: Vec<(&str, Box<dyn Fn(&mut RouteHeader)>)> = vec![
        ("derived route", Box::new(|_| {})),
        ("model swapped", Box::new(|r| r.model = "anthropic/claude-haiku-4.5".into())),
        ("dialect swapped", Box::new(|r| r.dialect = Dialect::OpenAiChat)),
        ("effort lowered", Box::new(|r| r.effort = "low".into())),
        ("max_tokens lowered", Box::new(|r| r.max_tokens -= 1)),
        ("estimate lowered by 1", Box::new(|r| r.est_input_tokens -= 1)),
        ("cache_ttl lowered", Box::new(|r| r.cache_ttl = CacheTtl::M5)),
        ("stream flipped", Box::new(|r| r.stream = false)),
        ("required flag missing", Box::new(|r| r.flags.clear())),
        ("extra flag (only restricts)", Box::new(|r| r.flags.push("fast".into()))),
    ];
    let check_cases: Vec<Value> = muts
        .iter()
        .map(|(n, m)| {
            let mut r = good.clone();
            m(&mut r);
            json!({"name": n, "route_text": String::from_utf8(r.to_bytes().unwrap()).unwrap(), "mismatch": money::check_route(&r, &f, &c).err()})
        })
        .collect();
    json!({
        "_schema": "Route header (plan 03 §7.1). parse[]: exact route-header bytes (text) → outcome ok | json (parser-differential) | malformed (unknown field, wrong type/enum/length). facts[]: provider body (body_text, exact bytes) → deterministic facts: est_input_tokens = ceil(text_bytes / 3) + images × catalog.max_image_tokens + pages × catalog.max_page_tokens, text_bytes = body length − Σ length of inline image data (Anthropic image source.data; OpenAI image_url.url starting 'data:'), pages = count of '/Type <ws>* /Page' (not /Pages) in each base64 PDF (min 1), cache_ttl = longest cache_control ttl (present without ttl = 5m), effort = output_config.effort | reasoning_effort (null = catalog default), flags = sorted subset of documents/fast/images. check[]: Worker comparison of route_text against facts of facts[0] and the catalog entry; mismatch = first failing field in order model, dialect, effort, max_tokens, est_input_tokens, cache_ttl, stream, flags (null = accepted).",
        "catalog_entry": serde_json::from_str::<Value>(SONNET).unwrap(),
        "parse": parse_cases,
        "facts": fact_cases,
        "check_body": 0,
        "check": check_cases,
        "pdf_pages": {"pdf_text": String::from_utf8_lossy(pdf), "pages": money::count_pdf_pages(pdf)},
    })
}

// ------------------------------------------------------------------ money

fn money_vectors() -> Value {
    let sonnet: CatalogEntry = json::parse(SONNET.as_bytes()).unwrap();
    let ds: CatalogEntry = json::parse(DEEPSEEK.as_bytes()).unwrap();
    let u = |i, o, w5, w1, r, pc: Option<i64>| Usage { input: i, output: o, cache_write_5m: w5, cache_write_1h: w1, cache_read: r, estimated: false, provider_cost_uusd: pc };
    let cost_cases: Vec<Value> = [
        ("plan 05 worked example", 0, u(2000, 1800, 2000, 0, 36000, None), false),
        ("one input token rounds up", 0, u(1, 0, 0, 0, 0, None), false),
        ("one cache-read token: 0.2 µ$ → 1", 0, u(0, 0, 0, 0, 1, None), false),
        ("zero usage", 0, u(0, 0, 0, 0, 0, None), false),
        ("fast multiplier", 0, u(1000, 1000, 0, 0, 0, None), true),
        ("1h cache write", 0, u(0, 0, 0, 1_000_000, 0, None), false),
        ("overflow", 0, u(u64::MAX, u64::MAX, 0, 0, 0, None), false),
        ("provider cost on a non-OpenRouter entry is refused", 0, u(1, 1, 0, 0, 0, Some(5)), false),
        ("OpenRouter: reported cost is authoritative", 1, u(9, 9, 0, 0, 9, Some(777)), false),
        ("OpenRouter without reported cost is refused", 1, u(9, 9, 0, 0, 0, None), false),
        ("OpenRouter negative cost is refused", 1, u(0, 0, 0, 0, 0, Some(-1)), false),
    ]
    .iter()
    .map(|(n, e, usage, fast)| {
        let entry = if *e == 0 { &sonnet } else { &ds };
        let r = money::cost_uusd(entry, usage, *fast);
        json!({"name": n, "entry": e, "usage": usage, "fast": fast, "outcome": outcome(r), "cost_uusd": r.ok()})
    })
    .collect();
    let reserve_cases: Vec<Value> = [
        ("plan 05 worked example", 40_000u64, 32_000u32, CacheTtl::M5, false),
        ("1h ttl doubles input", 40_000, 32_000, CacheTtl::H1, false),
        ("no cache", 40_000, 32_000, CacheTtl::None, false),
        ("fast ×6", 40_000, 32_000, CacheTtl::None, true),
        ("2.5 µ$ rounds up to 3", 1, 0, CacheTtl::M5, false),
        ("zero", 0, 0, CacheTtl::M5, false),
        ("overflow", u64::MAX, u32::MAX, CacheTtl::H1, true),
    ]
    .iter()
    .map(|(n, est, mt, ttl, fast)| {
        let r = money::reserve_uusd(&sonnet, *est, *mt, *ttl, *fast);
        json!({"name": n, "entry": 0, "est_input_tokens": est, "max_tokens": mt, "cache_ttl": ttl, "fast": fast, "outcome": outcome(r), "reserve_uusd": r.ok()})
    })
    .collect();
    let decimals: Vec<Value> = [
        "0", "0.0", "0.1", "0.0001234", "0.000123", "1.5e-05", "1.5E-5", "1e-7", "1e-300", "2", "1.25e2", "1E+2",
        "0.0000010000000000000000000000000000000000001", "9223372036854.775807", "9223372036854.775808", "1e30", "-1", "-0", "01",
        "1.", ".5", "1e", "1e+", "NaN", "Infinity", "0x10", "", " 1", "1 ", "1_000",
    ]
    .iter()
    .map(|s| {
        let r = money::usd_decimal_to_uusd_ceil(s);
        json!({"text": s, "outcome": outcome(r), "uusd": r.ok()})
    })
    .collect();
    json!({
        "_schema": "Money (plan 05 §3, §5.1), all integer µ$, checked arithmetic. entries: [0] curated Anthropic entry, [1] OpenRouter-imported entry (prices µ$ per million tokens). cost[]: cost_uusd = ceil(Σ usage_i × price_i × (fast ? fast_multiplier : 1) / 1e6); OpenRouter entries use usage.provider_cost_uusd (required, ≥ 0); others MUST NOT carry it. reserve[]: ceil((est × in × m + max_tokens × out) × fast / 1e6) with m = 5/4 (5m), 2 (1h), 1 (none), computed exactly. decimal[]: OpenRouter usage.cost JSON number text → µ$ rounded up, no floating point; outcome ok | malformed | overflow.",
        "entries": [serde_json::from_str::<Value>(SONNET).unwrap(), serde_json::from_str::<Value>(DEEPSEEK).unwrap()],
        "cost": cost_cases,
        "reserve": reserve_cases,
        "decimal": decimals,
    })
}

// ------------------------------------------------------------------ usernames

fn usernames() -> Value {
    let existing = ["alice", "bob-smith", "x9"];
    let tombstones = ["old-name", "carol"];
    let inputs: [(&str, &str); 37] = [
        ("valid", "abc"),
        ("valid", "alice2"),
        ("valid", "a-b"),
        ("valid", "a1-b2-c3"),
        ("valid", "0xff"),
        ("valid", "abcdefghijklmnopqrstuvwxyz012345"),
        ("case variant", "Alice"),
        ("case variant", "ALICE"),
        ("case variant", "Bob-Smith"),
        ("case variant", "NewUser"),
        ("taken", "alice"),
        ("taken", "bob-smith"),
        ("tombstoned", "old-name"),
        ("tombstoned", "Carol"),
        ("reserved", "admin"),
        ("reserved", "Admin"),
        ("reserved", "api"),
        ("reserved", "moochy"),
        ("invalid (too short, also reserved)", "v1"),
        ("reserved", "anonymous"),
        ("invalid", "ab"),
        ("invalid", "x9"),
        ("invalid", "abcdefghijklmnopqrstuvwxyz0123456"),
        ("invalid", "-abc"),
        ("invalid", "abc-"),
        ("invalid", "a--b"),
        ("invalid", "a_b"),
        ("invalid", "a.b"),
        ("invalid", "a b"),
        ("invalid", " abc"),
        ("invalid", ""),
        ("confusable", "\u{430}lice"),
        ("confusable", "al\u{200B}ice"),
        ("confusable", "alice\u{202E}"),
        ("confusable", "\u{FF41}lice"),
        ("confusable", "ali\u{0441}e"),
        ("confusable", "\u{131}nfo"),
    ];
    let cases: Vec<Value> = inputs
        .iter()
        .map(|(kind, s)| {
            let v = username::verdict(s, |h| existing.contains(&h), |h| tombstones.contains(&h));
            json!({"kind": kind, "input": s, "input_hex": hex(s.as_bytes()), "canonical": username::canonical(s).ok(), "verdict": v.as_str()})
        })
        .collect();
    let display: Vec<Value> = ["plain", "a\u{1b}[2Jb", "rtl\u{202E}txt", "zero\u{200B}width", "tab\tnl\n", "café ✓"]
        .iter()
        .map(|s| json!({"input": s, "display": username::display_safe(s)}))
        .collect();
    json!({
        "_schema": "Usernames (CONTRACT §11). canonical(input): reject any non-ASCII byte (confusables, zero-width, bidi) → ASCII-lowercase → ^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$ with no '--' → not in reserved. verdict(input) = first of: invalid | reserved | taken (canonical ∈ existing) | tombstoned (canonical ∈ tombstones) | ok. cases[]: kind is descriptive only; check canonical (null when refused before lookup) and verdict. display[]: Rust display_safe escapes C0/C1 controls, bidi controls, zero-width and other invisible format characters as \\u{XXXX}.",
        "reserved": username::RESERVED,
        "existing": existing,
        "tombstones": tombstones,
        "cases": cases,
        "display": display,
    })
}

/// Exact file bytes: pretty JSON (sorted keys) + newline.
pub fn render(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap();
    s.push('\n');
    s
}
