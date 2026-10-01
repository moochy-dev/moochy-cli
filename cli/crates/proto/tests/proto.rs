//! Roundtrip + negative tests for every primitive of `moochy-proto`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use bytes::BytesMut;
use moochy_proto::crypto::{self, ContentKey, EncSecret, RequestOpener, ResponseOpener, ResponseSealer, SignKey, TaskContext};
use moochy_proto::frame::{HEADER_LEN, Header, MAX_CHUNK, MAX_FRAME};
use moochy_proto::money::{self, CatalogEntry};
use moochy_proto::msg::{self, CacheTtl, Dialect, InnerPayload, Msg, Receipt, ReceiptStatus, RouteHeader, Usage};
use moochy_proto::{B, Blob, DeviceId, Error, PledgeId, RepoId, TaskId, Ulid, b64, json, lp, unb64};
use std::collections::BTreeMap;

const T0: u64 = 1_790_000_000_000;

fn task() -> TaskId {
    "01K6A0000000000000000000T1".parse().unwrap()
}
fn dev(s: &str) -> DeviceId {
    s.parse().unwrap()
}
fn ck() -> ContentKey {
    ContentKey::from_bytes([0x11; 32])
}
fn open_all(ck: &ContentKey, t: &TaskId, frames: &[bytes::Bytes]) -> Result<Vec<u8>, Error> {
    let mut o = RequestOpener::new(ck, t)?;
    for f in frames {
        o.push(&mut f.to_vec())?;
    }
    o.finish()
}

#[test]
fn lp_and_encodings() {
    assert_eq!(lp(&[b"ab", b""]).unwrap(), [0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0]);
    assert_eq!(b64(&[0xfb, 0xff]), "-_8");
    assert_eq!(unb64("-_8").unwrap(), [0xfb, 0xff]);
    for bad in ["-_8=", "+/8", "-_9", "a", " AA", "AA\n"] {
        assert_eq!(unb64(bad), Err(Error::Malformed), "{bad}");
    }
    let t = task();
    assert_eq!(t.to_string(), "01K6A0000000000000000000T1");
    assert_eq!(TaskId(Ulid::parse(&t.to_string()).unwrap()), t);
    for bad in ["01k6a0000000000000000000t1", "01K6A0000000000000000000T", "81K6A0000000000000000000T1", "01K6A000000000000000000OT1", "d_01K6A0000000000000000000T1"] {
        assert!(bad.parse::<TaskId>().is_err(), "{bad}");
    }
    let d = DeviceId::new(T0).unwrap();
    assert!(d.text().starts_with("d_"));
    assert_eq!(d.text().parse::<DeviceId>().unwrap(), d);
    assert!(d.0.to_string().parse::<DeviceId>().is_err(), "prefix required");
    assert!("u_01K6A0000000000000000000T1".parse::<DeviceId>().is_err());
    let fresh = TaskId::new(T0).unwrap();
    assert_eq!(fresh.0.timestamp_ms(), T0);
    assert!(fresh.is_fresh(T0 + 600_000, 600_000));
    assert!(!fresh.is_fresh(T0 + 600_001, 600_000));
    assert!(!fresh.is_fresh(T0 - 600_001, 600_000));
}

#[test]
fn request_roundtrip_multi_chunk() {
    let t = task();
    // Incompressible payload → several chunks.
    let mut payload = vec![0u8; 3 * MAX_CHUNK + 17];
    crypto::fill_random(&mut payload).unwrap();
    let s = crypto::seal_request(&ck(), &t, &payload).unwrap();
    assert!(s.frames.len() >= 4);
    assert!(s.frames.iter().all(|f| f.len() <= MAX_FRAME));
    assert_eq!(s.body_len, s.frames.iter().map(|f| (f.len() - HEADER_LEN) as u64).sum::<u64>());
    assert_eq!(open_all(&ck(), &t, &s.frames).unwrap(), payload);
    let (h, _) = Header::decode(&s.frames[0]).unwrap();
    assert_eq!((h.attempt, h.seq, h.last), (0, 0, false));
    assert!(Header::decode(s.frames.last().unwrap()).unwrap().0.last);
}

#[test]
fn request_negatives() {
    let t = task();
    let mut payload = vec![0u8; 2 * MAX_CHUNK];
    crypto::fill_random(&mut payload).unwrap();
    let f = crypto::seal_request(&ck(), &t, &payload).unwrap().frames;
    let n = f.len();
    // Wrong CK, wrong task.
    assert_eq!(open_all(&ContentKey::from_bytes([0x12; 32]), &t, &f), Err(Error::Decrypt));
    let other: TaskId = "01K6A0000000000000000000T2".parse().unwrap();
    assert_eq!(open_all(&ck(), &other, &f), Err(Error::Sequence));
    // Truncation: last frame dropped.
    assert_eq!(open_all(&ck(), &t, &f[..n - 1]), Err(Error::Sequence));
    // Reorder / duplicate.
    let mut sw = f.clone();
    sw.swap(0, 1);
    assert_eq!(open_all(&ck(), &t, &sw), Err(Error::Sequence));
    let dup = [f[0].clone(), f[0].clone()];
    assert_eq!(open_all(&ck(), &t, &dup), Err(Error::Sequence));
    // Frame after last.
    let mut after = f.clone();
    after.push(f[0].clone());
    assert_eq!(open_all(&ck(), &t, &after), Err(Error::Sequence));
    // Flip: ciphertext bit, tag bit, last flag (AAD), header seq rewritten (nonce+AAD).
    for (idx, bit) in [(HEADER_LEN + 5, 1u8), (f[0].len() - 1, 0x80)] {
        let mut g = f.clone();
        let mut b = g[0].to_vec();
        b[idx] ^= bit;
        g[0] = b.into();
        assert_eq!(open_all(&ck(), &t, &g), Err(Error::Decrypt));
    }
    let mut g = f.clone();
    let mut b = g[n - 1].to_vec();
    b[22] = 0; // clear `last` on the final frame
    g[n - 1] = b.into();
    assert_eq!(open_all(&ck(), &t, &g), Err(Error::Decrypt));
    // Poisoned after first failure.
    let mut o = RequestOpener::new(&ck(), &t).unwrap();
    let mut bad = f[0].to_vec();
    bad[HEADER_LEN] ^= 1;
    assert_eq!(o.push(&mut bad), Err(Error::Decrypt));
    assert_eq!(o.push(&mut f[0].to_vec()), Err(Error::Sequence));
    // Oversize payload refused by the sealer.
    assert_eq!(crypto::seal_request(&ck(), &t, &vec![0; crypto::MAX_PAYLOAD + 1]).err(), Some(Error::TooLarge));
}

#[test]
fn zstd_bomb_and_trailing_data() {
    let t = task();
    // Exactly the cap: accepted.
    let ok = vec![b' '; crypto::MAX_PAYLOAD];
    let s = crypto::seal_request(&ck(), &t, &ok).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.frames).unwrap().len(), crypto::MAX_PAYLOAD);
    // One byte over (a tiny compressed bomb): rejected while streaming.
    let bomb = zstd::bulk::compress(&vec![b' '; crypto::MAX_PAYLOAD + 1], 19).unwrap();
    assert!(bomb.len() < 4096, "bomb is small: {}", bomb.len());
    let s = crypto::seal_compressed(&ck(), &t, &bomb).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.frames), Err(Error::TooLarge));
    // A 1 GiB bomb fails just the same, without allocating more than the cap.
    let mut z = zstd::bulk::Compressor::new(19).unwrap();
    let big = z.compress(&vec![0u8; 1 << 30]).unwrap();
    let s = crypto::seal_compressed(&ck(), &t, &big).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.frames), Err(Error::TooLarge));
    // Trailing bytes after the zstd frame, and two concatenated frames: rejected.
    let mut tr = zstd::bulk::compress(b"{}", 3).unwrap();
    tr.push(0);
    let s = crypto::seal_compressed(&ck(), &t, &tr).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.frames), Err(Error::Malformed));
    let one = zstd::bulk::compress(b"{}", 3).unwrap();
    let s = crypto::seal_compressed(&ck(), &t, &[one.clone(), one].concat()).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.frames), Err(Error::Malformed));
    // Garbage that is not zstd.
    let s = crypto::seal_compressed(&ck(), &t, b"not zstd at all").unwrap();
    assert_eq!(open_all(&ck(), &t, &s.frames), Err(Error::Malformed));
    // Incomplete zstd frame.
    let full = zstd::bulk::compress(&[7u8; 1000], 3).unwrap();
    let s = crypto::seal_compressed(&ck(), &t, &full[..full.len() - 2]).unwrap();
    assert!(open_all(&ck(), &t, &s.frames).is_err());
}

fn sealer(attempt: u8, r: [u8; 32]) -> ResponseSealer {
    ResponseSealer::new(&ck(), &r, &task(), &dev("d_01K6A0000000000000000000W1"), attempt).unwrap()
}
fn opener(attempt: u8, r: [u8; 32]) -> ResponseOpener {
    ResponseOpener::new(&ck(), &r, &task(), &dev("d_01K6A0000000000000000000W1"), attempt).unwrap()
}

#[test]
fn response_roundtrip_and_aad_binding() {
    let r = [0x22; 32];
    let mut s = sealer(1, r);
    let chunks: [&[u8]; 3] = [b"hello ", &[0xAB; MAX_CHUNK], b""];
    let frames: Vec<_> = chunks.iter().enumerate().map(|(i, c)| s.seal(c, i == 2).unwrap()).collect();
    assert_eq!(s.seal(b"x", true), Err(Error::Sequence), "nothing after last");
    assert_eq!(sealer(1, r).seal(&[0; MAX_CHUNK + 1], false), Err(Error::TooLarge));
    let mut o = opener(1, r);
    let mut all = Vec::new();
    for f in &frames {
        let (pt, _) = o.open(BytesMut::from(&f[..])).unwrap();
        all.extend_from_slice(&pt);
    }
    assert!(o.is_complete());
    assert_eq!(all, chunks.concat());
    assert_eq!(o.running_hash(), crypto::sha256(&all));
    assert_eq!(s.running_hash(), o.running_hash());

    // Two attempts of one task: different RK, cross-open fails.
    let rk1 = crypto::rk(&ck(), &r, &task(), &dev("d_01K6A0000000000000000000W1"), 1).unwrap();
    let rk2 = crypto::rk(&ck(), &r, &task(), &dev("d_01K6A0000000000000000000W1"), 2).unwrap();
    let rk1b = crypto::rk(&ck(), &[0x23; 32], &task(), &dev("d_01K6A0000000000000000000W1"), 1).unwrap();
    assert_ne!(rk1.expose(), rk2.expose());
    assert_ne!(rk1.expose(), rk1b.expose());

    // Each AAD component, with the header rewritten to match the opener: decryption fails.
    let f0 = frames[0].to_vec();
    let rewrite = |f: &[u8], at: usize, v: &[u8]| {
        let mut f = f.to_vec();
        f[at..at + v.len()].copy_from_slice(v);
        BytesMut::from(&f[..])
    };
    // attempt (key + AAD)
    assert_eq!(opener(2, r).open(rewrite(&f0, 17, &[2])).err(), Some(Error::Decrypt));
    // R (key + AAD)
    assert_eq!(opener(1, [0x23; 32]).open(rewrite(&f0, 0, &[2])).err(), Some(Error::Decrypt));
    // task
    let t2: TaskId = "01K6A0000000000000000000T2".parse().unwrap();
    let mut o2 = ResponseOpener::new(&ck(), &r, &t2, &dev("d_01K6A0000000000000000000W1"), 1).unwrap();
    assert_eq!(o2.open(rewrite(&f0, 1, &t2.0.0)).err(), Some(Error::Decrypt));
    // seq: frame 1 relabelled as seq 0
    assert_eq!(opener(1, r).open(rewrite(&frames[1], 18, &[0, 0, 0, 0])).err(), Some(Error::Decrypt));
    // last flag flipped
    assert_eq!(opener(1, r).open(rewrite(&f0, 22, &[1])).err(), Some(Error::Decrypt));
    // header mismatch without rewrite → Sequence; truncated stream is not complete
    assert_eq!(opener(2, r).open(BytesMut::from(&f0[..])).err(), Some(Error::Sequence));
    let mut tr = opener(1, r);
    tr.open(BytesMut::from(&f0[..])).unwrap();
    assert!(!tr.is_complete());
    // a request frame is never accepted as a response frame
    let req = crypto::seal_request(&ck(), &task(), b"{}").unwrap().frames;
    assert_eq!(opener(1, r).open(BytesMut::from(&req[0][..])).err(), Some(Error::Sequence));
}

#[test]
fn hpke_wrap() {
    let sk = EncSecret::from_bytes(&[0x33; 32]).unwrap();
    let pk = sk.public();
    assert_eq!(EncSecret::from_bytes(&sk.to_bytes()).unwrap().public(), pk);
    let route = br#"{"x":1}"#;
    let w = crypto::wrap(&pk, &task(), route, &ck()).unwrap();
    assert_eq!(crypto::unwrap(&sk, &task(), route, &w).unwrap().expose(), ck().expose());
    // Fresh ephemeral each time.
    assert_ne!(crypto::wrap(&pk, &task(), route, &ck()).unwrap(), w);
    assert_eq!(crypto::unwrap(&sk, &task(), br#"{"x":2}"#, &w).err(), Some(Error::Decrypt));
    let t2: TaskId = "01K6A0000000000000000000T2".parse().unwrap();
    assert_eq!(crypto::unwrap(&sk, &t2, route, &w).err(), Some(Error::Decrypt));
    let other = EncSecret::from_bytes(&[0x34; 32]).unwrap();
    assert_eq!(crypto::unwrap(&other, &task(), route, &w).err(), Some(Error::Decrypt));
    for i in [0, 40, 79] {
        let mut b = w;
        b[i] ^= 1;
        assert_eq!(crypto::unwrap(&sk, &task(), route, &b).err(), Some(Error::Decrypt), "byte {i}");
    }
    // Small-order recipient key is refused (all-zero DH).
    assert!(crypto::wrap(&[0; 32], &task(), route, &ck()).is_err());
}

fn route_bytes() -> Vec<u8> {
    br#"{"repo_id":"r_01K6A0000000000000000000R1","dialect":"anthropic.messages","model":"anthropic/claude-sonnet-5.5","effort":"high","max_tokens":1024,"est_input_tokens":10,"cache_ttl":"none","stream":true,"affinity":"AAAAAAAAAAAAAAAAAAAAAA","flags":[]}"#.to_vec()
}

#[test]
fn signatures_and_inner_payload() {
    let gw = SignKey::from_seed(&[0x44; 32]);
    let gw_pub = gw.public();
    let t = task();
    let repo: RepoId = "r_01K6A0000000000000000000R1".parse().unwrap();
    let route = route_bytes();
    let ctx = TaskContext { task: &t, repo: &repo, route: &route };
    let mut headers = BTreeMap::new();
    headers.insert("anthropic-version".to_owned(), "2023-06-01".to_owned());
    let p = InnerPayload::build(&ctx, b"{\"model\":\"m\"}".to_vec(), headers, [5; 32], dev("d_01K6A0000000000000000000G1"), &gw).unwrap();
    p.verify(&ctx, &gw_pub).unwrap();
    let bytes = p.to_bytes().unwrap();
    assert_eq!(InnerPayload::parse(&bytes).unwrap(), p);
    // Tamper: body, headers, route, repo, wrong key, extra field, v != 1.
    let mut q = p.clone();
    q.body_b64.0.push(b' ');
    assert_eq!(q.verify(&ctx, &gw_pub), Err(Error::Hash));
    let mut q = p.clone();
    q.headers.insert("anthropic-beta".to_owned(), "x".to_owned());
    assert_eq!(q.verify(&ctx, &gw_pub), Err(Error::BadSignature));
    let route2 = [route.clone(), b" ".to_vec()].concat();
    assert_eq!(p.verify(&TaskContext { route: &route2, ..ctx }, &gw_pub), Err(Error::BadSignature));
    let repo2: RepoId = "r_01K6A0000000000000000000R2".parse().unwrap();
    assert_eq!(p.verify(&TaskContext { repo: &repo2, ..ctx }, &gw_pub), Err(Error::BadSignature));
    assert_eq!(p.verify(&ctx, &SignKey::from_seed(&[0x45; 32]).public()), Err(Error::BadSignature));
    let mut extra = bytes.clone();
    extra.pop();
    extra.extend_from_slice(br#","x":1}"#);
    assert_eq!(InnerPayload::parse(&extra), Err(Error::Malformed));
    let v2 = String::from_utf8(bytes.clone()).unwrap().replacen("\"v\":1", "\"v\":2", 1);
    assert_eq!(InnerPayload::parse(v2.as_bytes()), Err(Error::Malformed));

    // Auth, checkpoint, dispute.
    let k = SignKey::from_seed(&[0x46; 32]);
    let m = crypto::auth_msg(&[1; 32], "wss://127.0.0.1:443", &[2; 32], &dev("d_01K6A0000000000000000000G1")).unwrap();
    let sig = k.sign(&m);
    crypto::verify(&k.public(), &m, &sig).unwrap();
    let m2 = crypto::auth_msg(&[1; 32], "wss://127.0.0.1:444", &[2; 32], &dev("d_01K6A0000000000000000000G1")).unwrap();
    assert_eq!(crypto::verify(&k.public(), &m2, &sig), Err(Error::BadSignature));
    let c = crypto::checkpoint_msg(&t, 1, &[3; 32], 7, &[4; 32]).unwrap();
    crypto::verify(&k.public(), &c, &k.sign(&c)).unwrap();
    assert_ne!(c, crypto::checkpoint_msg(&t, 2, &[3; 32], 7, &[4; 32]).unwrap());
    let d = crypto::dispute_msg(&t, 1, "resp_commit").unwrap();
    assert_eq!(crypto::verify(&k.public(), &d, &k.sign(&c)), Err(Error::BadSignature));
    // Non-canonical S (S + ℓ) is rejected even though it would verify under a lax verifier.
    let mut s = k.sign(&d);
    let l: [u8; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(s[32 + i]) + u16::from(l[i]) + carry;
        s[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(crypto::verify(&k.public(), &d, &s), Err(Error::BadSignature));
}

fn receipt() -> Receipt {
    Receipt {
        v: 1,
        task_id: task(),
        attempt: 1,
        repo_id: "r_01K6A0000000000000000000R1".parse().unwrap(),
        pledge_id: "p_01K6A0000000000000000000P1".parse::<PledgeId>().unwrap(),
        worker_device: dev("d_01K6A0000000000000000000W1"),
        gateway_device: dev("d_01K6A0000000000000000000G1"),
        dialect: Dialect::AnthropicMessages,
        provider: "anthropic".into(),
        model_reported: "claude-sonnet-5-5".into(),
        usage: Usage { input: 2000, output: 1800, cache_write_5m: 2000, cache_write_1h: 0, cache_read: 36000, estimated: false, provider_cost_uusd: None },
        catalog_version: 1,
        cost_uusd: 34_200,
        req_commit: B([1; 32]),
        resp_commit: B([2; 32]),
        provider_req_hash: B([3; 32]),
        status: ReceiptStatus::Ok,
        t_start: T0,
        t_started: T0 + 300,
        t_end: T0 + 5000,
    }
}

#[test]
fn receipts_and_projections() {
    let k = SignKey::from_seed(&[0x47; 32]);
    let (bytes, sig) = crypto::sign_receipt(&k, &receipt()).unwrap();
    assert_eq!(crypto::open_receipt(&k.public(), &bytes, &sig).unwrap(), receipt());
    let mut b2 = bytes.clone();
    b2[10] ^= 1;
    assert_eq!(crypto::open_receipt(&k.public(), &b2, &sig).err(), Some(Error::BadSignature));
    // Valid signature over bytes with a duplicate key: still rejected (parser-differential rule).
    let dup = String::from_utf8(bytes.clone()).unwrap().replacen("{", r#"{"cost_uusd":1,"#, 1);
    let dsig = k.sign(&crypto::receipt_msg(dup.as_bytes()).unwrap());
    assert_eq!(crypto::open_receipt(&k.public(), dup.as_bytes(), &dsig).err(), Some(Error::Json));
    // A receipt signature never verifies as a projection.
    assert_eq!(crypto::open_projection(&k.public(), &bytes, &sig).err(), Some(Error::BadSignature));
    let p = msg::Projection {
        v: 1,
        receipt_ref: B([9; 16]),
        repo_id: receipt().repo_id,
        donor: None,
        model: "anthropic/claude-sonnet-5.5".into(),
        cost_uusd: 34_200,
        day: "2026-10-01".into(),
        receipt_sha256: B(crypto::sha256(&bytes)),
    };
    let (pb, ps) = crypto::sign_projection(&k, &p).unwrap();
    assert_eq!(crypto::open_projection(&k.public(), &pb, &ps).unwrap(), p);
    // Commitments and salts.
    let s_req = crypto::salt(&[6; 32], crypto::SaltName::Req).unwrap();
    let s_resp = crypto::salt(&[6; 32], crypto::SaltName::Resp).unwrap();
    assert_ne!(s_req.expose(), s_resp.expose());
    assert_ne!(crypto::req_commit(&s_req, b"a").unwrap(), crypto::req_commit(&s_req, b"b").unwrap());
    assert_ne!(crypto::resp_commit(&s_resp, &[0; 32]).unwrap(), crypto::resp_commit(&s_req, &[0; 32]).unwrap());
    assert_eq!(crypto::headers_sha256(&BTreeMap::new()).unwrap(), crypto::sha256(b""));
}

#[test]
fn messages() {
    let t = task();
    let all = vec![
        Msg::Hello(msg::Hello { nonce: B([1; 32]), server_time: T0, min_client_version: "0.1.0".into(), relay_release: "r1".into(), log_checkpoint: None }),
        Msg::TaskSubmit(msg::TaskSubmit { task: t, route_b64: Blob(route_bytes()), wraps: vec![msg::Wrap { worker_device: dev("d_01K6A0000000000000000000W1"), wrap: B([7; 80]) }], body_len: 100, body_chunks: 1 }),
        Msg::TaskAck(msg::TaskAck { task: t, attempt: 1, r: B([2; 32]) }),
        Msg::TaskNack(msg::TaskNack { task: t, attempt: 1, r: B([2; 32]), code: msg::code::FIREWALL.into(), retryable: false, retry_after_ms: None, sealed_detail: Some(Blob(vec![1, 2])) }),
        Msg::TaskStarted(msg::TaskRef { task: t, attempt: 2 }),
        Msg::ReceiptAck(msg::TaskRef { task: t, attempt: 2 }),
        Msg::TaskCancel(msg::TaskCancel { task: t, attempt: None, reason: Some("client_closed".into()) }),
        Msg::WorkerOffer(msg::WorkerOffer { slots_free: 4, models: vec![msg::OfferModel { dialect: Dialect::OpenAiChat, model: "deepseek/deepseek-chat".into(), rl_headroom: 90 }], pledges: vec![], window_open: true, local_cap_left: 5_000_000 }),
        Msg::Error(msg::ErrorMsg { code: "unknown_type".into(), message: "x".into(), task: None }),
    ];
    for m in all {
        let b = m.to_bytes().unwrap();
        assert!(b.starts_with(format!("{{\"t\":\"{}\"", m.t()).as_bytes()), "{}", String::from_utf8_lossy(&b));
        assert_eq!(Msg::parse(&b).unwrap(), m);
    }
    let ack = br#"{"t":"task.ack","task":"01K6A0000000000000000000T1","attempt":1,"R":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","future":{"x":[1]}}"#;
    assert!(matches!(Msg::parse(ack), Ok(Msg::TaskAck(_))), "unknown fields ignored");
    assert_eq!(Msg::parse(br#"{"t":"task.teleport","task":"x"}"#), Err(Error::UnknownType));
    assert_eq!(Msg::parse(br#"{"t":"task.ack","t":"task.ack"}"#), Err(Error::Json));
    assert_eq!(Msg::parse(br#"{"task":"01K6A0000000000000000000T1"}"#), Err(Error::Malformed));
    assert_eq!(Msg::parse(br#"{"t":"task.ack","task":"01K6A0000000000000000000T1","attempt":256,"R":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}"#), Err(Error::Malformed));
    assert_eq!(Msg::parse(br#"{"t":"task.ack","task":"01K6A0000000000000000000T1","attempt":1,"R":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"}"#), Err(Error::Malformed), "31-byte R");
    assert!(msg::code::retryable("busy") && !msg::code::retryable("firewall") && !msg::code::retryable("whatever"));

    // Route header: exact fields, unknown and duplicate keys refused.
    let r = RouteHeader::parse(&route_bytes()).unwrap();
    assert_eq!(r.cache_ttl, CacheTtl::None);
    assert_eq!(RouteHeader::parse(&r.to_bytes().unwrap()).unwrap(), r);
    let s = String::from_utf8(route_bytes()).unwrap();
    assert_eq!(RouteHeader::parse(s.replacen("{", r#"{"model":"anthropic/claude-haiku-4.5","#, 1).as_bytes()), Err(Error::Json));
    assert_eq!(RouteHeader::parse(s.replacen("{", r#"{"extra":1,"#, 1).as_bytes()), Err(Error::Malformed));
    assert_eq!(RouteHeader::parse(s.replace("\"none\"", "\"2h\"").as_bytes()), Err(Error::Malformed));
}

fn sonnet() -> CatalogEntry {
    json::parse(br#"{"model":"anthropic/claude-sonnet-5.5","provider":"anthropic","provider_model_id":"claude-sonnet-5-5","aliases":["claude-sonnet-5-5"],"dialects":["anthropic.messages"],"in":2000000,"out":10000000,"cache_write_5m":2500000,"cache_write_1h":4000000,"cache_read":200000,"max_image_tokens":1600,"max_page_tokens":3000,"fast_multiplier":6,"default_effort":"high","max_output":64000,"source":"curated"}"#).unwrap()
}

#[test]
fn money_math() {
    let c = sonnet();
    // plan 05 §5.1 worked example.
    assert_eq!(money::reserve_uusd(&c, 40_000, 32_000, CacheTtl::M5, false).unwrap(), 420_000);
    assert_eq!(money::reserve_uusd(&c, 40_000, 32_000, CacheTtl::H1, false).unwrap(), 480_000);
    assert_eq!(money::reserve_uusd(&c, 40_000, 32_000, CacheTtl::None, true).unwrap(), 6 * 400_000);
    assert_eq!(money::reserve_uusd(&c, 1, 0, CacheTtl::M5, false).unwrap(), 3, "2.5 µ$ rounds up");
    assert_eq!(money::cost_uusd(&c, &receipt().usage, false).unwrap(), 34_200);
    let tiny = Usage { input: 1, ..Usage::default() };
    assert_eq!(money::cost_uusd(&c, &tiny, false).unwrap(), 2);
    assert_eq!(money::cost_uusd(&c, &Usage { cache_read: 1, ..Usage::default() }, false).unwrap(), 1, "0.2 µ$ → 1");
    assert_eq!(money::cost_uusd(&c, &Usage::default(), false).unwrap(), 0);
    let huge = Usage { input: u64::MAX, output: u64::MAX, ..Usage::default() };
    assert_eq!(money::cost_uusd(&c, &huge, false), Err(Error::Overflow));
    assert_eq!(money::reserve_uusd(&c, u64::MAX, u32::MAX, CacheTtl::H1, true), Err(Error::Overflow));
    // Provider cost only for OpenRouter, and required there.
    assert_eq!(money::cost_uusd(&c, &Usage { provider_cost_uusd: Some(1), ..Usage::default() }, false), Err(Error::Malformed));
    let or = CatalogEntry { provider: "openrouter".into(), ..c.clone() };
    assert_eq!(money::cost_uusd(&or, &Usage { provider_cost_uusd: Some(777), input: 9, ..Usage::default() }, false).unwrap(), 777);
    assert_eq!(money::cost_uusd(&or, &Usage::default(), false), Err(Error::Malformed));
    assert_eq!(money::cost_uusd(&or, &Usage { provider_cost_uusd: Some(-1), ..Usage::default() }, false), Err(Error::Malformed));
    for (s, want) in [
        ("0", Ok(0)),
        ("0.0", Ok(0)),
        ("0.1", Ok(100_000)),
        ("0.0001234", Ok(124)),
        ("0.000123", Ok(123)),
        ("1.5e-05", Ok(15)),
        ("1.5E-5", Ok(15)),
        ("1e-7", Ok(1)),
        ("1e-300", Ok(1)),
        ("2", Ok(2_000_000)),
        ("1.25e2", Ok(125_000_000)),
        ("0.0000010000000000000000000000000000000000001", Ok(2)),
        ("9223372036854.775807", Ok(i64::MAX)),
        ("9223372036854.775808", Err(Error::Overflow)),
        ("1e30", Err(Error::Overflow)),
        ("-1", Err(Error::Malformed)),
        ("01", Err(Error::Malformed)),
        ("1.", Err(Error::Malformed)),
        (".5", Err(Error::Malformed)),
        ("1e", Err(Error::Malformed)),
        ("NaN", Err(Error::Malformed)),
        ("0x10", Err(Error::Malformed)),
        ("", Err(Error::Malformed)),
        (" 1", Err(Error::Malformed)),
    ] {
        assert_eq!(money::usd_decimal_to_uusd_ceil(s), want, "{s}");
    }
}

#[test]
fn body_facts_and_route_check() {
    let c = sonnet();
    let body = br#"{"model":"claude-sonnet-5-5","max_tokens":1024,"stream":true,"system":[{"type":"text","text":"sys","cache_control":{"type":"ephemeral","ttl":"1h"}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}]}"#;
    let f = money::body_facts(Dialect::AnthropicMessages, body).unwrap();
    assert_eq!((f.max_tokens, f.stream, f.cache_ttl, f.images, f.pages, f.fast), (1024, true, CacheTtl::H1, 1, 0, false));
    assert_eq!(f.text_bytes, body.len() as u64 - 12);
    assert_eq!(f.est_input_tokens(&c).unwrap(), (body.len() as u64 - 12).div_ceil(3) + 1600);
    assert_eq!(f.flags(), ["images"]);
    let repo: RepoId = "r_01K6A0000000000000000000R1".parse().unwrap();
    let route = f.route(&c, Dialect::AnthropicMessages, repo, [0; 16]).unwrap();
    assert_eq!(route.effort, "high");
    assert_eq!(money::check_route(&route, &f, &c), Ok(()));
    let bad = |m: &dyn Fn(&mut RouteHeader)| {
        let mut r = route.clone();
        m(&mut r);
        money::check_route(&r, &f, &c)
    };
    assert_eq!(bad(&|r| r.model = "anthropic/claude-haiku-4.5".into()), Err("model"));
    assert_eq!(bad(&|r| r.dialect = Dialect::OpenAiChat), Err("dialect"));
    assert_eq!(bad(&|r| r.effort = "low".into()), Err("effort"));
    assert_eq!(bad(&|r| r.max_tokens = 1023), Err("max_tokens"));
    assert_eq!(bad(&|r| r.est_input_tokens -= 1), Err("est_input_tokens"));
    assert_eq!(bad(&|r| r.cache_ttl = CacheTtl::M5), Err("cache_ttl"));
    assert_eq!(bad(&|r| r.stream = false), Err("stream"));
    assert_eq!(bad(&|r| r.flags.clear()), Err("flags"));
    assert_eq!(bad(&|r| r.flags.push("fast".into())), Ok(()), "extra flags only restrict");

    // OpenAI dialect: both max fields must agree; data URL images excluded; effort explicit.
    let ob = br#"{"model":"deepseek/deepseek-chat","max_completion_tokens":50,"reasoning_effort":"low","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}},{"type":"image_url","image_url":{"url":"https://x/y.png"}}]}]}"#;
    let f = money::body_facts(Dialect::OpenAiChat, ob).unwrap();
    assert_eq!((f.max_tokens, f.effort.as_deref(), f.images, f.stream, f.cache_ttl), (50, Some("low"), 2, false, CacheTtl::None));
    assert_eq!(f.text_bytes, ob.len() as u64 - "data:image/png;base64,AAAA".len() as u64);
    let both = br#"{"model":"m","max_completion_tokens":50,"max_tokens":51,"messages":[]}"#;
    assert_eq!(money::body_facts(Dialect::OpenAiChat, both), Err(Error::Malformed));
    assert_eq!(money::body_facts(Dialect::AnthropicMessages, br#"{"model":"m","messages":[]}"#), Err(Error::Malformed), "max_tokens required");
    assert_eq!(money::body_facts(Dialect::AnthropicMessages, br#"{"model":"m","max_tokens":1,"max_tokens":9}"#), Err(Error::Json));
    assert_eq!(money::body_facts(Dialect::AnthropicMessages, br#"{"model":"m","max_tokens":1,"x":{"cache_control":{"ttl":"2h"}}}"#), Err(Error::Malformed));

    // PDF pages: /Type /Page objects counted, /Pages not.
    let pdf = b"%PDF-1.7\n1 0 obj <</Type /Pages /Kids [2 0 R 3 0 R 4 0 R]>>\n2 0 obj <</Type/Page>>\n3 0 obj <</Type\n/Page /Parent 1 0 R>>\n4 0 obj <</Type /Page>>\n5 0 obj <</Type /PageLabel>>";
    assert_eq!(money::count_pdf_pages(pdf), 3);
    use base64::Engine as _;
    let data = base64::engine::general_purpose::STANDARD.encode(pdf);
    let db = format!(r#"{{"model":"m","max_tokens":1,"speed":"fast","messages":[{{"role":"user","content":[{{"type":"document","source":{{"type":"base64","media_type":"application/pdf","data":"{data}"}}}}]}}]}}"#);
    let f = money::body_facts(Dialect::AnthropicMessages, db.as_bytes()).unwrap();
    assert_eq!((f.pages, f.fast, f.text_bytes), (3, true, db.len() as u64));
    assert_eq!(f.flags(), ["documents", "fast"]);
    assert_eq!(f.est_input_tokens(&c).unwrap(), (db.len() as u64).div_ceil(3) + 9000);
}

/// `cargo test --release -p moochy-proto --test proto -- --ignored --nocapture throughput`
#[test]
#[ignore = "benchmark: run in release"]
fn throughput() {
    use std::time::Instant;
    let total: usize = 512 << 20;
    let n = total / MAX_CHUNK;
    let pt = vec![0x5Au8; MAX_CHUNK];
    let r = [0x22; 32];
    let mut s = sealer(1, r);
    let mut frames = Vec::with_capacity(n);
    let t0 = Instant::now();
    for i in 0..n {
        frames.push(s.seal(&pt, i + 1 == n).unwrap());
    }
    let seal = t0.elapsed();
    let mut bufs: Vec<BytesMut> = frames.iter().map(|f| BytesMut::from(&f[..])).collect();
    let mut o = opener(1, r);
    let t1 = Instant::now();
    for b in &mut bufs {
        o.open_in_place(b).unwrap();
    }
    let open = t1.elapsed();
    let mbps = |d: std::time::Duration| (n * MAX_CHUNK) as f64 / d.as_secs_f64() / 1e6;
    println!("64 KiB chunks, {} MB: seal {:.0} MB/s, open {:.0} MB/s (incl. running SHA-256)", n * MAX_CHUNK / 1_000_000, mbps(seal), mbps(open));
    if !cfg!(debug_assertions) {
        assert!(mbps(seal) >= 800.0 && mbps(open) >= 800.0, "below the 800 MB/s target");
    }
}
