//! Roundtrip + negative tests for every primitive of `moochy-proto`.
#![allow(clippy::pedantic, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use bytes::{Bytes, BytesMut};
use prost::Message as _;
use moochy_proto::crypto::{self, ContentKey, EncSecret, MAX_CHUNK, RequestOpener, ResponseOpener, ResponseSealer, SignKey, TAG_LEN, TaskContext};
use moochy_proto::pb;
use moochy_proto::money::{self, CatalogEntry};
use moochy_proto::msg::{self, CacheTtl, Dialect, InnerPayload, Receipt, ReceiptStatus, RouteHeader, Usage};
use moochy_proto::{B, DeviceId, Error, PledgeId, RepoId, TaskId, Ulid, b64, json, lp, unb64};
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
fn open_all(ck: &ContentKey, t: &TaskId, chunks: &[pb::Chunk]) -> Result<Vec<u8>, Error> {
    let mut o = RequestOpener::new(ck, t)?;
    for c in chunks {
        o.push(c)?;
    }
    o.finish()
}
fn flip(c: &pb::Chunk, idx: usize, bit: u8) -> pb::Chunk {
    let mut v = c.ct.to_vec();
    v[idx] ^= bit;
    pb::Chunk { ct: Bytes::from(v), ..c.clone() }
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
    assert!(fresh.admissible(T0 + 1, T0) && !fresh.admissible(T0 + 1, T0 + 1), "D18 boot floor");
    assert!(!fresh.admissible(T0 + 600_001, 0));
}

#[test]
fn request_roundtrip_multi_chunk() {
    let t = task();
    // Incompressible payload → several chunks.
    let mut payload = vec![0u8; 3 * MAX_CHUNK + 17];
    crypto::fill_random(&mut payload).unwrap();
    let s = crypto::seal_request(&ck(), &t, &payload).unwrap();
    assert!(s.chunks.len() >= 4);
    assert!(s.chunks.iter().all(|c| c.ct.len() <= MAX_CHUNK + TAG_LEN && c.attempt == 0));
    assert_eq!(s.body_len, s.chunks.iter().map(|c| c.ct.len() as u64).sum::<u64>());
    assert!(s.chunks.iter().enumerate().all(|(i, c)| c.seq == i as u32 && c.last == (i + 1 == s.chunks.len())));
    let mut o = RequestOpener::new(&ck(), &t).unwrap();
    s.chunks.iter().for_each(|c| o.push(c).unwrap());
    assert_eq!(o.chunks() as usize, s.chunks.len());
    assert_eq!(o.finish().unwrap(), payload);
    // Small JSON bodies compress into one chunk.
    let one = crypto::seal_request(&ck(), &t, &[b'{'; 100_000]).unwrap();
    assert_eq!(one.chunks.len(), 1);
}

/// Production split (CONTRACT §15.2): parent decrypts only, validator child inflates + parses.
#[test]
fn decrypt_only_then_inflate() {
    let t = task();
    let mut payload = vec![0u8; 3 * MAX_CHUNK];
    crypto::fill_random(&mut payload).unwrap();
    let s = crypto::seal_request(&ck(), &t, &payload).unwrap();
    let mut d = crypto::RequestDecryptor::new(&ck(), &t).unwrap();
    s.chunks.iter().for_each(|c| d.push(c).unwrap());
    assert_eq!(d.chunks() as usize, s.chunks.len());
    let z = d.finish().unwrap();
    assert_eq!(z.len() as u64, s.body_len - (s.chunks.len() * TAG_LEN) as u64, "exactly the compressed bytes");
    assert_eq!(moochy_proto::inflate::inflate_all(&z, crypto::MAX_PAYLOAD).unwrap(), payload);
    // Same refusals as the all-in-one opener: order, attempt, truncation, tamper (buffer untouched).
    let mut d = crypto::RequestDecryptor::new(&ck(), &t).unwrap();
    assert_eq!(d.push(&s.chunks[1]), Err(Error::Sequence));
    let mut d = crypto::RequestDecryptor::new(&ck(), &t).unwrap();
    d.push(&s.chunks[0]).unwrap();
    assert_eq!(d.finish(), Err(Error::Sequence), "last chunk missing");
    let mut d = crypto::RequestDecryptor::new(&ck(), &t).unwrap();
    let mut out = b"keep".to_vec();
    assert_eq!(d.push_into(&flip(&s.chunks[0], 3, 1), &mut out), Err(Error::Decrypt));
    assert_eq!(out, b"keep");
    assert_eq!(d.push_into(&s.chunks[0], &mut out), Err(Error::Sequence), "poisoned");
    let mut d = crypto::RequestDecryptor::new(&ck(), &t).unwrap();
    assert_eq!(d.push(&pb::Chunk { attempt: 2, ..s.chunks[0].clone() }), Err(Error::Sequence));
    // The child refuses a bomb exactly like the streaming path.
    let bomb = zstd::bulk::compress(&vec![b' '; crypto::MAX_PAYLOAD + 1], 3).unwrap();
    assert_eq!(moochy_proto::inflate::inflate_all(&bomb, crypto::MAX_PAYLOAD), Err(Error::TooLarge));
}

#[test]
fn request_negatives() {
    let t = task();
    let mut payload = vec![0u8; 2 * MAX_CHUNK];
    crypto::fill_random(&mut payload).unwrap();
    let f = crypto::seal_request(&ck(), &t, &payload).unwrap().chunks;
    let n = f.len();
    // Wrong CK, wrong task (task id is in K_req and the AAD).
    assert_eq!(open_all(&ContentKey::from_bytes([0x12; 32]), &t, &f), Err(Error::Decrypt));
    let other: TaskId = "01K6A0000000000000000000T2".parse().unwrap();
    assert_eq!(open_all(&ck(), &other, &f), Err(Error::Decrypt));
    // Truncation: last chunk dropped.
    assert_eq!(open_all(&ck(), &t, &f[..n - 1]), Err(Error::Sequence));
    // Reorder / duplicate / chunk after last / nonzero attempt.
    let mut sw = f.clone();
    sw.swap(0, 1);
    assert_eq!(open_all(&ck(), &t, &sw), Err(Error::Sequence));
    assert_eq!(open_all(&ck(), &t, &[f[0].clone(), f[0].clone()]), Err(Error::Sequence));
    let mut after = f.clone();
    after.push(f[0].clone());
    assert_eq!(open_all(&ck(), &t, &after), Err(Error::Sequence));
    let mut att = f.clone();
    att[0].attempt = 1;
    assert_eq!(open_all(&ck(), &t, &att), Err(Error::Sequence));
    // Flip a ciphertext bit, a tag bit; relabel seq (nonce+AAD); clear `last` (AAD).
    let mut g = f.clone();
    g[0] = flip(&f[0], 5, 1);
    assert_eq!(open_all(&ck(), &t, &g), Err(Error::Decrypt));
    g[0] = flip(&f[0], f[0].ct.len() - 1, 0x80);
    assert_eq!(open_all(&ck(), &t, &g), Err(Error::Decrypt));
    let relabel = [pb::Chunk { seq: 0, ..f[1].clone() }];
    assert_eq!(open_all(&ck(), &t, &relabel), Err(Error::Decrypt));
    let mut g = f.clone();
    g[n - 1].last = false;
    assert_eq!(open_all(&ck(), &t, &g), Err(Error::Decrypt));
    // Short / oversize ct.
    assert_eq!(open_all(&ck(), &t, &[pb::Chunk { ct: Bytes::from_static(&[0; 15]), ..f[0].clone() }]), Err(Error::TooLarge));
    assert_eq!(open_all(&ck(), &t, &[pb::Chunk { ct: Bytes::from(vec![0; MAX_CHUNK + TAG_LEN + 1]), ..f[0].clone() }]), Err(Error::TooLarge));
    // Poisoned after the first failure.
    let mut o = RequestOpener::new(&ck(), &t).unwrap();
    assert_eq!(o.push(&flip(&f[0], 0, 1)), Err(Error::Decrypt));
    assert_eq!(o.push(&f[0]), Err(Error::Sequence));
    // Oversize payload refused by the sealer.
    assert_eq!(crypto::seal_request(&ck(), &t, &vec![0; crypto::MAX_PAYLOAD + 1]).err(), Some(Error::TooLarge));
}

#[test]
fn zstd_bomb_and_trailing_data() {
    let t = task();
    // Exactly the cap: accepted.
    let ok = vec![b' '; crypto::MAX_PAYLOAD];
    let s = crypto::seal_request(&ck(), &t, &ok).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.chunks).unwrap().len(), crypto::MAX_PAYLOAD);
    // One byte over (a tiny compressed bomb): rejected while streaming.
    let bomb = zstd::bulk::compress(&vec![b' '; crypto::MAX_PAYLOAD + 1], 3).unwrap();
    assert!(bomb.len() < 8192, "bomb is small: {}", bomb.len());
    let s = crypto::seal_compressed(&ck(), &t, &bomb).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.chunks), Err(Error::TooLarge));
    // A 256 MiB bomb fails just the same, without allocating more than the cap.
    let big = zstd::bulk::compress(&vec![0u8; 1 << 28], 3).unwrap();
    let s = crypto::seal_compressed(&ck(), &t, &big).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.chunks), Err(Error::TooLarge));
    // Trailing bytes after the zstd frame, and two concatenated frames: rejected.
    let mut tr = zstd::bulk::compress(b"{}", 3).unwrap();
    tr.push(0);
    let s = crypto::seal_compressed(&ck(), &t, &tr).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.chunks), Err(Error::Malformed));
    let one = zstd::bulk::compress(b"{}", 3).unwrap();
    let s = crypto::seal_compressed(&ck(), &t, &[one.clone(), one].concat()).unwrap();
    assert_eq!(open_all(&ck(), &t, &s.chunks), Err(Error::Malformed));
    // Not zstd; incomplete zstd frame; empty body.
    let s = crypto::seal_compressed(&ck(), &t, b"not zstd at all").unwrap();
    assert_eq!(open_all(&ck(), &t, &s.chunks), Err(Error::Malformed));
    let full = zstd::bulk::compress(&[7u8; 1000], 3).unwrap();
    let s = crypto::seal_compressed(&ck(), &t, &full[..full.len() - 2]).unwrap();
    assert!(open_all(&ck(), &t, &s.chunks).is_err());
    let s = crypto::seal_compressed(&ck(), &t, b"").unwrap();
    assert_eq!(s.chunks.len(), 1);
    assert_eq!(open_all(&ck(), &t, &s.chunks), Err(Error::Malformed));
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
    let parts: [&[u8]; 3] = [b"hello ", &[0xAB; MAX_CHUNK], b""];
    let chunks: Vec<_> = parts.iter().enumerate().map(|(i, c)| s.seal(c, i == 2).unwrap()).collect();
    assert!(chunks.iter().all(|c| c.attempt == 1));
    assert_eq!(s.seal(b"x", true).err(), Some(Error::Sequence), "nothing after last");
    assert_eq!(sealer(1, r).seal(&[0; MAX_CHUNK + 1], false).err(), Some(Error::TooLarge));
    // open (zero-copy path) and open_into (caller buffer) agree.
    let mut o = opener(1, r);
    let mut all = Vec::new();
    for c in &chunks {
        all.extend_from_slice(&o.open(c.clone()).unwrap());
    }
    assert!(o.is_complete());
    assert_eq!(all, parts.concat());
    let mut o2 = opener(1, r);
    let mut out = BytesMut::new();
    chunks.iter().for_each(|c| o2.open_into(c, &mut out).unwrap());
    assert_eq!(&out[..], &all[..]);
    assert_eq!(o.running_hash(), crypto::sha256(&all));
    assert_eq!(s.running_hash(), o.running_hash());

    // Two attempts of one task: different RK; cross-open fails.
    let w = dev("d_01K6A0000000000000000000W1");
    let rk1 = crypto::rk(&ck(), &r, &task(), &w, 1).unwrap();
    let rk2 = crypto::rk(&ck(), &r, &task(), &w, 2).unwrap();
    let rk1b = crypto::rk(&ck(), &[0x23; 32], &task(), &w, 1).unwrap();
    assert_ne!(rk1.expose(), rk2.expose());
    assert_ne!(rk1.expose(), rk1b.expose());

    // Each AAD component, with the visible fields relabelled to match the opener: Decrypt.
    let c0 = chunks[0].clone();
    assert_eq!(opener(2, r).open(pb::Chunk { attempt: 2, ..c0.clone() }).err(), Some(Error::Decrypt));
    assert_eq!(opener(1, [0x23; 32]).open(c0.clone()).err(), Some(Error::Decrypt));
    let t2: TaskId = "01K6A0000000000000000000T2".parse().unwrap();
    let mut o3 = ResponseOpener::new(&ck(), &r, &t2, &w, 1).unwrap();
    assert_eq!(o3.open(c0.clone()).err(), Some(Error::Decrypt));
    let w2 = dev("d_01K6A0000000000000000000W2");
    assert_eq!(ResponseOpener::new(&ck(), &r, &task(), &w2, 1).unwrap().open(c0.clone()).err(), Some(Error::Decrypt));
    assert_eq!(opener(1, r).open(pb::Chunk { seq: 0, ..chunks[1].clone() }).err(), Some(Error::Decrypt));
    assert_eq!(opener(1, r).open(pb::Chunk { last: true, ..c0.clone() }).err(), Some(Error::Decrypt));
    // Visible mismatch → Sequence; poisoned; truncated stream not complete.
    let mut o4 = opener(2, r);
    assert_eq!(o4.open(c0.clone()).err(), Some(Error::Sequence));
    assert_eq!(o4.open(pb::Chunk { attempt: 2, ..c0.clone() }).err(), Some(Error::Sequence), "poisoned");
    let mut tr = opener(1, r);
    tr.open(c0.clone()).unwrap();
    assert!(!tr.is_complete());
    let mut o5 = opener(1, r);
    let mut buf = BytesMut::from(&b"keep"[..]);
    assert_eq!(o5.open_into(&flip(&c0, 0, 1), &mut buf).err(), Some(Error::Decrypt));
    assert_eq!(&buf[..], b"keep", "failed open_into leaves the buffer untouched");
    // A request chunk is never a response chunk (different key and AAD).
    let req = crypto::seal_request(&ck(), &task(), b"{}").unwrap().chunks;
    assert_eq!(opener(1, r).open(pb::Chunk { attempt: 1, ..req[0].clone() }).err(), Some(Error::Decrypt));
}

#[test]
fn sealed_detail() {
    let (r, w) = ([0x22; 32], dev("d_01K6A0000000000000000000W1"));
    let sd = crypto::seal_detail(&ck(), &r, &task(), &w, 1, "firewall", "field `mcp_servers` is not allowed").unwrap();
    assert_eq!(sd.len(), "field `mcp_servers` is not allowed".len() + TAG_LEN);
    assert_eq!(crypto::open_detail(&ck(), &r, &task(), &w, 1, "firewall", &sd).unwrap(), "field `mcp_servers` is not allowed");
    // Code, attempt, R, worker, task are all bound.
    assert_eq!(crypto::open_detail(&ck(), &r, &task(), &w, 1, "busy", &sd).err(), Some(Error::Decrypt));
    assert_eq!(crypto::open_detail(&ck(), &r, &task(), &w, 2, "firewall", &sd).err(), Some(Error::Decrypt));
    assert_eq!(crypto::open_detail(&ck(), &[0x23; 32], &task(), &w, 1, "firewall", &sd).err(), Some(Error::Decrypt));
    assert_eq!(crypto::open_detail(&ck(), &r, &task(), &dev("d_01K6A0000000000000000000W2"), 1, "firewall", &sd).err(), Some(Error::Decrypt));
    assert_eq!(crypto::open_detail(&ck(), &r, &task(), &w, 1, "firewall", &sd[..10]).err(), Some(Error::TooLarge));
    assert_eq!(crypto::seal_detail(&ck(), &r, &task(), &w, 1, "firewall", &"x".repeat(1025)).err(), Some(Error::TooLarge));
    assert!(crypto::seal_detail(&ck(), &r, &task(), &w, 1, "firewall", &"x".repeat(1024)).is_ok());
    assert_eq!(moochy_proto::b64(&crypto::sha256(b"abc")), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", "SHA-256 KAT");
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
    // to_bytes writes the body's base64 by hand: byte-identical to serde_json, for every body
    // length mod 3 and for header values that need JSON escapes.
    assert_eq!(bytes, serde_json::to_vec(&p).unwrap());
    for n in [0usize, 1, 2, 3, 4, 5, 1000, 100_001] {
        let mut h = BTreeMap::new();
        h.insert("x-q".to_owned(), "a \"quoted\" \\ value é".to_owned());
        let body: Vec<u8> = (0..n).map(|i| (i * 31 % 251) as u8).collect();
        let q = InnerPayload::build(&ctx, body, h, [6; 32], dev("d_01K6A0000000000000000000G1"), &gw).unwrap();
        assert_eq!(q.to_bytes().unwrap(), serde_json::to_vec(&q).unwrap(), "body of {n} bytes");
    }
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
    let upper = String::from_utf8(bytes.clone()).unwrap().replacen("anthropic-version", "Anthropic-Version", 1);
    assert_eq!(InnerPayload::parse(upper.as_bytes()), Err(Error::Malformed), "header names are lowercase");
    let crlf = String::from_utf8(bytes.clone()).unwrap().replacen("2023-06-01", "2023-06-01\\r\\nx: y", 1);
    assert_eq!(InnerPayload::parse(crlf.as_bytes()), Err(Error::Malformed), "no CR/LF in header values");
    let v2 = String::from_utf8(bytes.clone()).unwrap().replacen("\"v\":1", "\"v\":2", 1);
    assert_eq!(InnerPayload::parse(v2.as_bytes()), Err(Error::Malformed));

    // Auth, checkpoint, dispute.
    let k = SignKey::from_seed(&[0x46; 32]);
    let m = crypto::auth_msg(&[1; 32], "https://127.0.0.1:443", &[2; 32], &dev("d_01K6A0000000000000000000G1")).unwrap();
    let sig = k.sign(&m);
    crypto::verify(&k.public(), &m, &sig).unwrap();
    let m2 = crypto::auth_msg(&[1; 32], "https://127.0.0.1:444", &[2; 32], &dev("d_01K6A0000000000000000000G1")).unwrap();
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
    // Signed but out of range: attempt 0, negative cost, time going backwards.
    for (from, to) in [("\"attempt\":1", "\"attempt\":0"), ("\"cost_uusd\":34200", "\"cost_uusd\":-1"), ("\"t_end\":", "\"t_end\":1,\"x\":")] {
        let b = String::from_utf8(bytes.clone()).unwrap().replacen(from, to, 1);
        let sig = k.sign(&crypto::receipt_msg(b.as_bytes()).unwrap());
        assert_eq!(crypto::open_receipt(&k.public(), b.as_bytes(), &sig).err(), Some(Error::Malformed), "{to}");
    }
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
fn protobuf_and_artifacts() {
    // link.proto messages round-trip; ciphertext stays a zero-copy Bytes.
    let up = pb::SubmitUp {
        msg: Some(pb::submit_up::Msg::Open(pb::SubmitOpen {
            task: task().to_string(),
            route: Bytes::from(route_bytes()),
            wraps: vec![pb::Wrap { worker_device: "d_01K6A0000000000000000000W1".into(), wrap: Bytes::from(vec![7; 80]) }],
            body_len: 100,
            body_chunks: 1,
            platform_sandboxed: false,
        })),
    };
    assert_eq!(pb::SubmitUp::decode(up.encode_to_vec().as_slice()).unwrap(), up);
    let ch = pb::ServeUp { msg: Some(pb::serve_up::Msg::Chunk(sealer(1, [1; 32]).seal(b"x", true).unwrap())) };
    assert_eq!(pb::ServeUp::decode(Bytes::from(ch.encode_to_vec())).unwrap(), ch);
    assert!(msg::code::retryable("busy") && !msg::code::retryable("firewall") && !msg::code::retryable("whatever"));

    // Route header: exact fields; duplicate, unknown, out-of-enum all refused.
    let r = RouteHeader::parse(&route_bytes()).unwrap();
    assert_eq!(r.cache_ttl, CacheTtl::None);
    assert_eq!(RouteHeader::parse(&r.to_bytes().unwrap()).unwrap(), r);
    let s = String::from_utf8(route_bytes()).unwrap();
    assert_eq!(RouteHeader::parse(s.replacen("{", r#"{"model":"anthropic/claude-haiku-4.5","#, 1).as_bytes()), Err(Error::Json));
    assert_eq!(RouteHeader::parse(s.replacen("{", r#"{"extra":1,"#, 1).as_bytes()), Err(Error::Malformed));
    assert_eq!(RouteHeader::parse(s.replace("\"none\"", "\"2h\"").as_bytes()), Err(Error::Malformed));
    assert_eq!(RouteHeader::parse(s.replace("1024", "-1").as_bytes()), Err(Error::Malformed));

    // Catalog: strict, unknown pricing fields refused.
    let cat = format!(r#"{{"version":3,"effective_at_ms":0,"entries":[{}]}}"#, SONNET);
    let c = msg::Catalog::parse(cat.as_bytes()).unwrap();
    assert_eq!(c.entry("anthropic/claude-sonnet-5.5", "anthropic"), Some(&sonnet()));
    assert!(c.entry("anthropic/claude-sonnet-5.5", "openrouter").is_none());
    let extra = cat.replacen("\"in\":", "\"long_context_in\":9,\"in\":", 1);
    assert_eq!(msg::Catalog::parse(extra.as_bytes()), Err(Error::Malformed));
}

const SONNET: &str = r#"{"model":"anthropic/claude-sonnet-5.5","provider":"anthropic","provider_model_id":"claude-sonnet-5-5","aliases":["claude-sonnet-5-5"],"dialects":["anthropic.messages"],"in":2000000,"out":10000000,"cache_write_5m":2500000,"cache_write_1h":4000000,"cache_read":200000,"max_image_tokens":1600,"max_page_tokens":3000,"fast_multiplier":6,"default_effort":"high","max_output":64000,"source":"curated"}"#;

fn sonnet() -> CatalogEntry {
    json::parse(SONNET.as_bytes()).unwrap()
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
    // F20: xAI's long-context price and reasoning allowance, as the relay's ledger.Reserve.
    let mut r = msg::RouteHeader::parse(&route_bytes()).unwrap();
    assert_eq!(money::reserve_for_route(&c, &r).unwrap(), money::reserve_uusd(&c, 10, 1024, CacheTtl::None, false).unwrap());
    let xai = CatalogEntry { provider: "xai".into(), ..c.clone() };
    assert_eq!(money::reserve_for_route(&xai, &r).unwrap(), money::reserve_uusd(&c, 10, 1024 + 32_000, CacheTtl::None, false).unwrap());
    r.est_input_tokens = 200_000;
    let long = CatalogEntry { input: 2 * c.input, out: 2 * c.out, ..c.clone() };
    assert_eq!(money::reserve_for_route(&xai, &r).unwrap(), money::reserve_uusd(&long, 200_000, 1024 + 32_000, CacheTtl::None, false).unwrap());
    let plain = CatalogEntry { default_effort: "none".into(), ..xai.clone() };
    assert_eq!(money::reserve_for_route(&plain, &r).unwrap(), money::reserve_uusd(&long, 200_000, 1024, CacheTtl::None, false).unwrap());
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
    assert_eq!((f.max_tokens, f.stream, f.cache_ttl, f.images, f.pages, f.fast), (Some(1024), true, CacheTtl::H1, 1, 0, false));
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
    assert_eq!((f.max_tokens, f.effort.as_deref(), f.images, f.stream, f.cache_ttl), (Some(50), Some("low"), 2, false, CacheTtl::None));
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

const GPT: &str = r#"{"model":"openai/gpt-5.5","provider":"openai","provider_model_id":"gpt-5.5","dialects":["openai.chat","openai.responses"],"in":1250000,"out":10000000,"cache_write_5m":0,"cache_write_1h":0,"cache_read":125000,"max_image_tokens":1500,"max_page_tokens":0,"default_effort":"medium","max_output":128000,"source":"curated"}"#;

/// CONTRACT §18.6: `openai.responses` request facts and route check.
#[test]
fn responses_body_facts_and_route() {
    let c: CatalogEntry = json::parse(GPT.as_bytes()).unwrap();
    assert_eq!(serde_json::to_string(&Dialect::OpenAiResponses).unwrap(), "\"openai.responses\"");
    assert_eq!(Dialect::OpenAiResponses.as_str(), "openai.responses");
    assert_eq!(json::parse::<Dialect>(b"\"openai.responses\"").unwrap(), Dialect::OpenAiResponses);
    // Codex: no max_output_tokens → catalog max_output; reasoning.effort; inline image.
    let b = br#"{"model":"gpt-5.5","stream":true,"reasoning":{"effort":"high","summary":"auto"},"instructions":"be brief","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}]}"#;
    let f = money::body_facts(Dialect::OpenAiResponses, b).unwrap();
    assert_eq!((f.max_tokens, f.max_tokens_for(&c), f.effort.as_deref(), f.stream, f.images), (None, 128_000, Some("high"), true, 1));
    assert_eq!(f.text_bytes, b.len() as u64 - "data:image/png;base64,AAAA".len() as u64);
    let repo: RepoId = "r_01K6A0000000000000000000R1".parse().unwrap();
    let route = f.route(&c, Dialect::OpenAiResponses, repo, [0; 16]).unwrap();
    assert_eq!((route.max_tokens, route.effort.as_str(), route.flags.clone()), (128_000, "high", vec!["images".to_owned()]));
    assert_eq!(money::check_route(&route, &f, &c), Ok(()));
    let mut r2 = route.clone();
    r2.max_tokens = 1_000;
    assert_eq!(money::check_route(&r2, &f, &c), Err("max_tokens"), "absent cap = catalog max_output, exactly");
    // Explicit cap, default effort, no images.
    let b = br#"{"model":"openai/gpt-5.5","max_output_tokens":2048,"input":"hello"}"#;
    let f = money::body_facts(Dialect::OpenAiResponses, b).unwrap();
    assert_eq!((f.max_tokens_for(&c), f.effort.as_deref(), f.stream, f.images), (2048, None, false, 0));
    assert_eq!(f.route(&c, Dialect::OpenAiResponses, repo, [0; 16]).unwrap().effort, "medium");
    // Wrong types are refused; the other dialects still require their cap.
    for bad in [&br#"{"model":"m","max_output_tokens":-1}"#[..], br#"{"model":"m","reasoning":{"effort":3}}"#, br#"{"model":"m","max_output_tokens":4294967296}"#, br#"{"input":"x"}"#] {
        assert_eq!(money::body_facts(Dialect::OpenAiResponses, bad).err(), Some(Error::Malformed), "{}", String::from_utf8_lossy(bad));
    }
    assert_eq!(money::body_facts(Dialect::OpenAiChat, br#"{"model":"m","messages":[]}"#).err(), Some(Error::Malformed));
}

/// CONTRACT §18.6: Responses `usage` → receipt usage → cost (checked math, never wrapping).
#[test]
fn responses_usage_and_cost() {
    use money::{ResponsesUsage, responses_usage};
    let c: CatalogEntry = json::parse(GPT.as_bytes()).unwrap();
    let ru = |i, o, t, cached| ResponsesUsage { input_tokens: i, output_tokens: o, total_tokens: t, cached_tokens: cached, provider_cost_uusd: None };
    // 10,000 input of which 8,000 cached, 1,500 output (incl. reasoning).
    let u = responses_usage(&ru(Some(10_000), Some(1_500), Some(11_500), Some(8_000)));
    assert_eq!((u.input, u.cache_read, u.output, u.cache_write_5m, u.cache_write_1h, u.estimated), (2_000, 8_000, 1_500, 0, 0, false));
    // 2,000 × 1.25 + 8,000 × 0.125 + 1,500 × 10 = 2,500 + 1,000 + 15,000 µ$
    assert_eq!(money::cost_uusd(&c, &u, false).unwrap(), 18_500);
    // A provider that leaves reasoning out of output_tokens: total − input wins.
    let u = responses_usage(&ru(Some(100), Some(10), Some(400), None));
    assert_eq!((u.input, u.output, u.estimated), (100, 300, false));
    // Ceil to the next µ$: 1 input token = 1.25 µ$ → 2.
    assert_eq!(money::cost_uusd(&c, &responses_usage(&ru(Some(1), Some(0), None, None)), false).unwrap(), 2);
    // cached > input: no wrap; input counted whole, usage estimated (settles at the reservation).
    let u = responses_usage(&ru(Some(5), Some(1), None, Some(9)));
    assert_eq!((u.input, u.cache_read, u.estimated), (5, 9, true));
    // total < input: the total term is ignored, never wraps.
    assert_eq!(responses_usage(&ru(Some(500), Some(7), Some(3), None)).output, 7);
    // Missing fields → estimated.
    assert!(responses_usage(&ru(None, Some(1), None, None)).estimated && responses_usage(&ru(Some(1), None, None, None)).estimated);
    // Overflow is an error, never a wrapped amount.
    let huge = responses_usage(&ru(Some(u64::MAX), Some(u64::MAX), None, None));
    assert_eq!(money::cost_uusd(&c, &huge, false), Err(Error::Overflow));
    // Provider-reported cost: OpenRouter required and authoritative, xAI optional, openai refused.
    let with = |p: &str, pc: Option<i64>| {
        let e = CatalogEntry { provider: p.into(), ..c.clone() };
        money::cost_uusd(&e, &responses_usage(&ResponsesUsage { provider_cost_uusd: pc, ..ru(Some(10), Some(10), None, None) }), false)
    };
    assert_eq!((with("openrouter", Some(42)), with("xai", Some(43)), with("xai", None)), (Ok(42), Ok(43), Ok(113)));
    assert_eq!((with("openrouter", None), with("openai", Some(1))), (Err(Error::Malformed), Err(Error::Malformed)));
}
