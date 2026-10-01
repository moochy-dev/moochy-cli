//! Performance + allocation checks (CONTRACT §13, R6). Own binary so the counting allocator only
//! sees this test. Runs in every `cargo test` (smaller workload, allocation budget enforced);
//! throughput/latency budgets are enforced in release builds, which CI must run:
//! `cargo test --release -p moochy-proto --test perf -- --nocapture`
#![allow(clippy::pedantic, clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::cast_precision_loss, clippy::cast_possible_truncation)]

use bytes::BytesMut;
use moochy_proto::crypto::{self, ContentKey, MAX_CHUNK, RequestOpener, ResponseOpener, ResponseSealer};
use moochy_proto::{DeviceId, TaskId};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::alloc::System;
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn pct(mut v: Vec<Duration>, p: usize) -> Duration {
    v.sort();
    v[(v.len() * p / 100).min(v.len() - 1)]
}

#[test]
fn perf() {
    let ck = ContentKey::from_bytes([0x11; 32]);
    let task: TaskId = "01K6A0000000000000000000T1".parse().unwrap();
    let w: DeviceId = "d_01K6A0000000000000000000W1".parse().unwrap();
    let r = [0x22; 32];
    let release = !cfg!(debug_assertions);

    // 1) Gateway: 100 KB body → all sealed chunks (= first sealed byte).
    // Text-like body: words drawn by a xorshift PRNG, so zstd works for real (≈3× ratio).
    let words: Vec<&str> = "the of and to in is that for it as with was on be by this are from code fn let mut impl struct return if else match self error result ok some none use pub crate test assert vec string".split(' ').collect();
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut body = Vec::with_capacity(100_000);
    while body.len() < 100_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        body.extend_from_slice(words[(x % words.len() as u64) as usize].as_bytes());
        body.push(if x.is_multiple_of(11) { b'\n' } else { b' ' });
    }
    let mut times = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        let s = crypto::seal_request(&ck, &task, &body).unwrap();
        times.push(t.elapsed());
        assert!(s.body_len > 0);
    }
    let (p50, p99) = (pct(times.clone(), 50), pct(times, 99));
    let z = crypto::seal_request(&ck, &task, &body).unwrap().body_len;
    println!("seal_request 100 KB (→ {z} B sealed): p50 {p50:?} p99 {p99:?} (budget 1 ms / 3 ms)");

    // 1b) Worker: open that 100 KB request (AEAD + pure-Rust zstd decode).
    let sealed100 = crypto::seal_request(&ck, &task, &body).unwrap();
    let mut times = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        let mut o = RequestOpener::new(&ck, &task).unwrap();
        sealed100.chunks.iter().for_each(|c| o.push(c).unwrap());
        assert_eq!(o.finish().unwrap().len(), body.len());
        times.push(t.elapsed());
    }
    println!("open_request 100 KB (ruzstd): p50 {:?} p99 {:?} (Worker budget Assign→Ack 1 ms / 3 ms, whole path)", pct(times.clone(), 50), pct(times, 99));

    // 2) Worker: open the same request (decrypt + inflate), allocations per chunk.
    let mut big = vec![0u8; 8 * MAX_CHUNK];
    crypto::fill_random(&mut big).unwrap();
    let sealed = crypto::seal_request(&ck, &task, &big).unwrap();
    let mut o = RequestOpener::new(&ck, &task).unwrap();
    o.push(&sealed.chunks[0]).unwrap();
    let reg = Region::new(GLOBAL);
    for c in &sealed.chunks[1..] {
        o.push(c).unwrap();
    }
    let st = reg.change();
    println!("RequestOpener: {} chunks, {} allocations, {} reallocations (output growth only)", sealed.chunks.len() - 1, st.allocations, st.reallocations);
    assert_eq!(o.finish().unwrap(), big);

    // 3) Response stream: 64 KiB chunks, MB/s and allocations per chunk. Best of 3 runs (shared
    //    machines are noisy; the budget is about what the code can do, not about the neighbours).
    let total = if release { 1 << 30 } else { 32 << 20 };
    let n = total / MAX_CHUNK / 3;
    let pt = vec![0x5Au8; MAX_CHUNK];
    let mut out = BytesMut::with_capacity(MAX_CHUNK + 64);
    let mbps = |d: Duration| (n * MAX_CHUNK) as f64 / d.as_secs_f64() / 1e6;
    let (mut best_seal, mut best_open, mut allocs) = (0f64, 0f64, 0u64);
    for rep in 0..3u8 {
        let mut s = ResponseSealer::new(&ck, &r, &task, &w, 1 + rep).unwrap();
        let mut op = ResponseOpener::new(&ck, &r, &task, &w, 1 + rep).unwrap();
        // Warm up: first chunk sizes the arenas.
        let c = s.seal(&pt, false).unwrap();
        out.clear();
        op.open_into(&c, &mut out).unwrap();
        drop(c);
        let (mut ts, mut to) = (Duration::ZERO, Duration::ZERO);
        let reg = Region::new(GLOBAL);
        for i in 0..n {
            let t = Instant::now();
            let c = s.seal(&pt, i + 1 == n).unwrap();
            ts += t.elapsed();
            out.clear();
            let t = Instant::now();
            op.open_into(&c, &mut out).unwrap();
            to += t.elapsed();
        }
        let st = reg.change();
        assert!(op.is_complete());
        allocs += (st.allocations + st.reallocations) as u64;
        best_seal = best_seal.max(mbps(ts));
        best_open = best_open.max(mbps(to));
    }
    println!("64 KiB chunks × {n} × 3: best seal {best_seal:.0} MB/s, best open {best_open:.0} MB/s (incl. running SHA-256); allocations {allocs}");
    assert_eq!(allocs, 0, "no allocation per chunk once warm");

    // 3b) AEAD only (request path, no running hash): best of 3 × 64 MiB through seal_compressed.
    let raw = vec![0x5Au8; 256 << 20];
    let mut aead_seal = 0f64;
    for _ in 0..3 {
        let t = Instant::now();
        let sealed = crypto::seal_compressed(&ck, &task, &raw[..64 << 20]).unwrap();
        aead_seal = aead_seal.max((64 << 20) as f64 / t.elapsed().as_secs_f64() / 1e6);
        assert!(sealed.body_len > 0);
    }
    println!("AEAD only (no SHA-256): best seal {aead_seal:.0} MB/s");

    // 3c) One-shot SHA-256 (body_sha256 of a large body).
    let t = Instant::now();
    let h = crypto::sha256(&raw);
    println!("crypto::sha256 256 MiB: {:.0} MB/s ({:02x}…)", (256 << 20) as f64 / t.elapsed().as_secs_f64() / 1e6, h[0]);

    // 4) Per token-sized chunk: seal + open latency (budget for the whole hop chain: 300 µs p50).
    let mut s = ResponseSealer::new(&ck, &r, &task, &w, 2).unwrap();
    let mut op = ResponseOpener::new(&ck, &r, &task, &w, 2).unwrap();
    let mut lat = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        let t = Instant::now();
        let c = s.seal(b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hello\"}}\n\n", i == 9_999).unwrap();
        out.clear();
        op.open_into(&c, &mut out).unwrap();
        lat.push(t.elapsed());
    }
    println!("token chunk seal+open: p50 {:?} p99 {:?}", pct(lat.clone(), 50), pct(lat, 99));

    if release {
        assert!(p50 <= Duration::from_millis(1) && p99 <= Duration::from_millis(3), "100 KB seal over budget");
        // CONTRACT R6: AEAD ≥ 800 MB/s per core; AEAD + running SHA-256 ≥ 750 MB/s per core.
        assert!(aead_seal >= 800.0, "AEAD below the R6 800 MB/s budget");
        assert!(best_seal >= 750.0 && best_open >= 750.0, "AEAD + running SHA-256 below the R6 750 MB/s budget");
    }
}
