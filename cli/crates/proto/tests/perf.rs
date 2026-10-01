//! Performance + allocation checks (CONTRACT §13). Own binary so the counting allocator only
//! sees this test. Run: `cargo test --release -p moochy-proto --test perf -- --ignored --nocapture`
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
#[ignore = "benchmark: run in release"]
fn perf() {
    let ck = ContentKey::from_bytes([0x11; 32]);
    let task: TaskId = "01K6A0000000000000000000T1".parse().unwrap();
    let w: DeviceId = "d_01K6A0000000000000000000W1".parse().unwrap();
    let r = [0x22; 32];
    let release = !cfg!(debug_assertions);

    // 1) Gateway: 100 KB body → all sealed chunks (= first sealed byte).
    let body: Vec<u8> = (0..100_000u32).map(|i| b"{\"role\":\"user\",\"content\":\"lorem ipsum dolor sit amet\"},"[(i % 52) as usize]).collect();
    let mut times = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        let s = crypto::seal_request(&ck, &task, &body).unwrap();
        times.push(t.elapsed());
        assert!(s.body_len > 0);
    }
    let (p50, p99) = (pct(times.clone(), 50), pct(times, 99));
    println!("seal_request 100 KB: p50 {p50:?} p99 {p99:?} (budget 1 ms / 3 ms)");

    // 2) Worker: open the same request (decrypt + inflate), allocations per chunk.
    let big: Vec<u8> = (0..8 * MAX_CHUNK).map(|i| (i * 7 % 251) as u8).collect();
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

    // 3) Response stream: 64 KiB chunks, MB/s and allocations per chunk.
    let total = if release { 1 << 30 } else { 32 << 20 };
    let n = total / MAX_CHUNK;
    let pt = vec![0x5Au8; MAX_CHUNK];
    let mut s = ResponseSealer::new(&ck, &r, &task, &w, 1).unwrap();
    let mut op = ResponseOpener::new(&ck, &r, &task, &w, 1).unwrap();
    let mut out = BytesMut::with_capacity(MAX_CHUNK + 64);
    // Warm up: first chunk sizes the arenas.
    let c = s.seal(&pt, false).unwrap();
    op.open_into(&c, &mut out).unwrap();
    drop(c);
    let (mut ts, mut to) = (Duration::ZERO, Duration::ZERO);
    let reg = Region::new(GLOBAL);
    for i in 1..n {
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
    let mbps = |d: Duration| ((n - 1) * MAX_CHUNK) as f64 / d.as_secs_f64() / 1e6;
    println!(
        "64 KiB chunks × {}: seal {:.0} MB/s, open {:.0} MB/s (incl. running SHA-256); allocations {} over {} chunks",
        n - 1,
        mbps(ts),
        mbps(to),
        st.allocations + st.reallocations,
        n - 1
    );
    assert_eq!(st.allocations + st.reallocations, 0, "no allocation per chunk once warm");

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
        assert!(mbps(ts) >= 800.0 && mbps(to) >= 800.0, "below the 800 MB/s target");
    }
}
