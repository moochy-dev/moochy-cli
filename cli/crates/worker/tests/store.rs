//! Outbox / served-set / reservation store: caps, replay protection, retention, and crash
//! safety (a kill mid-write simulated by truncating the log at every byte offset).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::PathBuf;

use moochy_worker::store::{RECEIPT_RETENTION_MS, Reservation, Store, StoreError, TASK_WINDOW_MS};

const T0: u64 = 1_790_812_800_000; // 2026-10-01T00:00Z

fn dir(name: &str) -> PathBuf {
    let base = std::env::var_os("MOOCHY_TEST_TMP").map_or_else(std::env::temp_dir, PathBuf::from);
    let d = base.join(format!("moochy-worker-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn res<'a>(key: &'a [u8], pledge: &'a str, amount: u64, now: u64) -> Reservation<'a> {
    Reservation {
        key,
        pledge_id: pledge,
        pledge_period: 1,
        pledge_budget_uusd: 1_000,
        per_task_cap_uusd: 500,
        amount_uusd: amount,
        device_cap_uusd: 1_500,
        now_ms: now,
    }
}

#[test]
fn caps_count_open_attempts_and_settle() {
    let d = dir("caps");
    let path = d.join("outbox.log");
    let mut s = Store::open(&path, T0).unwrap();
    s.reserve(&res(b"a", "p1", 400, T0)).unwrap();
    s.reserve(&res(b"b", "p1", 400, T0)).unwrap();
    assert!(matches!(s.reserve(&res(b"c", "p1", 400, T0)), Err(StoreError::Cap("pledge budget"))));
    assert!(matches!(s.reserve(&res(b"c", "p2", 501, T0)), Err(StoreError::Cap("per-task cap"))));
    s.reserve(&res(b"c", "p2", 500, T0)).unwrap();
    assert!(matches!(s.reserve(&res(b"d", "p3", 300, T0)), Err(StoreError::Cap("device monthly cap"))));
    assert!(matches!(s.reserve(&res(b"a", "p3", 1, T0)), Err(StoreError::Duplicate)));
    assert_eq!(s.device_left(1_500, T0), 200);
    // Settle a at 100 (receipt), release b (zero-spend proof).
    s.put_receipt(b"a", b"receipt-a", 100, T0).unwrap();
    s.release(b"b").unwrap();
    assert_eq!(s.device_left(1_500, T0), 1_500 - 100 - 500);
    assert_eq!(s.pledge_left("p1", 1, 1_000), 900);
    // Survives reopen.
    drop(s);
    let s = Store::open(&path, T0 + 1).unwrap();
    assert_eq!(s.device_left(1_500, T0), 900);
    assert_eq!(s.pledge_left("p1", 1, 1_000), 900);
    assert_eq!(s.unacked().collect::<Vec<_>>(), vec![(&b"a"[..], &b"receipt-a"[..])]);
    // New calendar month: spent resets, open reservations still count.
    let nov = T0 + 31 * 86_400_000;
    assert_eq!(s.device_left(1_500, nov), 1_000);
}

#[test]
fn served_set_window_and_replay() {
    let d = dir("served");
    let path = d.join("outbox.log");
    let mut s = Store::open(&path, T0).unwrap();
    s.check_served("d_gw", "T1", T0 - 1000, T0).unwrap();
    assert!(matches!(s.check_served("d_gw", "T1", T0 - 1000, T0), Err(StoreError::Replay)));
    s.check_served("d_other", "T1", T0, T0).unwrap();
    assert!(matches!(s.check_served("d_gw", "T2", T0 - TASK_WINDOW_MS - 1, T0), Err(StoreError::Stale)));
    assert!(matches!(s.check_served("d_gw", "T3", T0 + TASK_WINDOW_MS + 1, T0), Err(StoreError::Stale)));
    drop(s);
    // Persisted across a restart (no fsync needed for a process crash).
    let mut s = Store::open(&path, T0 + 5_000).unwrap();
    assert!(matches!(s.check_served("d_gw", "T1", T0 - 1000, T0 + 5_000), Err(StoreError::Replay)));
    drop(s);
    // Pruned once outside the window, where the freshness check refuses it anyway.
    let later = T0 + 2 * TASK_WINDOW_MS;
    let mut s = Store::open(&path, later).unwrap();
    assert!(matches!(s.check_served("d_gw", "T1", T0 - 1000, later), Err(StoreError::Stale)));
}

#[test]
fn retention_and_since() {
    let d = dir("retention");
    let path = d.join("outbox.log");
    let mut s = Store::open(&path, T0).unwrap();
    s.put_receipt(b"k1", b"r1", 0, T0).unwrap();
    s.put_receipt(b"k2", b"r2", 0, T0 + 10).unwrap();
    assert!(s.ack(b"k1", T0 + 20).unwrap());
    assert!(!s.ack(b"k1", T0 + 21).unwrap());
    assert!(!s.ack(b"nope", T0).unwrap());
    assert_eq!(s.unacked().count(), 1);
    assert_eq!(s.since(T0 + 5).count(), 1);
    assert_eq!(s.since(0).count(), 2);
    s.compact(T0 + RECEIPT_RETENTION_MS).unwrap();
    assert_eq!(s.since(0).count(), 2, "acked receipts are kept 7 more days");
    s.compact(T0 + 20 + RECEIPT_RETENTION_MS + 1).unwrap();
    assert_eq!(s.since(0).count(), 1, "then dropped");
    drop(s);
    let s = Store::open(&path, T0 + 20 + RECEIPT_RETENTION_MS + 2).unwrap();
    assert_eq!(s.unacked().map(|(k, _)| k.to_vec()).collect::<Vec<_>>(), vec![b"k2".to_vec()]);
}

#[test]
fn stale_open_reservation_settles_pessimistically() {
    let d = dir("stale");
    let path = d.join("outbox.log");
    let mut s = Store::open(&path, T0).unwrap();
    s.reserve(&res(b"x", "p", 300, T0)).unwrap();
    drop(s); // power loss before the receipt
    let s = Store::open(&path, T0 + 25 * 3600 * 1000).unwrap();
    assert_eq!(s.pledge_left("p", 1, 1_000), 700, "settled at its amount, no longer open");
}

/// Kill mid-write: for every prefix length of the final log, reopening yields exactly the
/// state of the last complete record, truncates the torn tail, and accepts new writes.
#[test]
fn crash_mid_write_every_offset() {
    let d = dir("crash");
    let path = d.join("outbox.log");
    // Build a log without compaction rewriting it: open once, then append records.
    let mut s = Store::open(&path, T0).unwrap();
    let mut marks = vec![std::fs::metadata(&path).unwrap().len()];
    let mut step = |s: &mut Store, f: &dyn Fn(&mut Store)| {
        f(s);
        marks.push(std::fs::metadata(&path).unwrap().len());
    };
    step(&mut s, &|s| s.reserve(&res(b"a", "p", 100, T0)).unwrap());
    step(&mut s, &|s| s.check_served("g", "t1", T0, T0).unwrap());
    step(&mut s, &|s| s.put_receipt(b"a", b"signed receipt bytes a", 40, T0).unwrap());
    step(&mut s, &|s| s.reserve(&res(b"b", "p", 200, T0)).unwrap());
    step(&mut s, &|s| {
        s.ack(b"a", T0).unwrap();
    });
    step(&mut s, &|s| s.put_receipt(b"b", b"signed receipt bytes b", 0, T0).unwrap());
    drop(s);
    let full = std::fs::read(&path).unwrap();
    assert_eq!(*marks.last().unwrap(), full.len() as u64);

    // Expected (pledge_left, unacked count, served t1?) after each complete record.
    let expect = [(1000, 0, false), (900, 0, false), (900, 0, true), (960, 1, true), (760, 1, true), (760, 0, true), (960, 1, true)];
    let crash = d.join("crash.log");
    for cut in 0..=full.len() {
        std::fs::write(&crash, &full[..cut]).unwrap();
        let k = marks.iter().rposition(|m| *m as usize <= cut).unwrap();
        let mut s = Store::open(&crash, T0).unwrap();
        let (left, unacked, served) = expect[k];
        assert_eq!(s.pledge_left("p", 1, 1_000), left, "cut {cut}");
        assert_eq!(s.unacked().count(), unacked, "cut {cut}");
        assert_eq!(matches!(s.check_served("g", "t1", T0, T0), Err(StoreError::Replay)), served, "cut {cut}");
        // Still writable and durable after recovery.
        s.put_receipt(b"z", b"after", 0, T0).unwrap();
        drop(s);
        let s = Store::open(&crash, T0).unwrap();
        assert!(s.since(0).any(|(k, _)| k == b"z"), "cut {cut}");
    }

    // A flipped byte in the middle (not a torn tail) is also detected by the CRC.
    let mut bad = full.clone();
    let mid = marks[2] as usize + 10;
    bad[mid] ^= 0x40;
    std::fs::write(&crash, &bad).unwrap();
    let s = Store::open(&crash, T0).unwrap();
    assert_eq!(s.pledge_left("p", 1, 1_000), 900);
}
