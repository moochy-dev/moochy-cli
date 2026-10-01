//! libFuzzer target: arbitrary bytes, split into attacker-chosen pieces, into the pure-Rust
//! `Inflater` (cap 1 MiB). Invariants: no panic / ASan report / timeout; output ≤ cap; anything
//! whenever ruzstd and C zstd both accept, the bytes are identical (differential oracle,
//! test-only). Known and accepted: ruzstd is laxer than libzstd on some corrupt blocks (it
//! may decode what libzstd calls "data corruption"); harmless here because only the Worker
//! decodes and the result must still pass strict JSON + the Gateway's signed body hash.
#![no_main]

use libfuzzer_sys::fuzz_target;
use moochy_proto::inflate::Inflater;

const CAP: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let Some((&[a, b], z)) = data.split_first_chunk::<2>().map(|(h, r)| (h, r)) else { return };
    let piece = usize::from(u16::from_le_bytes([a, b])).max(1);
    let mut inf = Inflater::new(CAP);
    let mut ok = true;
    for c in z.chunks(piece) {
        if inf.push(c).is_err() {
            ok = false;
            break;
        }
    }
    if !ok {
        return;
    }
    if let Ok(out) = inf.finish() {
        assert!(out.len() <= CAP);
        if let Ok(c) = zstd::bulk::decompress(z, CAP) {
            assert!(c == out, "ruzstd and C zstd both accept but disagree");
        }
    }
});
