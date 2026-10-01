#!/usr/bin/env bash
# Fuzz the pure-Rust zstd decode path with libFuzzer + ASan on STABLE rustc (RUSTC_BOOTSTRAP
# unlocks -Z sanitizer flags; no nightly, no cargo-fuzz). Usage: ./run.sh [seconds] [workers]
# Env: FUZZ_DIR (corpus/artifacts, default /tmp/moochy-proto-fuzz), CARGO_TARGET_DIR.
set -euo pipefail
cd "$(dirname "$0")"
SECS=${1:-600}
WORKERS=${2:-1}
DIR=${FUZZ_DIR:-/tmp/moochy-proto-fuzz}
HOST=$(rustc -vV | sed -n 's/^host: //p')
export RUSTC_BOOTSTRAP=1
export RUSTFLAGS="-Zsanitizer=address -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow-checks"
cargo build --release --target "$HOST" -j "${JOBS:-4}" --bins
BIN=${CARGO_TARGET_DIR:-target}/$HOST/release
mkdir -p "$DIR/corpus" "$DIR/artifacts"
[ -n "$(ls -A "$DIR/corpus")" ] || "$BIN/seeds" "$DIR/corpus"
exec "$BIN/inflate" "$DIR/corpus" -artifact_prefix="$DIR/artifacts/" -max_total_time="$SECS" \
  -max_len=262144 -timeout=10 -rss_limit_mb=2048 -fork="$WORKERS" -print_final_stats=1
