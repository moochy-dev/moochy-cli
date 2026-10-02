#!/usr/bin/env bash
# Fuzz moochy-worker's parsers with libFuzzer + ASan on STABLE rustc (RUSTC_BOOTSTRAP unlocks
# -Z sanitizer flags; no nightly, no cargo-fuzz). Usage: ./run.sh [seconds-per-target] [targets…]
# Env: FUZZ_DIR (corpus/artifacts, default /tmp/moochy-worker-fuzz), CARGO_TARGET_DIR, JOBS.
set -euo pipefail
cd "$(dirname "$0")"
SECS=${1:-300}
shift || true
TARGETS=${*:-firewall json json_diff stream reemit validate inspect local_url}
DIR=${FUZZ_DIR:-/tmp/moochy-worker-fuzz}
HOST=$(rustc -vV | sed -n 's/^host: //p')
export RUSTC_BOOTSTRAP=1
export RUSTFLAGS="-Zsanitizer=address -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow-checks"
cargo build --release --target "$HOST" -j "${JOBS:-4}" --bins
BIN=${CARGO_TARGET_DIR:-target}/$HOST/release
mkdir -p "$DIR"
[ -d "$DIR/stream" ] || "$BIN/seeds" "$DIR"
rc=0
for t in $TARGETS; do
  mkdir -p "$DIR/$t" "$DIR/artifacts/$t"
  echo "== $t (${SECS}s)"
  "$BIN/$t" "$DIR/$t" -artifact_prefix="$DIR/artifacts/$t/" -max_total_time="$SECS" \
    -max_len=1048576 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1 2>&1 | grep -E "^(#[0-9]+.*DONE|stat::number_of_executed_units|stat::peak_rss|==[0-9]+==ERROR|SUMMARY|.*panicked|Test unit written)" || rc=1
done
exit $rc
