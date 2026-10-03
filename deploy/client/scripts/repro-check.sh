#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Reproducible-build check for the Linux musl `moochy` artifact (06 §12, CI-08).
#
#   repro-check.sh [--dry-run] [--target TRIPLE] [--against FILE]
#
# Without --against: builds the committed tree twice from two copies at
# different absolute paths (different umask, TZ, locale, CARGO_TARGET_DIR) and
# requires bit-identical binaries.
# With --against FILE: builds once and requires the result to equal FILE, a
# released binary or the .tar.xz archive cargo-dist published (independent
# rebuild of a release; run it on the same runner image as the release).
#
# Build flags must match .github/build-setup.yml and `dist build` (profile `dist`,
# --workspace; cli/Cargo.toml needs [profile.dist] inherits = "release"):
# sources remapped to /build, CARGO_HOME to /cargo, no incremental, SOURCE_DATE_EPOCH
# from the last commit. Run from the repository root (the directory with cli/).
set -Eeuo pipefail

target=${TARGET:-$(uname -m)-unknown-linux-musl}
against="" dry_run=0
while (($#)); do
	case $1 in
	--dry-run) dry_run=1 ;;
	--target) target=${2:?}; shift ;;
	--against) against=${2:?}; shift ;;
	-h | --help) sed -n '3,/^set /s/^# \{0,1\}//p' "$0" >&2; exit 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
	shift
done
[[ $target == *-linux-musl ]] || { echo "only *-linux-musl targets are in scope" >&2; exit 2; }
[[ -f cli/Cargo.toml && -f cli/Cargo.lock ]] || { echo "run from the repository root (cli/Cargo.lock required)" >&2; exit 2; }
cargo_home=${CARGO_HOME:-$HOME/.cargo}
jobs=${JOBS:-4}
epoch=$(git log -1 --format=%ct)
# Native musl builds (CI runner with musl-tools): ring's C code needs musl-gcc.
cc_var=CC_${target//-/_}
if [[ -z ${!cc_var:-} ]] && command -v musl-gcc >/dev/null; then export "$cc_var=musl-gcc"; fi

# build DIR UMASK TZ LANG → path of the built binary
build() {
	local src=$1/src
	mkdir -p "$src"
	git archive HEAD | tar -x -C "$src"
	(
		cd "$src/cli"
		umask "$2"
		export TZ=$3 LANG=$4 LC_ALL=$4 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$src/cli/target SOURCE_DATE_EPOCH=$epoch
		export RUSTFLAGS="--remap-path-prefix=$src=/build --remap-path-prefix=$cargo_home=/cargo"
		# dist 0.33 appends these for every musl target (cargo-dist src/build/cargo.rs).
		[[ $target == *-musl ]] && RUSTFLAGS+=" -Ctarget-feature=+crt-static -Clink-self-contained=yes"
		# Exactly what `dist build` runs: same profile, same package set (feature unification).
		cargo build --profile dist --locked -j "$jobs" --workspace --target "$target" >&2
	)
	echo "$src/cli/target/$target/dist/moochy"
}

if ((dry_run)); then
	echo "[dry-run] git archive HEAD → <tmp>/a/src (umask 022, TZ=UTC) and <tmp>/bb/deeper/src (umask 077, TZ=Asia/Kolkata)" >&2
	echo "[dry-run] RUSTFLAGS='--remap-path-prefix=<src>=/build --remap-path-prefix=$cargo_home=/cargo' CARGO_INCREMENTAL=0 cargo build --profile dist --locked --workspace --target $target" >&2
	echo "[dry-run] compare sha256 of both binaries${against:+ and of $against}" >&2
	exit 0
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/moochy-repro.XXXXXX")
trap 'rm -rf "$work"' EXIT
a=$(build "$work/a" 022 UTC C.UTF-8)
sum_a=$(sha256sum "$a" | cut -d' ' -f1)
if [[ -n $against ]]; then
	ref=$against
	if [[ $against == *.tar.xz ]]; then
		mkdir -p "$work/ref" && tar -xJf "$against" -C "$work/ref"
		ref=$(find "$work/ref" -type f -name moochy | head -n1)
	fi
	[[ -f $ref ]] || { echo "no moochy binary in $against" >&2; exit 1; }
	sum_b=$(sha256sum "$ref" | cut -d' ' -f1)
else
	b=$(build "$work/bb/deeper" 077 Asia/Kolkata en_US.UTF-8)
	sum_b=$(sha256sum "$b" | cut -d' ' -f1)
fi
printf '{"event":"repro_check","target":"%s","a":"%s","b":"%s","identical":%s}\n' \
	"$target" "$sum_a" "$sum_b" "$([[ $sum_a == "$sum_b" ]] && echo true || echo false)"
[[ $sum_a == "$sum_b" ]]
