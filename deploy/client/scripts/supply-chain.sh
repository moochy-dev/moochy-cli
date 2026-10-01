#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Dependency gate for the client (06 §12, CI-08): cargo-deny (advisories,
# licences, bans, sources), cargo-vet (audits), and a guard that the crypto/TLS
# trust base is audited, never exempted. Run from the repository root.
#   supply-chain.sh [--dry-run]
set -Eeuo pipefail
dir=deploy/client
store=$dir/supply-chain
# Crates whose bugs break the confidentiality/integrity promise.
trust_base=(hpke chacha20poly1305 chacha20 poly1305 aead x25519-dalek curve25519-dalek
	ed25519-zebra hkdf hmac sha2 ring rustls rustls-webpki tokio-rustls subtle zeroize scrypt)

cmds=(
	"cargo deny --manifest-path cli/Cargo.toml --config $dir/deny.toml check"
	"cargo vet --locked --manifest-path cli/Cargo.toml --store-path $store"
)
if [[ ${1:-} == --dry-run ]]; then
	printf '[dry-run] %s\n' "${cmds[@]}" "refuse [[exemptions.<crate>]] in $store/config.toml for: ${trust_base[*]}"
	exit 0
fi
[[ -f cli/Cargo.lock && -f $store/config.toml ]] || { echo "run from the repository root" >&2; exit 2; }

rc=0
for c in "${cmds[@]}"; do
	echo "+ $c" >&2
	# shellcheck disable=SC2086 # intentional word splitting of the fixed command lines
	$c || rc=1
done
exempt=()
for crate in "${trust_base[@]}"; do
	if grep -q "^\[\[exemptions\.$crate\]\]" "$store/config.toml"; then exempt+=("$crate"); fi
done
if ((${#exempt[@]})); then
	echo "trust-base crates exempted instead of audited: ${exempt[*]}" >&2
	rc=1
fi
exit "$rc"
