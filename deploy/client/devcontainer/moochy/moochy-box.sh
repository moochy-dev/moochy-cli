#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Moochy in a cloud box (CONTRACT §17): boat.dev, E2B, Daytona, Modal, Codespaces/devcontainers,
# any Linux VM or container.
#
#   moochy-box.sh            install moochy if missing, enroll this box if needed, start it
#   moochy-box.sh --install  install only (image or template build: NEVER enroll in an image,
#                            every box started from it would be a clone)
#
# Idempotent: run it at every box start. Secret-free: the enrollment token comes from the
# platform's secret store as MOOCHY_ENROLL (or a file named by MOOCHY_ENROLL_FILE); create it on
# your own machine with `moochy box token create --repo OWNER/NAME`. Your own device key never
# goes into a box: the box generates its own (one project, its own monthly limit, expiring).
set -eu

RELEASES="${MOOCHY_RELEASES:-https://github.com/moochy-dev/moochy-cli/releases/latest/download}"

say() { printf 'moochy-box: %s\n' "$*" >&2; }
as_root() {
	if [ "$(id -u)" = 0 ]; then "$@"
	elif command -v sudo >/dev/null 2>&1; then sudo -n "$@"
	else return 1; fi
}

install_moochy() {
	command -v moochy >/dev/null 2>&1 && return 0
	[ "$(uname -s)" = Linux ] || { say "installs on Linux only; on macOS: brew install moochy-dev/tap/moochy"; exit 1; }
	case "$(uname -m)" in
		x86_64 | amd64) arch=x86_64 ;;
		aarch64 | arm64) arch=aarch64 ;;
		*) say "unsupported CPU $(uname -m)"; exit 1 ;;
	esac
	libc=gnu
	if ldd --version 2>&1 | grep -qi musl; then libc=musl; fi
	if ! command -v curl >/dev/null 2>&1 || ! command -v xz >/dev/null 2>&1; then
		if command -v apt-get >/dev/null 2>&1; then
			as_root apt-get update -qq && as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl xz-utils ca-certificates >/dev/null
		elif command -v apk >/dev/null 2>&1; then
			as_root apk add --no-cache curl xz ca-certificates >/dev/null
		fi
	fi
	name="moochy-$arch-unknown-linux-$libc.tar.xz"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/$name" "$RELEASES/$name"
	curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/$name.sha256" "$RELEASES/$name.sha256"
	want=$(cut -d' ' -f1 <"$tmp/$name.sha256")
	got=$(sha256sum "$tmp/$name" | cut -d' ' -f1)
	[ -n "$want" ] && [ "$want" = "$got" ] || { say "checksum mismatch: nothing installed"; exit 1; }
	# Signed build provenance, when the GitHub CLI is there and signed in.
	if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
		gh attestation verify "$tmp/$name" --repo moochy-dev/moochy-cli >/dev/null || { say "provenance check failed: nothing installed"; exit 1; }
	fi
	tar -xJf "$tmp/$name" -C "$tmp"
	bin=$(find "$tmp" -type f -name moochy | head -n 1)
	[ -n "$bin" ] || { say "no moochy binary in $name"; exit 1; }
	# System-wide, so the AppArmor profile can grant `moochy run` its user namespaces (Ubuntu).
	if as_root install -m 0755 "$bin" /usr/local/bin/moochy; then
		prof=$(find "$tmp" -type f -path '*apparmor/moochy' | head -n 1)
		if [ -n "$prof" ] && [ -d /etc/apparmor.d ]; then
			as_root install -m 0644 "$prof" /etc/apparmor.d/moochy && { as_root apparmor_parser -r /etc/apparmor.d/moochy 2>/dev/null || true; }
		fi
	else
		mkdir -p "$HOME/.local/bin"
		install -m 0755 "$bin" "$HOME/.local/bin/moochy"
		PATH="$HOME/.local/bin:$PATH"
		say "installed in ~/.local/bin (no root): if \`moochy doctor\` reports no sandbox, use \`moochy run --box-is-sandbox\`"
	fi
	rm -rf "$tmp"
	trap - EXIT
}

# The box identity is bound to the machine-id (and this boot): a box needs one, created here at
# start, never baked into an image.
ensure_machine_id() {
	[ -s /etc/machine-id ] || [ -s /var/lib/dbus/machine-id ] && return 0
	id=$(tr -d '-' </proc/sys/kernel/random/uuid)
	printf '%s\n' "$id" | as_root tee /etc/machine-id >/dev/null || { say "no /etc/machine-id, and no root to create one: enrollment would be refused"; exit 1; }
}

install_moochy
[ "${1:-}" = "--install" ] && { say "installed ($(moochy --version))"; exit 0; }

ensure_machine_id
home="${MOOCHY_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/moochy}"
# The box's keys live in the encrypted-file keystore; its passphrase stays on the box (0600).
if [ -z "${MOOCHY_PASSPHRASE:-}" ] && [ -z "${MOOCHY_PASSPHRASE_FILE:-}" ]; then
	pf="$home/box-passphrase"
	if [ ! -s "$pf" ]; then
		(umask 077 && mkdir -p "$home" && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$pf")
	fi
	export MOOCHY_PASSPHRASE_FILE="$pf"
fi
if [ -z "${MOOCHY_ENROLL:-}" ] && [ -n "${MOOCHY_ENROLL_FILE:-}" ]; then
	MOOCHY_ENROLL=$(cat "$MOOCHY_ENROLL_FILE")
	export MOOCHY_ENROLL
fi
if moochy status --json >/dev/null 2>&1; then
	say "already running"
	exit 0
fi
if [ -z "${MOOCHY_ENROLL:-}" ] && moochy config show 2>/dev/null | grep -q '"device_id":null'; then
	say "installed, not enrolled: set MOOCHY_ENROLL from your platform's secret store (moochy box token create --repo OWNER/NAME on your machine), then run this again"
	exit 0
fi
moochy up --headless
say "ready. Start your agent with: moochy run -- <agent>"
say "if \`moochy doctor\` reports no user namespaces or Landlock here: moochy run --box-is-sandbox -- <agent>"
