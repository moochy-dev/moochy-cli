#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Moochy client installer: curl -fsSL https://moochy.dev/install.sh | sh
#
# Installs the `moochy` binary from the GitHub release into ~/.local/bin
# (or $MOOCHY_INSTALL_DIR). Never uses sudo, never edits shell rc files.
# Checks the archive's SHA-256 and, when the GitHub CLI is signed in, its build
# attestation (gh attestation verify). To not trust moochy.dev for this script,
# read it first: curl -fsSLo install.sh https://raw.githubusercontent.com/moochy-dev/moochy-cli/main/deploy/client/install.sh
#
#   MOOCHY_VERSION=vX.Y.Z   install that release instead of the latest
#   MOOCHY_INSTALL_DIR=DIR  install into DIR instead of ~/.local/bin
#   NO_COLOR=1              plain output
set -eu

REPO="https://github.com/moochy-dev/moochy-cli"

# --- output ---------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then
	e=$(printf '\033')
	case "${COLORTERM:-}" in
	truecolor | 24bit)
		MINT="${e}[38;2;125;211;174m" BUTTER="${e}[38;2;245;217;122m" CORAL="${e}[38;2;255;127;107m" ;;
	*)
		MINT="${e}[38;5;115m" BUTTER="${e}[38;5;222m" CORAL="${e}[38;5;209m" ;;
	esac
	BOLD="${e}[1m" DIM="${e}[2m" RESET="${e}[0m"
else
	MINT='' BUTTER='' CORAL='' BOLD='' DIM='' RESET=''
fi

step() { printf '%s==>%s %s\n' "$MINT$BOLD" "$RESET" "$*"; }
detail() { printf '    %s%s%s\n' "$DIM" "$*" "$RESET"; }
die() {
	printf '%serror:%s %s\n' "$CORAL$BOLD" "$RESET" "$*" >&2
	exit 1
}

# --- platform -------------------------------------------------------------
os=$(uname -s)
arch=$(uname -m)
case "$os" in
Linux) suffix=unknown-linux-musl ;; # static: any distro
Darwin)
	suffix=apple-darwin
	# An x86_64 shell under Rosetta on Apple Silicon: take the native build.
	if [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
		arch=arm64
	fi
	;;
*) die "Moochy supports Linux and macOS only (this system reports '$os')." ;;
esac
case "$arch" in
x86_64 | amd64) arch=x86_64 ;;
aarch64 | arm64) arch=aarch64 ;;
*) die "Moochy supports x86_64 and arm64 only (this system reports '$arch')." ;;
esac
target="moochy-$arch-$suffix"
file="$target.tar.xz"

version="${MOOCHY_VERSION:-}"
case "$version" in
'') base="$REPO/releases/latest/download" ;;
*[!0-9A-Za-z.+-]*) die "MOOCHY_VERSION='$version' is not a version (expected vX.Y.Z)." ;;
v*) base="$REPO/releases/download/$version" ;;
*) version="v$version" base="$REPO/releases/download/$version" ;;
esac

dir="${MOOCHY_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}"

# --- tools ----------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "curl or wget is required."
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	die "sha256sum or shasum is required to verify the download."
fi

command -v tar >/dev/null 2>&1 || die "tar is required."

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t moochy)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

# --- install --------------------------------------------------------------
printf '\n  %smoochy%s %sinstaller%s\n\n' "$MINT$BOLD" "$RESET" "$DIM" "$RESET"

step "Platform $BUTTER$os $arch$RESET"
detail "$file (${version:-latest})"

step "Downloading"
detail "$base/$file"
fetch "$base/$file" "$tmp/$file" ||
	die "download failed: $base/$file (check your network, or MOOCHY_VERSION if set)."
fetch "$base/$file.sha256" "$tmp/$file.sha256" ||
	die "download failed: $base/$file.sha256"

step "Verifying SHA-256"
want=$(cut -d' ' -f1 <"$tmp/$file.sha256")
got=$(sha256 "$tmp/$file")
[ -n "$want" ] && [ "$want" = "$got" ] ||
	die "checksum mismatch for $file (expected ${want:-nothing}, got $got). Nothing was installed."
detail "$got"

# The .sha256 comes from the same release, so it only proves the download is
# whole. The build attestation is signed by this repository's release workflow
# and checked against github.com, not against moochy.dev or the release files.
step "Verifying build provenance"
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
	gh attestation verify "$tmp/$file" --repo moochy-dev/moochy-cli \
		--signer-workflow moochy-dev/moochy-cli/.github/workflows/release.yml >/dev/null 2>&1 ||
		die "build provenance check failed for $file (gh attestation verify). Nothing was installed."
	detail "built by github.com/moochy-dev/moochy-cli release.yml"
else
	detail "skipped: needs the GitHub CLI, signed in (gh auth login). Check it yourself:"
	detail "gh attestation verify $file --repo moochy-dev/moochy-cli"
fi

step "Extracting"
# Prefer xz | tar (any tar); macOS has no xz but its bsdtar reads .xz itself.
if command -v xz >/dev/null 2>&1; then
	xz -dc "$tmp/$file" | tar -xf - -C "$tmp" || die "cannot extract $file."
else
	tar -xJf "$tmp/$file" -C "$tmp" 2>/dev/null ||
		die "cannot extract $file: install xz (apt install xz-utils, apk add xz, dnf install xz)."
fi
bin="$tmp/$target/moochy"
[ -f "$bin" ] || die "archive $file does not contain $target/moochy."

step "Installing to $BUTTER$dir$RESET"
mkdir -p "$dir" || die "cannot create $dir (set MOOCHY_INSTALL_DIR to a writable directory)."
# Copy next to the target then rename: atomic, and safe if moochy is running.
if ! { cp "$bin" "$dir/.moochy.new" && chmod 0755 "$dir/.moochy.new" && mv -f "$dir/.moochy.new" "$dir/moochy"; }; then
	rm -f "$dir/.moochy.new"
	die "cannot write $dir/moochy (set MOOCHY_INSTALL_DIR to a writable directory)."
fi

installed=$("$dir/moochy" --version 2>&1) || die "installed $dir/moochy but it does not run: $installed"

printf '\n%sInstalled%s %s%s%s\n' "$MINT$BOLD" "$RESET" "$BUTTER" "$installed" "$RESET"
detail "$dir/moochy"

case ":${PATH:-}:" in
*":$dir:"*) cmd=moochy ;;
*)
	cmd="$dir/moochy"
	if [ -z "${MOOCHY_INSTALL_DIR:-}" ]; then line="export PATH=\"\$HOME/.local/bin:\$PATH\""; else line="export PATH=\"$dir:\$PATH\""; fi
	printf '\n%s is not on your PATH. Add this line to your shell profile:\n\n    %s%s%s\n' "$dir" "$BUTTER" "$line" "$RESET"
	;;
esac

printf '\n%sNext steps%s\n' "$BOLD" "$RESET"
printf '    %s%s login%s      sign in\n' "$BUTTER" "$cmd" "$RESET"
if [ "$os" = Linux ]; then
	printf '    %s%s doctor%s     check the sandbox\n' "$BUTTER" "$cmd" "$RESET"
	detail "Ubuntu 23.10+: 'moochy run' needs the AppArmor profile and a system-wide binary; 'moochy doctor' prints the fix."
fi
printf '    %sDocs%s           %shttps://moochy.dev/docs%s\n\n' "$DIM" "$RESET" "$MINT" "$RESET"
