<!-- SPDX-License-Identifier: Apache-2.0 -->
# Client release tooling (open source, Apache-2.0)

Release engineering for the open-source `moochy` client. Everything here is published with the client in the public `moochy-cli` repository (CONTRACT §0a). Contributions require a DCO sign-off (`git commit -s`).

Open-source client (Apache-2.0) · 100% free.

## Layout in the public repository

The export copies these files into place; everything else stays where it is.

| Here | Public repository |
|---|---|
| `dist-workspace.toml` | `/dist-workspace.toml` |
| `github/build-setup.yml` | `/.github/build-setup.yml` |
| `github/workflows/*.yml` | `/.github/workflows/` |
| `deny.toml`, `supply-chain/`, `scripts/`, `container/` | `/deploy/client/` (unchanged) |

Required in `cli/` (integrator / `mo-node`): `[profile.dist] inherits = "release"` in `cli/Cargo.toml`; `[package.metadata.dist] dist = true`, `repository`, `homepage` in `cli/crates/node/Cargo.toml`.

## What ships

`dist plan` produces, per release tag `vX.Y.Z`:

- archives for macOS (arm64, x86_64), Linux (arm64, x86_64; glibc and musl), Windows (arm64, x86_64), each with a `.sha256`;
- shell and PowerShell installers, a Homebrew formula (`moochy-dev/homebrew-tap`), and the npm package `moochy` (`npx -y moochy mcp`);
- no auto-updater (`install-updater = false`): `moochy update` verifies signatures itself (06 §12).

`github/workflows/release.yml` is **generated** by `dist generate` (cargo-dist 0.33.0); never edit it by hand.

## Verify a release (users)

Verification happens outside the binary; a binary checking itself would prove nothing.

```sh
# SLSA build provenance, Sigstore-signed by the release workflow
gh attestation verify moochy-x86_64-unknown-linux-musl.tar.xz --repo moochy-dev/moochy-cli

# or cosign with the bundle attached to the release
cosign verify-blob moochy-x86_64-unknown-linux-musl.tar.xz \
  --bundle moochy-x86_64-unknown-linux-musl.tar.xz.sigstore.json \
  --certificate-identity-regexp '^https://github.com/moochy-dev/moochy-cli/\.github/workflows/attest-release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# rebuild the Linux musl artifact yourself (Ubuntu 24.04, musl-tools, Rust as pinned)
git checkout vX.Y.Z
deploy/client/scripts/repro-check.sh --target x86_64-unknown-linux-musl --against moochy-x86_64-unknown-linux-musl.tar.xz
```

## Checks

| Script | Gate | CI job |
|---|---|---|
| `scripts/repro-check.sh` | two builds at different paths, umask, TZ, locale are bit-identical; `--against` compares with a release | `supply-chain/reproducible`, `attest-release/rebuild` |
| `scripts/supply-chain.sh` | `cargo deny` (advisories, licences, bans incl. OpenSSL, sources) + `cargo vet` + the crypto/TLS trust base is audited, never exempted (`hpke` included) | `supply-chain/deny-vet` |
| `scripts/dco-check.sh` | every commit has the author's `Signed-off-by:` | `supply-chain/dco` |

Every script takes `--dry-run`. After `cli/Cargo.lock` changes: `cargo vet regenerate imports` and `cargo vet regenerate exemptions` with `--manifest-path cli/Cargo.toml --store-path deploy/client/supply-chain`, then audit (`cargo vet certify`) any trust-base crate the regeneration exempted.

## Ubuntu 23.10+ (AppArmor user-namespace restriction)

`moochy run` needs unprivileged user namespaces. Where `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 23.10+), `apparmor/moochy` grants `userns` to `/usr/bin/moochy` and `/usr/local/bin/moochy` only, and confines nothing else. Never widen it to a user-writable path (`~/.local/bin`, `~/.cargo/bin`): any program of that user could put itself there and obtain the right. `moochy doctor` and a refused `moochy run` print the same fix for the binary actually running, and tell the user to install it system-wide first when its path is writable by them.

- **.deb** (when one is built; cargo-dist does not make them). Binary at `/usr/bin/moochy`. Ship `apparmor/moochy` as the conffile `/etc/apparmor.d/moochy`, only in packages for series with AppArmor ≥ 4.0 (24.04+; the `abi <abi/4.0>` / `userns` syntax does not parse on 22.04, which has no restriction anyway). `postinst configure`: `if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ] && aa-enabled --quiet 2>/dev/null; then apparmor_parser -r -T -W /etc/apparmor.d/moochy || true; fi` (`dh_apparmor --profile-name=moochy` generates the equivalent). `prerm remove`: `apparmor_parser -R /etc/apparmor.d/moochy 2>/dev/null || true`. dpkg removes the conffile on purge.
- **Tarball / shell installer** (installs to `~/.local/bin`: user-writable, so not covered on purpose). For `moochy run` on such hosts, install system-wide from the extracted archive: `sudo install -m 0755 moochy /usr/local/bin/moochy && sudo install -m 0644 apparmor/moochy /etc/apparmor.d/moochy && sudo apparmor_parser -r /etc/apparmor.d/moochy`, and run `/usr/local/bin/moochy` (put it first in `PATH` or remove the `~/.local/bin` copy). The Linux archives therefore carry the profile as `apparmor/moochy` (dist `include`).
- **Check:** `moochy doctor` shows `ok sandbox`; `aa-status | grep moochy` lists the profile.

## Headless donor container

`container/Containerfile`: a static musl binary on an empty base, uid 65532, state in the `/data` volume (encrypted-file keystore, plan 07 §8.3). The donor's provider key stays on infrastructure the donor controls.
