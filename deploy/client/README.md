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

`moochy run` needs unprivileged user namespaces: install `apparmor/moochy` with `sudo install -m 0644 deploy/client/apparmor/moochy /etc/apparmor.d/moochy && sudo apparmor_parser -r /etc/apparmor.d/moochy` (grants `userns` to `/usr/{,local/}bin/moochy` only; `moochy doctor` prints the same fix for the actual binary path).

## Headless donor container

`container/Containerfile`: a static musl binary on an empty base, uid 65532, state in the `/data` volume (encrypted-file keystore, plan 07 §8.3). The donor's provider key stays on infrastructure the donor controls.
