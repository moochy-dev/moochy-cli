# Moochy in cloud boxes (CONTRACT §17)

Agent boxes (boat.dev, E2B, Daytona, Modal, Codespaces/devcontainers) use your project's
donations with their **own** short-lived device. Your device key never goes into a box.

1. On your machine: `moochy box token create --repo OWNER/NAME [--ttl 24h] [--cap $20] [--max-boxes 1]`.
   The token is shown once: put it in the platform's secret store as `MOOCHY_ENROLL`.
2. In the box: `moochy-box.sh` (this directory). It installs moochy if missing (release archive,
   SHA-256 checked, provenance checked when `gh` is signed in), creates `/etc/machine-id` if the
   box has none, keeps the box keys in the encrypted-file keystore, enrolls with `MOOCHY_ENROLL`
   and starts moochy. Run it at every box start: it does nothing that is already done.
3. Run the agent: `moochy run -- <agent>`. Where `moochy doctor` reports no user namespaces or
   Landlock (most containers, gVisor): `moochy run --box-is-sandbox -- <agent>` (the box is the
   sandbox: clean environment, loud warning, and tool calls only if the project allows platform
   sandboxes, which is the default for box devices).

What a box is: a gateway device for one project, with its own monthly limit, expiring with the
token. It cannot accept donors, add members, claim projects or donate. It is bound to the machine
and the boot it enrolled on: a copied or forked disk, or a restart, must enroll again (one more of
the token's `--max-boxes`), and the server refuses a second live session of the same box.
`moochy box list`, `moochy box revoke <d_…>`, `moochy box token revoke <bt_…>` (token and all its boxes).

**Never enroll in an image or template.** Every box started from it would be a clone. Install at
build time (`moochy-box.sh --install`), enroll at start.

| Platform | Preset | Enroll at start |
|---|---|---|
| boat.dev, any cloud-init VM | `cloud-init.yaml` (install only) | SSH in: `MOOCHY_ENROLL=… moochy-box.sh` (or `MOOCHY_ENROLL_FILE=`); a forked VM enrolls again |
| E2B | `e2b.Dockerfile` | `Sandbox(…, envs={"MOOCHY_ENROLL": …})`, then `commands.run("moochy-box.sh")` (not the template start command: it is snapshotted) |
| Daytona, Codespaces, devcontainers | `../devcontainer/moochy` feature | `postStartCommand` runs `moochy-box.sh`; add `MOOCHY_ENROLL` as a Codespaces/Daytona secret. A stopped and restarted codespace enrolls again: size `--max-boxes` and `--ttl` for it |
| Modal | `modal_moochy.py` | Modal secret `moochy-enroll`; `sb.exec("moochy-box.sh")` |

Devcontainer use (until the feature is published to a registry, copy `../devcontainer/moochy` into
`.devcontainer/moochy`):

```json
{ "features": { "./moochy": {} } }
```

`../devcontainer/moochy/moochy-box.sh` is a copy of `moochy-box.sh` (a feature directory must be
self-contained); a unit test in `cli/crates/node/src/boxes.rs` keeps them identical.
