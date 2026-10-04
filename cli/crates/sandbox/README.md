# moochy-sandbox

Moochy's process isolation, built from operating system primitives: no Docker and no daemon. It
**fails closed**: if a jail cannot be set up, nothing runs unsandboxed.

- **`Spec::run`** (maintainer side, `moochy run`): runs a coding agent and everything it starts
  in a jail that sees only the project. It uses Linux user, mount, PID, net, IPC and UTS
  namespaces, `pivot_root`, Landlock, seccomp-bpf, `no_new_privs` and rlimits; on macOS it uses
  Seatbelt. Network access goes only to Moochy.
- **`lockdown_self`** (donor side): after start-up, the Moochy app locks itself irreversibly. It
  can no longer start programs (`execve`), its files are limited to its own state folder, and it
  can connect only to the provider and to Moochy.
- **`spawn_validator`** (donor side): a single-use child process with no files, no network and no
  keys, where all parsing of untrusted request bytes happens.

The only `unsafe` code lives in `sys`. The API is described in `API.md`. Test:
`cargo test -p moochy-sandbox` (some tests need user namespaces or Landlock and skip
themselves without them). License: Apache-2.0. Part of
[moochy-cli](https://github.com/moochy-dev/moochy-cli).
