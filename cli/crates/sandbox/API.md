# `moochy-sandbox` API (for mo-node and mo-worker)

CONTRACT §15. Three entry points. All of them **fail closed**: if the sandbox cannot be
established they return an `Error` naming the precise reason, and nothing runs unsandboxed.

```toml
moochy-sandbox = { path = "../sandbox" }
```

## 1. `moochy run -- <cmd>` (maintainer side, §15.1 / §15.4)

```rust
use moochy_sandbox::{Spec, mint_run_token, RUN_TOKEN_ENV, GATEWAY_SOCK_PATH};

let token = mint_run_token()?;                       // 256-bit, CSPRNG, fails closed
// mo-node: register `token` with the running Node over LocalControl as
// "sandboxed session for repo X" BEFORE starting the run (see §1.3).
let mut spec = Spec::new(worktree);                  // the git worktree, rw
spec.gateway_socket = Some(node_gateway_unix_socket); // host path, see §1.2
spec.gateway_loopback_port = Some(port);             // agent sees 127.0.0.1:<port>
spec.run_token = Some(token.clone());                // injected as MOOCHY_RUN_TOKEN, inside only
spec.env.insert("ANTHROPIC_BASE_URL".into(), format!("http://127.0.0.1:{port}").into());
spec.env.insert("ANTHROPIC_API_KEY".into(), token.clone().into()); // the run token IS the key
spec.ro_paths.push(tool_install_dir);                // e.g. ~/.local/share/claude (see §1.4)
spec.limits.wall_seconds = 0;                        // optional deadline → exit 124
let code = spec.run(program, &args)?;                // blocks; returns the agent's exit code
// mo-node: revoke `token` (LocalControl) — always, also on error paths.
```

| `Spec` field | Default | Meaning |
|---|---|---|
| `worktree` | required | The only read-write project dir. Mounted at the same absolute path inside. |
| `ro_paths` | `/usr /bin /sbin /lib /lib64 /etc` (those that exist) | Visible read-only (mount-level ro **and** Landlock read-only). Add toolchains. |
| `rw_paths` | empty | Extra read-write dirs (rare, e.g. a shared build cache). |
| `gateway_socket` | `None` | Host Unix socket of the gateway, bind-mounted at `/run/moochy/gateway.sock`. |
| `gateway_loopback_port` | `None` | Loopback TCP port inside the empty netns, bridged to `gateway_socket`. Requires it. |
| `env` | empty | The **only** variables passed (plus `PATH`, `HOME=/home/sandbox`, `TMPDIR=/tmp`, `USER`, `TERM`). Nothing is inherited. |
| `cwd` | worktree | Working directory inside. |
| `run_token` | `None` | Exported as `MOOCHY_RUN_TOKEN` inside the sandbox only. |
| `limits` | 4 GiB AS, 1024 fds, 512 procs, no core, no CPU/wall cap | rlimits (every one applied or the run fails); `wall_seconds` kills the whole sandbox (exit 124). cgroup v2 (§1.8): `processes` → `pids.max`, `memory_total_bytes` → `memory.max` + swap 0, `cpu_percent` → `cpu.max` (0 = unset). |
| `allow_hosts` | empty | `--allow-host`: exact host names reachable on :443 through the CONNECT proxy (§1.2b). Linux only (macOS: `Unsupported`). |
| `protected` | `[$HOME]` | No visible path (worktree, `ro_paths`, `rw_paths`) may be `/` or contain one of these. **mo-node: push the Moochy home dir.** |
| `git_writable` | `false` | Top-level `.git` writable except `hooks/ config config.worktree modules/ commondir` (§1.6). |
| `unsafe_no_sandbox` | `false` | `--unsafe-no-sandbox`: runs **without** a sandbox after a loud stderr warning. Debug only. |

Exit code: the agent's own code, `128+N` if killed by signal N, `124` on wall deadline.
`Err(...)` means the sandbox was **not** established and the command did not run; print it.

### 1.1 What the agent sees (Linux)

- New user, mount, PID, net, IPC and UTS namespaces. The agent is PID 1 of its own
  namespace, its uid maps to the caller's, and it holds no capabilities after exec.
- `pivot_root` into a tmpfs root holding only: `ro_paths`, the worktree (rw), `rw_paths`,
  private tmpfs `/tmp` (1777), `/home/sandbox` (`$HOME`, 0700) and `/run/moochy`, a minimal
  `/dev` (`null zero full random urandom`), and its own `/proc`. The real home, `~/.ssh`,
  `~/.aws`, other repos and the Moochy keystore/state **do not exist** inside.
- Secret-shaped and git-ignored files in the worktree are overmounted with an empty
  read-only file or dir (§1.5). Every `.git` is read-only (§1.6).
- Network: an empty netns with only `lo`. The agent's only route is
  `127.0.0.1:<gateway_loopback_port>` → bridge → gateway socket. Landlock (ABI ≥ 4) also
  restricts TCP `connect` to that port.
- Landlock FS (`/` read-only plus the rw set), abstract-socket and signal scoping
  (ABI ≥ 6), `no_new_privs`, the bounding set dropped, seccomp deny-list (§3), and
  `setsid` (no controlling terminal: TIOCSTI injection into your shell is impossible,
  and seccomp blocks it as well).
- Lifetime: the launcher → reaper → PID 1 chain uses `PR_SET_PDEATHSIG(SIGKILL)` at each
  step, so killing `moochy run` (even with `kill -9`) kills every process in the sandbox.
- Own cgroup namespace; terminal resizes (`SIGWINCH`) are forwarded by the reaper to the
  agent's session (it has no controlling terminal).
- Refused before anything runs (A197): a worktree / `ro_paths` / `rw_paths` entry that is `/`
  or contains `$HOME` or a `protected` dir.

### 1.2 Gateway bridge

Agents only speak `http://host:port`. The sandbox has no route to the host, so:

```
agent ──TCP 127.0.0.1:<port>──▶ reaper (in the sandbox netns, outside its cage)
                                 └─▶ /run/moochy/gateway.sock (bind mount) ──▶ host gateway
```

**Request to mo-node:** expose the gateway door on a 0600 Unix socket under
`<home>/state/` (same HTTP as the TCP door) and pass its path as `gateway_socket`. The bridge
forwards bytes verbatim, one chunk at a time with no batching (CONTRACT §13). It is
single-threaded (`poll`), capped at 64 concurrent connections, and dies with the run.

### 1.2b `--allow-host` (off by default)

`spec.allow_hosts = vec!["registry.npmjs.org".into()]`. The launcher serves an HTTP CONNECT
proxy on a Unix socket in its 0700 scratch dir, bind-mounted at `/run/moochy/proxy.sock`; the
reaper bridges `127.0.0.1:3128` (`PROXY_LOOPBACK_PORT`) to it, Landlock allows connect to that
port, and `HTTPS_PROXY`/`https_proxy` point there (`NO_PROXY=127.0.0.1,localhost`; `spec.env`
can override). Policy, fail closed: `CONNECT <host>:443` only; `host` must equal an entry
(case-insensitive exact DNS name: no wildcards, no IP literals, invalid entries make `run` fail);
every resolved address must be public (no loopback/private/link-local/CGNAT/ULA/NAT64…, so DNS
rebinding onto the gateway or cloud metadata is refused) and the tunnel connects to the checked
address. Head ≤ 8 KiB in 10 s, connect ≤ 10 s, ≤ 64 tunnels. Refusals print one line
(`moochy: --allow-host proxy refused <host>:443 (…)`; the host is a validated name). Plain-HTTP
proxying is refused (405). Test: `e94_allow_host_proxy_exact_hosts_only`.

### 1.3 Run token ("this session is sandboxed", §15.4)

The goal: the Gateway releases pooled tool calls only to sessions it *knows* are inside
`moochy run`, and a process outside the sandbox cannot obtain such a session.

1. `moochy run` (the launcher, outside) mints `t = mint_run_token()?`.
2. It registers `t` with the running Node over the 0600 `LocalControl` socket (peer-uid
   checked) as `{repo, sandboxed: true, pid: <launcher pid>}`.
3. It passes `t` **only** through `Spec.run_token` / `Spec.env`. The token never appears
   on a command line, in a file, or in the launcher's own environment.
4. Inside, the agent uses `t` as its gateway API key. The Gateway treats requests bearing
   `t` as sandboxed.
5. When `run` returns, on any path including errors and signals, the launcher revokes
   `t`. The Node also revokes it if the registering launcher pid dies, which covers a
   SIGKILLed launcher.

Why it can't be forged for an unsandboxed process: the agent can *read* `t`, but it can't
carry it out. It has no network except the gateway itself, no writable path outside the
worktree / `/tmp` / `$HOME` tmpfs, and no ptrace or signals reaching the outside. The
worktree is the one shared channel. Writing `t` there gains nothing, because `t` dies with
the run (step 5). A process outside that reads it afterwards holds a revoked token.
(Residual risk: while the run is live, a process outside running as the same user could
read the worktree. Same-user malware is out of scope, plan 06 T14.) Tested by
`e97_run_token_only_inside_and_gone_after_run`.

### 1.4 Tools installed under `$HOME`

`$HOME` is a fresh tmpfs. Agents installed under the real home (`~/.local/bin/claude`,
nvm, cargo) must be added to `ro_paths`. **Request to mo-node:** resolve the command on the
host (`which`, `realpath`) and add the install dir (and the runtime it needs, e.g. node)
to `ro_paths`; let users add more in config. Never add the whole home.

### 1.5 Masking list (show it in `moochy doctor`)

`moochy_sandbox::mask::SECRET_PATTERNS` holds the globs, matched **case-insensitively** against
base names at any depth (a pattern with `/`, like `.config/gcloud`, against trailing path
components): `.env .env.* *.pem *.key *.p12 *.pfx *.jks *.keystore id_rsa* id_dsa* id_ecdsa*
id_ed25519* .npmrc .netrc .pypirc .pgpass .git-credentials .vault-token *.tfstate *.tfstate.*
service-account*.json credentials credentials.* credentials* .aws .gcloud .config/gcloud .azure
.kube .ssh .docker`, plus every git-ignored file and directory (`git ls-files --others --ignored
--exclude-standard --directory`, run with `core.fsmonitor`/hooks forced off) **except**
ignored dependency/build dirs (`node_modules target build dist out .venv venv vendor …`, see
`mask.rs`), which tools need; secret-shaped names inside them are still masked.
`mask::collect(&worktree)` returns the exact absolute paths for one run; `doctor` can print
it. Each match is overmounted with an empty read-only file or dir. Hard links, renames and
symlinks made inside resolve through the top mount, so they reach the empty file (a hard link
fails with EXDEV), never the real inode. **Fail closed** (A193): more than 1,000,000 entries
walked or 16,384 masks refuses the run instead of leaving the rest readable.

### 1.6 Git paths the host later executes

Git trusts files under `.git` that make the *host* run code later (`hooks/`, `config`:
`core.fsmonitor`, `core.hooksPath`, aliases, includes; `commondir`, which redirects both). So
(A191): **every `.git` is read-only inside** — the top-level one (unless `git_writable`, which
still keeps `hooks/ config modules/` read-only), every nested one (submodules, vendored repos),
and the `.git` file of a linked worktree, whose own gitdir and shared commondir are visible
read-only (other worktrees' gitdirs hidden; `git status`/`log` work). A worktree with **no**
`.git` gets an empty read-only placeholder dir (so `git init` inside fails), removed after the
run. macOS: one Seatbelt rule denies writes to any `.git` path at any depth, which also blocks
creating one. A `.git` planted in a *new* subdirectory can't be blocked by mounts on Linux;
after every run `moochy run` compares the git metadata the host trusts (every `.git`, its
`config`, `config.worktree`, `commondir`, `hooks/` listing) with the state before and prints
one line: `moochy: notice: git metadata changed during the run ("deep/.git"); review it …`
(paths escaped). Commits therefore happen outside, after review (same choice as Codex).

### 1.7 Host requirements and `moochy doctor`

Linux ≥ 5.13 (Landlock), unprivileged user namespaces, seccomp. On Ubuntu ≥ 23.10
(`kernel.apparmor_restrict_unprivileged_userns=1`), `run` returns
`Error::UserNsRestricted(fix)`. Print `fix` verbatim. It is a per-binary profile, **never**
the global sysctl:

```
# /etc/apparmor.d/moochy
abi <abi/4.0>,
include <tunables/global>
profile moochy /usr/local/bin/moochy flags=(unconfined) {
  userns,
  include if exists <local/moochy>
}
```
`sudo apparmor_parser -r /etc/apparmor.d/moochy`. Use the real installed path. The shipped
profile is `deploy/client/apparmor/moochy` (`/usr/{,local/}bin/moochy` only: a user-writable
path would hand `userns` to any program of that user).

### 1.8 cgroup v2 limits (when delegated)

`delegated_cgroup()` (for `moochy doctor`) returns the parent the run's cgroup is created in:
the parent of the launcher's own cgroup, when it is writable and delegates `memory`/`pids`/
`cpu` (true under a systemd user manager: terminal/tmux scopes, `systemd-run --user --scope`;
false under a root-owned login `session-N.scope`, where rlimits stay the only limits). The run
gets `moochy-run-<pid>-<id>` with the `Limits` above; the sandbox's first process moves into
it before `unshare`, so every descendant is inside. At the end `cgroup.kill` and `rmdir`; a
SIGKILLed launcher's empty cgroup is swept by the next run. Graceful by contract: no
delegated cgroup → no error. Test: `e95_cgroup_limits_when_delegated`.

### 1.9 macOS

`sandbox-exec` with a generated profile, plus: own session (`setsid`, no controlling
terminal) with `SIGINT SIGTERM SIGHUP SIGQUIT SIGWINCH` forwarded to the run's process group
while it runs, `RLIMIT_NOFILE/CORE/CPU` (`RLIMIT_NPROC` is per user on macOS and `RLIMIT_AS`
is not enforced: not set), the wall deadline (exit 124), `killpg(SIGKILL)` of whatever is left
in the group at the end, `HOME` = a private dir in the scratch dir. Residual: a descendant
that starts its own session survives the run (no PID namespace). `allow_hosts` → `Unsupported`.

The test suite on this box used the same shape, scoped to the test binary only
(`/etc/apparmor.d/moochy-sandbox-test`), and the profile was removed afterwards.

## 2. Donor side (§15.2)

### 2.1 `lockdown_self` (whole background process, donor and gateway roles)

```rust
let mut p = DonorPolicy::new(state_dir, relay_port);  // ro: system CA dirs that exist
p.ro_paths.push(std::env::current_exe()?);           // + anything still read after start
p.gateway_port = Some(gateway_port);                 // loopback bind allowed (§15.4)
let report = moochy_sandbox::lockdown_self(&p)?;     // Err → refuse to serve; doctor shows why
```

Call it **once, after** keys are loaded, config is read, and listeners and connections are
open. Call it before spawning extra threads if you can; it uses Landlock TSYNC (ABI ≥ 8)
and seccomp TSYNC, so existing threads are covered too. It is irreversible:

- seccomp (TSYNC): `execve`/`execveat` → EPERM (kernel-enforced "zero commands"). Also
  denied: `ptrace`, `process_vm_*`, all mount APIs, `bpf`, `keyctl`/`add_key`/`request_key`,
  `perf_event_open`, `userfaultfd`, `kexec*`, module syscalls, `unshare`, `setns`,
  `clone(CLONE_NEWUSER|CLONE_NEWNS)`, `clone3` (ENOSYS so libc falls back to `clone`),
  `open_by_handle_at`, `ioctl(TIOCSTI|TIOCLINUX)`, `reboot`, `swap*`, `acct`, clock setting,
  `io_uring_*`, and on x86_64 every x32-ABI number (`nr ≥ 0x4000_0000` → EPERM).
- Landlock FS: `state_dir` rw, `ro_paths` ro, nothing else exists. **Required**: without
  Landlock, `lockdown_self` fails.
- Landlock net (ABI ≥ 4): TCP connect only to 443 and `relay_port`; bind only
  `gateway_port`. On ABI < 4, `report.landlock_net == None`. Keep serving, but the systemd
  unit's `RestrictAddressFamilies` / `IPAddressAllow` is then the only network cage, and
  doctor must say so.
- Scope (ABI ≥ 6): no abstract-socket connect or signal outside the process.
- macOS: `sandbox_init` with a generated profile: `(deny default)`, `process-exec*` and
  `process-fork` denied, `state_dir` rw, `ro_paths` ro, outbound 443 + relay, and
  `mach-lookup` denied.

Also: `PR_SET_DUMPABLE 0` (no core/crash report with keys, no same-uid ptrace), and
`state_dir` gets every Landlock right except `Execute`.

`LockdownReport { no_new_privs, seccomp, landlock_fs, landlock_net, abi }` is the
`moochy doctor` line. `abi` is the kernel's real Landlock ABI (8 on the dev box).
**Request to mo-node:** since the process can no longer exec after lockdown, anything
that runs `git` (file sharing) must live in the `moochy mcp` shim (§15.2). Any later
`Command::spawn` in the background process will return EPERM.

### 2.2 `spawn_validator` (one per request, pre-spawned)

```rust
// Pre-spawn: the closure runs in the jailed child.
let v = moochy_sandbox::spawn_validator(|fd| moochy_worker::validate::serve(fd))?;
// Per request: write the opened request to v.sock, read the canonical body back,
// then v.wait(); spawn the next one.
```

Inside the child, after `fork`: not dumpable, rlimits (NOFILE 16, AS 1 GiB, no core; any
failure exits 71), an empty Landlock
domain (no path, no TCP), then a seccomp **allowlist**, where any other syscall kills the
process with SIGSYS (exit `128+31 = 159`). Allowed:

`read write sendto recvfrom readv writev close munmap mremap brk futex exit exit_group rt_sigreturn
rt_sigprocmask sigaltstack getrandom madvise sched_yield sched_getaffinity clock_gettime
clock_nanosleep ppoll nanosleep restart_syscall rseq`, `fcntl(F_GETFD|F_GETFL)`, and
`mmap`/`mprotect` **without** `PROT_EXEC`.

**Contract for mo-worker's `validate`:** use only the inherited fd (no `open`, `socket`,
`clone` or threads). Allocation, `HashMap` and pure-Rust `ruzstd` are fine (verified by
`validator echo`). A SIGSYS or any non-zero exit means "attempt failed": map it to a native
retryable error and keep serving (E96). Framing on the fd is yours; bound every length
before you allocate.

Fork caveat: `spawn_validator` forks the calling process. The child path relies on glibc's
fork-safe `malloc` and takes no other locks before seccomp. Pre-spawn validators so the
fork cost (page-table copy of a large process) stays off the request path.

## 3. Errors

`Error::{Unsupported(&str), UserNsRestricted(fix), Setup{what, err}, Exec(io), Timeout}`.
`Display` names the failing step (`"sandbox setup failed at mount /proc: …"`). Setup errors
from inside the jail are also printed to stderr as `moochy-sandbox: …` before the spawn
fails, because std only forwards an errno.

## 4. Test driver

Fuzzing (dev-only, `fuzz/`, not a workspace member): `cargo +nightly fuzz run mask_glob` /
`seccomp_tables` (from `cli/crates/sandbox`). The oracles live in `src/fuzzing.rs`
(`cfg(test)`/`cfg(fuzzing)` only) and run deterministically in `cargo test`: the seccomp one
executes the compiled BPF of all three profiles with a cBPF interpreter against the policy
restated independently.

`moochy-sandbox-test` (bin) = probes (`read write stat connect http proxy exec hardlink symlink
tiocsti ptrace env sleep forkbomb memhog`) + launchers (`run …`, `donor …`,
`validator echo|open|socket`). `tests/e2e.rs` runs it as real subprocesses; mo-e2e can lift
each `e9x_*` test 1:1 by running the same binary with the same arguments.
