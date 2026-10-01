# `moochy-sandbox` design

CONTRACT §15 (+ §15.4). This file covers **why** the sandbox is built the way it is and
which prior work it follows. `API.md` is the **what**.

## 1. Prior art (sources)

| Project | Approach | What we took |
|---|---|---|
| bubblewrap — <https://github.com/containers/bubblewrap> | setuid-less user namespaces, a tmpfs root plus bind mounts, `pivot_root`, `--new-session` against TIOCSTI ([CVE-2017-5226](https://www.cve.org/CVERecord?id=CVE-2017-5226)) | The mount recipe; `setsid` in addition to seccomp for TIOCSTI; comparing only the low 32 bits of the ioctl request |
| nsjail — <https://github.com/google/nsjail>, minijail — <https://github.com/google/minijail> | Namespaces + seccomp-bpf + rlimits/cgroups, PID 1 inside | Agent as PID 1 of its own PID ns; rlimits as the portable floor |
| Firejail — <https://github.com/netblue30/firejail> | setuid launcher with large per-app profiles | Rejected the setuid model: nothing in Moochy is setuid |
| gVisor — <https://gvisor.dev/docs/> | User-space kernel intercepting syscalls | Too heavy for "no daemon, ≤15 MB". We cut kernel surface with seccomp instead |
| OpenAI Codex CLI — <https://github.com/openai/codex> | Linux: Landlock + seccomp (now also bubblewrap); macOS: generated Seatbelt profile run by `sandbox-exec` | The same macOS shape; parameterised writable roots; read-only `.git` |
| Anthropic sandbox-runtime — <https://github.com/anthropic-experimental/sandbox-runtime> | bubblewrap on Linux, `sandbox-exec` on macOS, network only through a host-side proxy | Network = one allowed door (our gateway), reached through a bridge from an empty netns |
| Docker/moby default seccomp — <https://github.com/moby/profiles/blob/main/seccomp/default.json> | Deny-list; `clone3` → `ENOSYS` (errnoRet 38) so libc falls back to `clone`, whose flags seccomp can inspect | The same `clone3` → `ENOSYS` trick, verified in that profile |
| Chromium macOS sandbox — <https://chromium.googlesource.com/chromium/src/+/main/sandbox/mac/> | Seatbelt `(deny default)` + `sandbox_init` | Self-applied Seatbelt for the donor process and the validator |

Kernel references: Landlock — <https://docs.kernel.org/userspace-api/landlock.html>,
<https://landlock.io/>; seccomp — <https://docs.kernel.org/userspace-api/seccomp_filter.html>;
user namespaces — <https://man7.org/linux/man-pages/man7/user_namespaces.7.html>;
`clone(2)` — <https://man7.org/linux/man-pages/man2/clone.2.html>; `pivot_root(2)` —
<https://man7.org/linux/man-pages/man2/pivot_root.2.html>; TIOCSTI —
<https://man7.org/linux/man-pages/man2/ioctl_tty.2.html>; PDEATHSIG —
<https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html>; cgroup v2 —
<https://docs.kernel.org/admin-guide/cgroup-v2.html>. Ubuntu's userns restriction —
<https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces>. Git hooks and
`core.fsmonitor` — <https://git-scm.com/docs/githooks>, <https://git-scm.com/docs/git-config>.
Rust crates: `landlock` <https://docs.rs/landlock>, `seccompiler`
<https://github.com/rust-vmm/seccompiler>, `rustix`.

### Landlock ABI (from the kernel docs, checked 2026-10-01)

| ABI | Adds | Used for |
|---|---|---|
| 1 (5.13) | FS access rights | FS cage (required) |
| 2 | `REFER` (rename/link across dirs) | rw roots |
| 3 | `TRUNCATE` | rw roots |
| 4 | TCP `BIND`/`CONNECT` | agent: connect gateway port only; donor: 443 + relay, bind gateway |
| 5 | `IOCTL_DEV` | handled in the FS set |
| 6 | Scope: abstract Unix sockets, signals | both sides |
| 7 | Audit logging flags | — |
| 8 | `RESTRICT_SELF_TSYNC` (all threads) | donor `lockdown_self` |
| 9 | Pathname Unix socket restriction | not yet (crate ceiling); the netns + mount view already confine the agent |
| 10 | UDP bind, quiet rules | not yet |
| 11 | `RESTRICT_SELF_NO_NEW_PRIVS` | not needed (we set NNP ourselves) |

Everything is negotiated best-effort through the `landlock` crate. The FS cage is
**required** (we fail closed without it); higher ABIs add layers. This box runs kernel 7.0
at Landlock ABI 8.

## 2. Layering

**Maintainer side (`Spec::run`).** Each layer stands on its own:

1. **Visibility (mount ns + `pivot_root`).** Secrets outside the view don't exist inside.
   The view is built by PID 1 of the new PID namespace, which mounts its own `/proc` before
   pivoting. The kernel refuses a procfs mount in a user namespace once no full procfs is
   visible, and a procfs mounted by the reaper would show the host's PIDs. Private tmpfs
   dirs are mounted *before* the binds, so a worktree under `/tmp` sits on top of them.
2. **Permissions (Landlock).** `/` is read-only and only the rw set is writable. This
   holds even if the mount view had a gap.
3. **Network (empty netns + Landlock net).** The only route is the gateway bridge. The
   reaper sits in the sandbox netns but outside its PID namespace and cage, and splices
   loopback TCP to the bind-mounted gateway socket. It is single-threaded because after
   `unshare(CLONE_NEWPID)` the kernel refuses `CLONE_THREAD` (EINVAL; found in testing).
4. **Syscalls (seccomp deny-list).** Removes kernel attack surface and escape primitives
   (§4) while the agent keeps `execve`.
5. **Privilege.** `no_new_privs`, the bounding set dropped, uid ≠ 0 inside, `setsid`.
6. **Resources.** rlimits: `RLIMIT_NPROC` is accounted per user namespace (ucounts), so
   it caps a fork bomb inside the sandbox; plus `RLIMIT_AS`, `RLIMIT_NOFILE`, no core, and
   a wall deadline enforced by the reaper through a pidfd.
7. **Lifetime.** A `PDEATHSIG` chain plus PID-namespace teardown.

**Donor side.** The background process can't exec at all (seccomp TSYNC), and Landlock
TSYNC cages files and TCP. The only parser of a stranger's bytes runs in a forked child
with an allowlist where any other syscall kills it.

## 3. Decisions on ambiguous points (safer reading)

- Agent TCP **connect** is limited to the gateway port, even on loopback. Tools that start
  a local server can bind it, but can't connect to it. Contract: "no network at all,
  except the gateway".
- Mount-level read-only (`MS_RDONLY` remount) plus Landlock read-only for `ro_paths`:
  belt and braces.
- `.git/hooks` and `.git/config` are read-only inside. They are code the *host* runs later.
- The run token is minted by the launcher, never by the agent. Minting fails closed; no
  predictable fallback.
- Donor lockdown requires Landlock FS; the network cage is best-effort with an explicit
  `None` in the report.
- The validator allowlist kills on violation (SIGSYS), never returns EPERM. A compromised
  parser gets no second try, and the parent sees a crisp failure.
- Denied syscalls in the deny-lists return EPERM, so agents and tools fail normally.
  `clone3` returns ENOSYS.

## 4. Threats → counters → proof

| Threat (escape / exfiltration class) | Counter | Proof (`tests/e2e.rs`, `moochy-sandbox-test`) |
|---|---|---|
| Read `~/.ssh`, `~/.aws`, the keystore, other repos | Not in the mount view + Landlock | `e93_worktree_rw_secrets_and_outside_invisible` |
| Write outside the worktree (system dirs, a sibling dir) | ro mounts + Landlock | `e93…` |
| Read `.env`, `*.pem`, git-ignored files in the worktree | Empty read-only overmount | `e97_secret_files_masked…`, `e97_git_ignored_masked…` |
| Reach a masked file through a hard link, rename or symlink made inside | Path resolution goes through the top mount (hard link → EXDEV, symlink → empty) | `e97_secret_files_masked_against_read_link_and_symlink` |
| Get code run later *outside* via git hooks or `core.fsmonitor` | `.git/hooks` and `.git/config` read-only | `e97_git_ignored_masked_and_git_exec_paths_read_only` |
| Exfiltrate over the network, DNS, or other loopback services | Empty netns; Landlock connect = gateway port only | `e94_only_gateway_reachable_and_no_host_env` |
| Provider keys or host secrets in the environment | `env_clear` plus an explicit allowlist | `e94…` |
| Terminal injection into the user's shell (TIOCSTI/TIOCLINUX) | `setsid` (no controlling tty) + seccomp, low-32-bit compare | `e95_terminal_injection_and_ptrace_denied` |
| ptrace / `process_vm_*` of other processes | seccomp + Yama + separate PID ns | `e95_terminal_injection…` |
| `/proc/<pid>` of host processes | Own PID ns and own procfs | covered by `e93`/`e95` (host processes don't exist inside) |
| Mount tricks, mount propagation back to the host | `MS_PRIVATE` recursive; mount syscalls denied after setup | seccomp table; host unaffected in `e93` |
| Nested user namespaces (kernel bug surface: e.g. nf_tables) | `unshare`/`setns`/`clone(NEWUSER|NEWNS)` denied, `clone3` ENOSYS | seccomp table |
| setuid binaries regaining privilege | `no_new_privs`, bounding set dropped, `nosuid` | — |
| fd leaks across exec | std `Command` is CLOEXEC; bridge fds are opened in the reaper only | — |
| Abstract Unix sockets (X11, D-Bus, …) | Per-netns namespace (empty) + Landlock scope (ABI ≥ 6) | — |
| Kernel attack surface (bpf, perf, userfaultfd, keyctl, modules, kexec) | seccomp deny | seccomp table |
| Fork bomb / memory hog | `RLIMIT_NPROC` (per userns) / `RLIMIT_AS` | `e95_process_and_memory_limits` |
| Runaway / orphaned processes | `PDEATHSIG` chain + PID-ns teardown; wall deadline | `e95_descendants_die_with_launcher`, `e95_wall_deadline` |
| Forged "sandboxed session" | Run token minted outside, injected inside only, revoked at end | `e97_run_token_only_inside_and_gone_after_run` |
| Donor process asked (via a hostile request) to run anything | exec → EPERM (sh, env, copied binary, execveat fd, memfd) | `e96_donor_lockdown_zero_commands_fs_net` |
| Donor reading files outside its state dir / connecting elsewhere | Landlock FS + net (TSYNC) | `e96_donor…` |
| Parser compromise opening files or sockets | Validator allowlist → SIGSYS | `e96_validator_parses_but_cannot_open_files_or_sockets` |
| macOS: launchd/XPC services, LaunchServices `open`, Apple Events, keychain | `(deny default)`, `mach-lookup` denied, no `appleevent-send`, donor `process-exec*`/`process-fork` denied | integrator to verify on a real Mac |

## 5. Platform matrix

| | Linux | macOS | Windows |
|---|---|---|---|
| `Spec::run` | Implemented and tested here (kernel 7.0, Landlock ABI 8) | `sandbox-exec` + generated profile; compiles (`aarch64-apple-darwin`), **untested** | Fails closed (`Unsupported`) |
| `lockdown_self` | seccomp TSYNC + Landlock TSYNC; tested | `sandbox_init` profile; untested | — |
| `spawn_validator` | fork + allowlist; tested | fork + `sandbox_init` `(deny default)`; untested | — |

`sandbox-exec` and `sandbox_init` are deprecated by Apple but remain the only third-party
Seatbelt entry points; Codex and sandbox-runtime use them too.

## 6. Not done yet

- `--allow-host` CONNECT-proxy allowlist (off by default per §15.1).
- cgroup v2 limits when a delegated cgroup exists. rlimits are the floor today.
- Landlock ABI 9/10 rules (pathname Unix sockets, UDP bind) once the crate ceiling allows.
- Linked git worktrees (gitdir outside the view): mo-node must add the gitdir with hooks
  and config protected.
- A fuzz target for the seccomp tables and the mask glob (contract: "reviewed and fuzzed").
