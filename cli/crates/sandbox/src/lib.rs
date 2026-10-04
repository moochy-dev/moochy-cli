//! `moochy-sandbox` — the maintainer-side `moochy run` jail and the donor-side
//! Worker privilege separation (CONTRACT §15).
//!
//! No Docker, no daemon: the sandbox is built from OS primitives (Linux user +
//! mount + PID + net + IPC + UTS namespaces, `pivot_root`, Landlock, seccomp-bpf,
//! `no_new_privs`, rlimits; macOS Seatbelt). It **fails closed**: if the jail
//! cannot be established, [`Spec::run`] returns an error and never runs the command
//! unsandboxed.
//!
//! Three entry points:
//! - [`Spec`] + [`Spec::run`] — maintainer side (§15.1): run a command (the coding
//!   agent and everything it spawns) inside the jail.
//! - [`lockdown_self`] — donor side (§15.2a): the donor process locks *itself*
//!   irreversibly after start-up — kernel-enforced "zero commands on donors"
//!   (no `execve`), plus a Landlock FS/net cage.
//! - [`spawn_validator`] — donor side (§15.2b): a single-use child with no FS, no
//!   network and no keys, where the only hostile-byte parsing runs. The parent
//!   (mo-worker's `validate`) talks to it over a socketpair.
//!
//! See `API.md`. The only `unsafe` in the crate lives in [`sys`] (CONTRACT §15
//! exception).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod donor;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod doctor;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use doctor::doctor;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod git;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mask;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod proxy;
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod fuzzing;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod sys_macos;

/// A fully-specified sandbox. Build it, then [`run`](Spec::run) a command inside.
///
/// Every field has a safe default (deny). The integrator fills in the worktree,
/// the gateway bridge, and any extra read-only roots the tools need.
#[derive(Clone, Debug)]
pub struct Spec {
    /// The one read-write project directory (the git worktree). Required.
    pub worktree: PathBuf,
    /// Extra read-only paths made visible inside (tool binaries, runtimes).
    /// Defaults cover the usual system dirs; add language toolchains here.
    pub ro_paths: Vec<PathBuf>,
    /// Extra read-write paths (rare; e.g. a shared cache). Empty by default.
    pub rw_paths: Vec<PathBuf>,
    /// Gateway Unix socket on the host, bind-mounted read-write inside at
    /// [`GATEWAY_SOCK_PATH`]. `None` = no gateway access.
    pub gateway_socket: Option<PathBuf>,
    /// If set, run a loopback TCP listener on `127.0.0.1:<port>` *inside* the
    /// sandbox netns that forwards to [`gateway_socket`](Spec::gateway_socket),
    /// so agents that only speak host:port reach the gateway. Requires
    /// `gateway_socket`.
    pub gateway_loopback_port: Option<u16>,
    /// Environment passed to the command. The parent environment is NOT
    /// inherited; only these plus a minimal safe base (`PATH`, `TERM`, ...).
    pub env: BTreeMap<OsString, OsString>,
    /// Working directory inside the sandbox. Defaults to the worktree root.
    pub cwd: Option<PathBuf>,
    /// Per-run gateway token (§15.4). Minted by the parent (mo-node), injected
    /// into the sandbox env as [`RUN_TOKEN_ENV`] and nowhere else, registered
    /// with the gateway over the local control socket and revoked when the run
    /// ends. The agent inside cannot forge it for an unsandboxed process outside
    /// because it never leaves the sandbox env. `None` = inject nothing.
    pub run_token: Option<String>,
    /// `--allow-host`: exact host names the agent may reach on :443 through the
    /// launcher's CONNECT proxy (`HTTPS_PROXY` inside). Empty (default) = no
    /// proxy, no network but the gateway. Linux: `127.0.0.1:3128` inside the
    /// netns; macOS: an ephemeral loopback port the profile allows.
    pub allow_hosts: Vec<String>,
    /// Directories no visible path may be or contain (A197): a worktree, `ro_paths`
    /// or `rw_paths` entry that is `/` or an ancestor of one of these is
    /// refused. Default: the real `$HOME` and the Moochy home wherever
    /// `moochy` would put it (`$MOOCHY_HOME`, `$XDG_CONFIG_HOME/moochy`,
    /// `~/.config/moochy`); a `--home` elsewhere must be pushed by the caller.
    pub protected: Vec<PathBuf>,
    /// Resource limits. Defaults are generous but finite (fork-bomb / OOM safe).
    pub limits: Limits,
    /// Let the agent write `.git` (commit inside). `hooks/`, `config` and
    /// `modules/` stay read-only, but a created `.git/commondir` would redirect
    /// the host's git to agent-written config (DESIGN.md). Default `false`:
    /// `.git` is read-only inside. Linked worktrees are always read-only.
    pub git_writable: bool,
    /// File keeping this worktree's masked inodes from one run to the next (F09): a file
    /// masked once stays masked after an agent edits a `.gitignore` or renames its directory.
    /// Must be out of the agent's reach. `None` = masks come from this run's tree only.
    pub mask_record: Option<PathBuf>,
    /// Escape hatch for debugging only. When true, [`run`](Spec::run) executes
    /// the command with NO sandbox after printing a loud warning to stderr.
    pub unsafe_no_sandbox: bool,
}

/// Resource limits applied with `setrlimit` (and cgroup v2 when delegated).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Max address space per process, bytes (`RLIMIT_AS`). 0 = unlimited.
    pub memory_bytes: u64,
    /// Max CPU seconds (`RLIMIT_CPU`). 0 = unlimited.
    pub cpu_seconds: u64,
    /// Max open files (`RLIMIT_NOFILE`).
    pub open_files: u64,
    /// Max processes/threads for this user inside the userns (`RLIMIT_NPROC`;
    /// also the sandbox-wide cgroup `pids.max`).
    pub processes: u64,
    /// Memory for the whole sandbox, bytes (cgroup `memory.max`, swap 0). 0 =
    /// no cgroup memory limit (`memory_bytes` still caps each process).
    pub memory_total_bytes: u64,
    /// CPU for the whole sandbox in percent of one CPU (cgroup `cpu.max`; 250 =
    /// 2.5 CPUs). 0 = unlimited.
    pub cpu_percent: u32,
    /// Max core dump size (`RLIMIT_CORE`); 0 disables cores.
    pub core_bytes: u64,
    /// Wall-clock deadline for the whole run, seconds. 0 = no deadline. On
    /// expiry the whole sandbox is killed and `run` returns 124.
    pub wall_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_bytes: 4 << 30, // 4 GiB
            cpu_seconds: 0,
            open_files: 1024,
            processes: 512,
            memory_total_bytes: 0,
            cpu_percent: 0,
            core_bytes: 0,
            wall_seconds: 0,
        }
    }
}

/// Path at which [`Spec::gateway_socket`] is exposed inside the sandbox.
pub const GATEWAY_SOCK_PATH: &str = "/run/moochy/gateway.sock";

/// Loopback port of the `--allow-host` proxy inside the sandbox.
pub const PROXY_LOOPBACK_PORT: u16 = 3128;

/// Path of the `--allow-host` proxy socket inside the sandbox.
pub const PROXY_SOCK_PATH: &str = "/run/moochy/proxy.sock";

/// Environment variable carrying [`Spec::run_token`] inside the sandbox.
pub const RUN_TOKEN_ENV: &str = "MOOCHY_RUN_TOKEN";

/// Mint a fresh 256-bit run token (64 hex chars) from the OS CSPRNG. Fails
/// closed: no randomness, no token (never a predictable fallback).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn mint_run_token() -> std::io::Result<String> {
    use std::io::Read as _;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(hex(&buf))
}

/// Lowercase hex.
pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

impl Spec {
    /// A deny-by-default spec for a given worktree. Add `ro_paths` for toolchains.
    #[must_use]
    pub fn new(worktree: PathBuf) -> Self {
        Self {
            worktree,
            ro_paths: default_ro_paths(),
            rw_paths: Vec::new(),
            gateway_socket: None,
            gateway_loopback_port: None,
            env: BTreeMap::new(),
            cwd: None,
            run_token: None,
            git_writable: false,
            mask_record: None,
            allow_hosts: Vec::new(),
            protected: default_protected(),
            limits: Limits::default(),
            unsafe_no_sandbox: false,
        }
    }

    /// Run `program` with `args` inside the sandbox, inheriting the current
    /// stdio. Blocks until the command (and everything it spawned) exits.
    /// Returns the command's exit code (or 128 + signal).
    ///
    /// Fails closed: any setup error aborts before the command runs.
    pub fn run(&self, program: &std::ffi::OsStr, args: &[OsString]) -> Result<i32, Error> {
        if self.gateway_loopback_port.is_some() && self.gateway_socket.is_none() {
            return Err(Error::Unsupported("gateway_loopback_port requires gateway_socket"));
        }
        if !self.unsafe_no_sandbox {
            self.check_exposure()?;
        }
        if !self.allow_hosts.is_empty() {
            if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
                return Err(Error::Unsupported("--allow-host is implemented only on Linux and macOS"));
            }
            if cfg!(target_os = "linux") && self.gateway_loopback_port == Some(PROXY_LOOPBACK_PORT) {
                return Err(Error::Unsupported("gateway_loopback_port collides with the --allow-host proxy port"));
            }
        }
        #[cfg(target_os = "linux")]
        {
            linux::run(self, program, args)
        }
        #[cfg(target_os = "macos")]
        {
            macos::run(self, program, args)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (program, args);
            Err(Error::Unsupported(
                "sandboxing is implemented only on Linux and macOS (Windows: later phase)",
            ))
        }
    }
}

impl Spec {
    /// A197: refuse a view that would expose `/`, the real home or the Moochy
    /// home (keystore, run key, other repos) inside the sandbox.
    fn check_exposure(&self) -> Result<(), Error> {
        let protected: Vec<PathBuf> = self.protected.iter().filter_map(|p| p.canonicalize().ok()).collect();
        let visible = std::iter::once(&self.worktree).chain(&self.rw_paths).chain(&self.ro_paths);
        for p in visible.filter_map(|p| p.canonicalize().ok()) {
            let hit = if p.parent().is_none() { Some(p.clone()) } else { protected.iter().find(|q| q.starts_with(&p)).cloned() };
            if let Some(q) = hit {
                return Err(Error::Setup {
                    what: "sandbox view check",
                    err: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("{} would expose {} inside the sandbox; use a project directory", p.display(), q.display()),
                    ),
                });
            }
        }
        Ok(())
    }
}

/// The cgroup v2 directory `Spec::run` would create its per-run cgroup in
/// (`memory.max`, `pids.max`, `cpu.max`, `cgroup.kill` at the end), or `None`
/// when no delegated cgroup is available and rlimits are the only limits. For
/// `moochy doctor`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn delegated_cgroup() -> Option<PathBuf> {
    cgroup::delegated_parent()
}

/// `$HOME` and every default location of the Moochy home (mirrors the node's
/// `Home::resolve`). Nonexistent entries are harmless (skipped by the check).
fn default_protected() -> Vec<PathBuf> {
    let env = |k| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let home = env("HOME");
    [
        home.clone(),
        env("MOOCHY_HOME"),
        env("XDG_CONFIG_HOME").map(|x| x.join("moochy")),
        home.map(|h| h.join(".config/moochy")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Default read-only system roots. These exist on virtually every Unix host and
/// carry no user secrets. The integrator appends language toolchains.
fn default_ro_paths() -> Vec<PathBuf> {
    ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"]
        .iter()
        .map(PathBuf::from)
        .collect()
}

// ───────────────────────── Donor side (CONTRACT §15.2) ─────────────────────────

/// Policy for [`lockdown_self`]: what the donor process may still touch after it
/// locks itself. Everything not listed is denied.
#[derive(Clone, Debug)]
pub struct DonorPolicy {
    /// The donor's state directory (outbox, served-task set): read-write.
    pub state_dir: PathBuf,
    /// Read-only files still needed after lockdown: CA roots, the donor's own
    /// binary. Nothing else on the filesystem is reachable.
    pub ro_paths: Vec<PathBuf>,
    /// The relay port the donor connects to. Outbound TCP is allowed only to
    /// this port and 443 (providers), where Landlock network (ABI ≥ 4) exists.
    pub relay_port: u16,
    /// Extra outbound TCP ports (default empty). For dev/e2e only: fake
    /// providers on loopback ports (`--base-url`, `MOOCHY_INSECURE_DEV=1`).
    /// Production leaves it empty.
    pub connect_ports: Vec<u16>,
    /// The loopback gateway port this process binds (§15.4). `None` = no bind
    /// allowed (donor-only machine with no local gateway door).
    pub gateway_port: Option<u16>,
    /// Debug escape hatch: skip the lockdown after a loud warning. Never in prod.
    pub unsafe_no_lockdown: bool,
}

impl DonorPolicy {
    #[must_use]
    pub fn new(state_dir: PathBuf, relay_port: u16) -> Self {
        Self {
            state_dir,
            ro_paths: default_donor_ro_paths(),
            relay_port,
            connect_ports: Vec::new(),
            gateway_port: None,
            unsafe_no_lockdown: false,
        }
    }
}

/// What the lockdown actually achieved on this OS/kernel, for `moochy doctor`
/// and the final report. Each layer records whether it was applied.
#[derive(Clone, Debug, Default)]
pub struct LockdownReport {
    pub no_new_privs: bool,
    pub seccomp: bool,
    pub landlock_fs: bool,
    /// `None` = network restriction unavailable on this kernel (ABI < 4): the
    /// deployment must rely on the systemd/launchd `RestrictAddressFamilies`
    /// hardening instead (§15.2 "bounded worst case").
    pub landlock_net: Option<bool>,
    /// The Landlock domain covers every thread (TSYNC, ABI ≥ 8), or the process
    /// was single-threaded when it locked itself. `lockdown_self` refuses
    /// otherwise, so in a successful report this is always true.
    pub all_threads: bool,
    pub abi: i32,
}

/// Lock the **current** process down irreversibly (CONTRACT §15.2a). On Linux:
/// kernel-enforced "zero commands" (`execve`/`execveat` denied), no `ptrace`,
/// `mount`, `bpf`, `keyctl`, `perf_event_open`, `userfaultfd`, namespace or
/// module syscalls; `no_new_privs`; a Landlock FS cage (state dir rw, `ro_paths`
/// ro, nothing else) and, where supported, a Landlock network cage (TCP connect
/// to 443 and the relay port only; bind the loopback gateway port). On macOS:
/// a Seatbelt profile (`sandbox_init`) denying `process-exec*`/`process-fork`
/// and limiting files and network the same way.
///
/// Call this once, after keys are loaded, config is read and connections are
/// open. It affects the whole process and cannot be undone. On Linux prefer to
/// call it while single-threaded (before the async runtime starts) so the TSYNC
/// paths cover every thread deterministically. Fails closed with a precise
/// reason unless [`DonorPolicy::unsafe_no_lockdown`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn lockdown_self(policy: &DonorPolicy) -> Result<LockdownReport, Error> {
    #[cfg(target_os = "linux")]
    {
        donor::lockdown_self(policy)
    }
    #[cfg(target_os = "macos")]
    {
        macos::lockdown_self(policy)
    }
}

/// Cage the process that forks validator children (the "zygote", CONTRACT §15.2b). Linux:
/// the donor lockdown with `policy`. macOS: one Seatbelt profile with no files, network or
/// exec but fork allowed, because macOS cannot stack a stricter profile in each child (A219).
pub fn lockdown_zygote(policy: &DonorPolicy) -> Result<LockdownReport, Error> {
    #[cfg(target_os = "linux")]
    {
        donor::lockdown_self(policy)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = policy;
        macos::lockdown_zygote().map(|()| LockdownReport { landlock_fs: true, landlock_net: Some(true), no_new_privs: true, all_threads: true, ..LockdownReport::default() })
    }
}

/// A single-use validator child (CONTRACT §15.2b): no filesystem, no network, no
/// keys, a seccomp allowlist (Linux) / `(deny default)` Seatbelt (macOS) and
/// tight rlimits. The only place a stranger's bytes are parsed.
///
/// Pre-spawn one so there is no latency on the hot path; use it for exactly one
/// request, then spawn a replacement. The in-child work is supplied by the
/// caller (mo-worker's `worker::validate`) via [`spawn_validator`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct Validator {
    /// The parent end of the socketpair to the child.
    pub sock: std::os::unix::net::UnixStream,
    pub(crate) child_pid: i32,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Validator {
    /// Wait for the validator child to exit; returns its exit code.
    pub fn wait(self) -> Result<i32, Error> {
        #[cfg(target_os = "linux")]
        {
            donor::wait_raw(self.child_pid)
        }
        #[cfg(target_os = "macos")]
        {
            sys_macos::wait_raw(self.child_pid).map_err(Error::Exec)
        }
    }

    /// The child's pid (for `kill`/diagnostics).
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.child_pid
    }
}

/// Spawn a [`Validator`] child. `run` executes inside the jailed child with the
/// child end of the socketpair as its only channel; its return value is the
/// child's exit code. `run` must not touch the filesystem or network — the
/// sandbox kills the process if it tries. Every other inherited fd is closed in
/// the child first; `run` receives [`sys`]'s channel fd (3).
///
/// **Never call this from a process that holds secrets**: `fork` copies the
/// caller's memory (provider key, device keys) into the child, where a parser
/// exploit could smuggle them into its output. Fork validators from a key-less
/// zygote started before any secret is loaded (see API.md §2.2).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn spawn_validator<F>(run: F) -> Result<Validator, Error>
where
    F: FnOnce(std::os::unix::io::RawFd) -> i32 + Send,
{
    #[cfg(target_os = "linux")]
    {
        donor::spawn_validator(run)
    }
    #[cfg(target_os = "macos")]
    {
        macos::spawn_validator(run)
    }
}

/// [`spawn_validator`] for safe callers: `run` gets the channel as an owned
/// `UnixStream` (no `unsafe` needed in node/worker). Every other fd the parent
/// held is closed in the child before the sandbox is applied.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn spawn_validator_with<F>(run: F) -> Result<Validator, Error>
where
    F: FnOnce(std::os::unix::net::UnixStream) -> i32 + Send,
{
    spawn_validator(move |_channel_fd| {
        #[cfg(target_os = "linux")]
        let stream = sys::channel_stream();
        #[cfg(target_os = "macos")]
        let stream = sys_macos::channel_stream();
        run(stream)
    })
}

/// Read-only roots a donor still needs after lockdown: the TLS trust store, and
/// name resolution for provider hosts (resolver + NSS config, the
/// systemd-resolved stub dir so a replaced resolv.conf stays readable, the
/// loader cache and lib dirs NSS modules are dlopen'ed from). No user data.
/// The integrator adds its own binary path.
fn default_donor_ro_paths() -> Vec<PathBuf> {
    [
        "/etc/ssl/certs",
        "/etc/pki",
        "/usr/share/ca-certificates",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        "/etc/host.conf",
        "/etc/gai.conf",
        "/etc/resolv.conf",
        "/run/systemd/resolve",
        "/etc/ld.so.cache",
        "/usr/lib",
        "/lib",
        "/usr/lib64",
        "/lib64",
    ]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

/// Everything that can go wrong establishing or running the sandbox. Each
/// variant names the precise reason so `moochy run` can print it and `moochy
/// doctor` can advise a fix.
#[derive(Debug)]
pub enum Error {
    /// A required OS feature is missing or forbidden (with a human reason).
    Unsupported(&'static str),
    /// Unprivileged user namespaces are blocked (e.g. Ubuntu's AppArmor
    /// restriction). Carries the exact fix text for `moochy doctor`.
    UserNsRestricted(String),
    /// An OS call failed during setup.
    Setup { what: &'static str, err: std::io::Error },
    /// The command could not be executed.
    Exec(std::io::Error),
    /// The run exceeded its wall-clock deadline and was killed.
    Timeout,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported(m) => write!(f, "sandbox unsupported: {m}"),
            Error::UserNsRestricted(m) => write!(f, "unprivileged user namespaces restricted: {m}"),
            Error::Setup { what, err } => write!(f, "sandbox setup failed at {what}: {err}"),
            Error::Exec(e) => write!(f, "could not run sandboxed command: {e}"),
            Error::Timeout => write!(f, "sandboxed run exceeded its wall-clock deadline"),
        }
    }
}

impl std::error::Error for Error {}
