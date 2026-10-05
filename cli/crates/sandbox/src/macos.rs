//! macOS side (CONTRACT §15.1 / §15.2): Seatbelt profiles.
//!
//! - Maintainer `moochy run` ([`run`]): generate a deny-by-default SBPL profile
//!   per run and exec the command under `sandbox-exec -p <profile>`.
//! - Donor self-lockdown ([`crate::lockdown_self`]) and the validator child
//!   ([`crate::spawn_validator`]) apply a profile to the current/forked process
//!   via `sandbox_init(3)` (the supported self-sandboxing entry point; the public
//!   `sandbox-exec` wraps the same libsandbox).
//!
//! `sandbox-exec`/`sandbox_init` are marked deprecated by Apple but remain the
//! mechanism every coding-agent CLI uses on macOS; there is no non-deprecated
//! public replacement for third-party self-sandboxing. We keep the profiles
//! tight and documented. See DESIGN.md.
//!
//! Known Seatbelt limits we rely on the profile (not the kernel) to cover:
//! services reached over `mach-lookup` (launchd/XPC, the keychain via
//! `com.apple.SecurityServer`) run outside the sandbox, so we deny `mach-lookup`
//! by default and `process-exec*`/`process-fork` on the donor side.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use crate::macos_profile::{donor_profile, maintainer_profile};
use crate::{DonorPolicy, Error, LockdownReport, Spec, Validator, mask};

fn setup(what: &'static str, err: std::io::Error) -> Error {
    Error::Setup { what, err }
}

/// CONTRACT §15.1 entry point (macOS).
pub fn run(spec: &Spec, program: &std::ffi::OsStr, args: &[OsString]) -> Result<i32, Error> {
    if spec.unsafe_no_sandbox {
        eprintln!("moochy: WARNING --unsafe-no-sandbox: running WITHOUT a sandbox (debugging only).");
        let mut cmd = Command::new(program);
        cmd.args(args).current_dir(&spec.worktree);
        apply_env(&mut cmd, spec, Path::new("/tmp"), &spec.worktree, None);
        return Ok(code(cmd.status().map_err(Error::Exec)?));
    }
    let worktree = spec
        .worktree
        .canonicalize()
        .map_err(|e| setup("canonicalize worktree", e))?;
    let scan = mask::scan_kept(&worktree, spec.mask_record.as_deref())?;
    crate::mask::notice_frozen(scan.masks.len());
    // G39: Seatbelt has no process cap, RLIMIT_NPROC is per user and RLIMIT_AS is not enforced.
    let d = crate::Limits::default();
    if spec.limits.processes != d.processes || spec.limits.memory_bytes != d.memory_bytes {
        eprintln!("moochy: note: the process and memory limits are not enforced on macOS");
    }
    let git_before = crate::git::snapshot(&scan.dotgits);
    // A private scratch dir per run: the shared /tmp and the per-user
    // /var/folders stay out of reach (other apps' files live there).
    let scratch = make_scratch()?;
    let home = scratch.join("home");
    std::fs::create_dir(&home).map_err(|e| setup("create scratch home", e))?;
    // `--allow-host`: the proxy on an ephemeral loopback port, the only one
    // besides the gateway the profile lets the agent reach.
    let proxy = if spec.allow_hosts.is_empty() {
        None
    } else {
        let allow = crate::proxy::Allowlist::new(&spec.allow_hosts);
        match allow.and_then(crate::proxy::Proxy::bind_loopback) {
            Ok(p) => Some(p),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&scratch);
                return Err(e);
            }
        }
    };
    let proxy_port = proxy.as_ref().and_then(crate::proxy::Proxy::port);
    // G23: the run's own terminal, the only one the profile opens.
    let ttys: Vec<std::path::PathBuf> = (0..3).filter_map(crate::sys_macos::ttyname).collect();
    let profile = maintainer_profile(spec, &worktree, &scan.masks, &scratch, proxy_port, &ttys);
    let profile = match profile {
        Ok(p) => p,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&scratch);
            return Err(e);
        }
    };

    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-p").arg(&profile).arg("--").arg(program).args(args);
    cmd.current_dir(&worktree);
    cmd.env_clear();
    apply_env(&mut cmd, spec, &scratch, &home, proxy_port);
    // Own session (no controlling terminal: no TIOCSTI into the user's shell,
    // A192) + rlimits, set between fork and exec.
    crate::sys_macos::session_and_limits(&mut cmd, &spec.limits);
    let status = supervise(&mut cmd, spec.limits.wall_seconds);
    drop(proxy);
    let _ = std::fs::remove_dir_all(&scratch);
    crate::git::notice_if_changed(&worktree, &git_before);
    status
}

/// Run `cmd` (a session leader), forwarding terminal signals to its process
/// group, enforcing the wall deadline (exit 124), and killing whatever is left
/// in the group when it exits (A198). A descendant that starts its own session
/// escapes the group: macOS has no PID namespace (residual, DESIGN.md).
fn supervise(cmd: &mut Command, wall_seconds: u64) -> Result<i32, Error> {
    use std::time::{Duration, Instant};
    let mut child = cmd.spawn().map_err(Error::Exec)?;
    let pgid = i32::try_from(child.id()).unwrap_or(0);
    let fwd = crate::sys_macos::forward_signals(pgid);
    let deadline = Instant::now().checked_add(Duration::from_secs(wall_seconds)).filter(|_| wall_seconds > 0);
    let result = loop {
        let Some(d) = deadline else { break child.wait().map(code).map_err(Error::Exec) };
        match child.try_wait() {
            Ok(Some(s)) => break Ok(code(s)),
            Ok(None) if Instant::now() >= d => {
                crate::sys_macos::killpg(pgid);
                let _ = child.wait();
                break Ok(WALL_TIMEOUT_EXIT);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => break Err(Error::Exec(e)),
        }
    };
    drop(fwd);
    crate::sys_macos::killpg(pgid);
    result
}

/// Exit code when the wall-clock deadline kills the run (as `timeout(1)`).
const WALL_TIMEOUT_EXIT: i32 = 124;

fn make_scratch() -> Result<std::path::PathBuf, Error> {
    use std::os::unix::fs::DirBuilderExt as _;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dir = std::env::temp_dir().join(format!("moochy-run-{}-{nanos}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| setup("create scratch dir", e))?;
    dir.canonicalize().map_err(|e| setup("canonicalize scratch dir", e))
}

fn apply_env(cmd: &mut Command, spec: &Spec, scratch: &Path, home: &Path, proxy_port: Option<u16>) {
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    // A private home in the scratch dir: tools' creds/history never land in
    // the repo (A198), and the real home stays out of reach.
    cmd.env("HOME", home);
    cmd.env("TMPDIR", scratch);
    if let Some(port) = proxy_port {
        let url = format!("http://127.0.0.1:{port}");
        for k in ["HTTPS_PROXY", "https_proxy"] {
            cmd.env(k, &url);
        }
        for k in ["NO_PROXY", "no_proxy"] {
            cmd.env(k, "127.0.0.1,localhost");
        }
    }
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    if let Some(tok) = &spec.run_token {
        cmd.env(crate::RUN_TOKEN_ENV, tok);
    }
}

fn code(s: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    s.code()
        .unwrap_or_else(|| s.signal().map_or(-1, |sig| 128i32.saturating_add(sig)))
}

/// Apply a Seatbelt profile to the current process via `sandbox_init(3)`.
/// Irreversible. CONTRACT §15.2a (macOS).
pub fn lockdown_self(policy: &DonorPolicy) -> Result<LockdownReport, Error> {
    if policy.unsafe_no_lockdown {
        eprintln!("moochy: WARNING --unsafe-no-lockdown: the background process is NOT sandboxed.");
        return Ok(LockdownReport::default());
    }
    let profile = donor_profile(policy);
    crate::sys_macos::apply_profile(&profile).map_err(|e| setup("sandbox_init", e))?;
    Ok(LockdownReport {
        seccomp: false,
        landlock_fs: true, // Seatbelt FS cage applied
        landlock_net: Some(true),
        no_new_privs: true,
        all_threads: true, // Seatbelt applies to the whole process
        abi: 0,
    })
}

/// Validator child (§15.2b) on macOS: fork, apply a no-filesystem, no-network,
/// no-exec Seatbelt profile, then run the caller's parser over the socketpair.
pub fn spawn_validator<F>(run: F) -> Result<Validator, Error>
where
    F: FnOnce(std::os::unix::io::RawFd) -> i32 + Send,
{
    use std::os::unix::io::AsRawFd as _;
    let (parent_sock, child_sock) =
        std::os::unix::net::UnixStream::pair().map_err(|e| setup("socketpair", e))?;
    let child_fd = child_sock.as_raw_fd();
    match crate::sys_macos::fork().map_err(|e| setup("fork", e))? {
        crate::sys_macos::Fork::Parent(pid) => {
            drop(child_sock);
            Ok(Validator {
                sock: parent_sock,
                child_pid: pid,
            })
        }
        crate::sys_macos::Fork::Child => {
            drop(parent_sock);
            // Drop every inherited fd first; only the channel survives (fd 3).
            let code = if crate::sys_macos::isolate_fds(child_fd).is_err() {
                71
            } else {
                // A zygote already caged by ZYGOTE_PROFILE cannot stack a second profile
                // (macOS refuses nested sandbox_init): the child inherits that cage and
                // loses fork + CPU with rlimits instead (A219).
                let caged = if ZYGOTE_CAGED.load(std::sync::atomic::Ordering::Relaxed) {
                    crate::sys_macos::limit_validator_child().is_ok()
                } else {
                    crate::sys_macos::apply_profile(VALIDATOR_PROFILE).is_ok()
                        && crate::sys_macos::limit_validator_child().is_ok()
                };
                if caged { run(crate::sys_macos::CHANNEL_FD) } else { 71 }
            };
            crate::sys_macos::exit_immediately(code);
        }
    }
}

const VALIDATOR_PROFILE: &str = "(version 1)\n(deny default)\n(deny process-exec*)\n(deny process-fork)\n(deny file*)\n(deny network*)\n";

/// The validator zygote's cage (macOS): the validator profile, except that it may fork its
/// single-use children (each then drops fork with rlimits), make their socketpairs, and
/// open `/dev/null` (each child points its stdio there before running).
const ZYGOTE_PROFILE: &str = "(version 1)\n(deny default)\n(allow process-fork)\n(allow system-socket (socket-domain AF_UNIX))\n(deny process-exec*)\n(deny file*)\n(deny network*)\n(allow file-read* file-write* (literal \"/dev/null\"))\n";

static ZYGOTE_CAGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Cage the validator zygote (§15.2b, macOS): no files, no network, no exec, fork allowed.
pub fn lockdown_zygote() -> Result<(), Error> {
    crate::sys_macos::apply_profile(ZYGOTE_PROFILE).map_err(|e| setup("sandbox_init (zygote)", e))?;
    ZYGOTE_CAGED.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}
