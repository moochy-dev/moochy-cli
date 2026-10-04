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
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

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
    let scan = mask::scan(&worktree)?;
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
    let profile = maintainer_profile(spec, &worktree, &scan.masks, &scratch, proxy_port);
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

/// Seatbelt matches resolved paths (`/var` is `/private/var`, `/tmp` is
/// `/private/tmp`): every path in a profile goes through here first.
fn real(p: &Path) -> String {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf()).to_string_lossy().into_owned()
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

/// Deny-by-default maintainer profile: read system paths, read-write the
/// worktree + scratch, deny the masked secret files explicitly, network only to
/// the gateway loopback port, no exec of setuid helpers, no mach services.
pub fn maintainer_profile(
    spec: &Spec,
    worktree: &Path,
    masks: &[std::path::PathBuf],
    scratch: &Path,
    proxy_port: Option<u16>,
) -> Result<String, Error> {
    let wt = sbpl_quote(&worktree.to_string_lossy());
    let wt_re = regex_escape(&worktree.to_string_lossy())
        .ok_or(Error::Unsupported("worktree path has characters the macOS profile cannot express"))?;
    let mut p = String::new();
    // Rules are matched last-wins: `deny default` first, allows after, the
    // secret masks last so they beat the worktree allow.
    p.push_str("(version 1)\n(deny default)\n");
    // Diagnostics off; we never want the sandbox to prompt.
    p.push_str("(deny file-write* file-read* (with no-report))\n");
    // An agent runs tools: it may fork and exec, and signal its own processes only.
    p.push_str("(allow process-fork)\n");
    p.push_str("(allow signal (target same-sandbox))\n");
    p.push_str("(allow sysctl-read)\n");
    p.push_str("(allow file-read-metadata)\n");
    // System paths (and dyld): read + exec.
    p.push_str("(allow process-exec* file-read* (regex #\"^/(usr|bin|sbin|opt|System|Library|Applications)/\"))\n");
    // F23: not the package managers' own data and config (Homebrew, MacPorts): user-owned
    // local databases and service configs live there. Their CA bundles stay readable.
    p.push_str(HOMEBREW_DATA_DENY);
    p.push_str("(allow file-read* (regex #\"^/(private/etc|private/var/db|etc)/\") (literal \"/\") (literal \"/private\"))\n");
    // Basic devices and the terminal (interactive agents).
    p.push_str("(allow file-read* file-write* file-ioctl (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/tty\") (regex #\"^/dev/ttys[0-9]+$\") (literal \"/dev/dtracehelper\"))\n");
    p.push_str("(allow file-read* (literal \"/dev/random\") (literal \"/dev/urandom\"))\n");
    // getpwuid() etc.; every other mach service (keychain, pasteboard, launchd
    // services, Apple Events) stays denied.
    p.push_str("(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n");
    // Tool directories the caller allows (read + exec), worktree read-write, scratch.
    for ro in &spec.ro_paths {
        let _ = writeln!(p, "(allow process-exec* file-read* (subpath {}))", sbpl_quote(&real(ro)));
    }
    let _ = writeln!(p, "(allow process-exec* file-read* file-write* (subpath {wt}))");
    let _ = writeln!(p, "(allow file-read* file-write* (subpath {}))", sbpl_quote(&real(scratch)));
    for p2 in &spec.rw_paths {
        let _ = writeln!(p, "(allow file-read* file-write* (subpath {}))", sbpl_quote(&real(p2)));
    }
    // Network: the gateway only (loopback port and/or its Unix socket).
    for port in spec.gateway_loopback_port.into_iter().chain(proxy_port) {
        let _ = writeln!(p, "(allow network-outbound (remote ip \"localhost:{port}\"))");
    }
    if let Some(sock) = &spec.gateway_socket {
        let q = sbpl_quote(&real(sock));
        let _ = writeln!(p, "(allow network-outbound (remote unix-socket (path-literal {q})))");
        let _ = writeln!(p, "(allow file-read* file-write* (literal {q}))");
    }
    // Mask secret-shaped / git-ignored files last: they beat every allow above. A deny is a
    // path, fixed at start: renaming a directory above a mask would move the secret out from
    // under it (F03), so no directory between the worktree and a mask may be renamed or removed.
    let mut ancestors = std::collections::BTreeSet::new();
    for m in masks {
        let _ = writeln!(p, "(deny file-read* file-write* process-exec* (subpath {}))", sbpl_quote(&m.to_string_lossy()));
        ancestors.extend(mask::ancestors_below(worktree, m));
    }
    for a in ancestors {
        let _ = writeln!(p, "(deny file-write-unlink (literal {}))", sbpl_quote(&a.to_string_lossy()));
    }
    // Git metadata the host's git later trusts (A191): no write to any `.git`
    // at any depth — which also blocks creating one (`git init`, a nested repo).
    // `git_writable` reopens the top-level one except the files that make the
    // host run code or redirect.
    let git_re = "\\.[gG][iI][tT]";
    if spec.git_writable {
        let _ = writeln!(p, "(deny file-write* (regex #\"^{wt_re}/.+/{git_re}(/|$)\"))");
        let _ = writeln!(
            p,
            "(deny file-write* (regex #\"^{wt_re}/{git_re}/(hooks|config|config\\.worktree|modules|commondir)(/|$)\"))"
        );
    } else {
        let _ = writeln!(p, "(deny file-write* (regex #\"^{wt_re}/(.+/)?{git_re}(/|$)\"))");
    }
    Ok(p)
}

const HOMEBREW_DATA_DENY: &str = "(deny file-read* file-write* process-exec* (regex #\"^/(opt/homebrew|opt/local|usr/local)/(var|etc)(/|$)\"))\n\
    (allow file-read* (regex #\"^/(opt/homebrew|opt/local|usr/local)/etc/(openssl[^/]*|ca-certificates)/\"))\n";

/// A path as a literal inside an SBPL `#"…"` regex; `None` for characters we
/// can't express safely there (quote, backslash, control).
fn regex_escape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len().saturating_mul(2));
    for c in s.chars() {
        if c == '"' || c == '\\' || c.is_control() {
            return None;
        }
        if ".^$*+?()[]{}|".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    Some(out)
}

/// Donor self-lockdown profile (§15.2a): deny process-exec/process-fork, limit
/// files to the state dir (rw) + CA roots (ro), network outbound to 443 + relay
/// (+ loopback gateway bind).
pub fn donor_profile(policy: &DonorPolicy) -> String {
    let state = sbpl_quote(&real(&policy.state_dir));
    let mut p = String::new();
    p.push_str("(version 1)\n(deny default)\n");
    p.push_str("(deny process-exec*)\n(deny process-fork)\n");
    let _ = writeln!(p, "(allow file-read* file-write* (subpath {state}))");
    for ro in &policy.ro_paths {
        let _ = writeln!(p, "(allow file-read* (subpath {}))", sbpl_quote(&real(ro)));
    }
    p.push_str("(allow file-read* (regex #\"^/(usr/lib|System/Library)/\"))\n");
    // Name resolution for provider hosts: getaddrinfo goes through libinfo and
    // mDNSResponder (mach service + its Unix socket) and reads /etc/hosts.
    p.push_str("(allow mach-lookup (global-name \"com.apple.dnssd.service\") (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n");
    p.push_str("(allow network-outbound (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))\n");
    p.push_str("(allow file-read-metadata)\n");
    p.push_str("(allow file-read* (literal \"/private/etc/hosts\") (literal \"/private/etc/resolv.conf\") (literal \"/private/var/run/resolv.conf\") (literal \"/Library/Preferences/com.apple.networkd.plist\"))\n");
    p.push_str("(allow sysctl-read)\n");
    let _ = writeln!(p, 
        "(allow network-outbound (remote tcp \"*:443\") (remote tcp \"*:{}\"))",
        policy.relay_port
    );
    // Dev/e2e only: fake providers on loopback ports (empty in production).
    for port in &policy.connect_ports {
        let _ = writeln!(p, "(allow network-outbound (remote tcp \"*:{port}\"))");
    }
    if let Some(gw) = policy.gateway_port {
        let _ = writeln!(p, 
            "(allow network-inbound (local tcp \"localhost:{gw}\"))"
        );
    }
    p
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

/// SBPL string literal with escaping of `"` and `\`.
fn sbpl_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn package_manager_data_is_not_a_system_path() {
        let wt = std::env::temp_dir();
        let p = super::maintainer_profile(&crate::Spec::new(wt.clone()), &wt, &[], &wt, None).unwrap();
        let (sys, deny) = (p.find("(usr|bin|sbin|opt|").unwrap(), p.find(super::HOMEBREW_DATA_DENY).unwrap());
        assert!(deny > sys, "F23: the deny follows (beats) the system-path allow");
    }
}
