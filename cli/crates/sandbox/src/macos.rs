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
        apply_env(&mut cmd, spec);
        return Ok(code(cmd.status().map_err(Error::Exec)?));
    }
    let worktree = spec
        .worktree
        .canonicalize()
        .map_err(|e| setup("canonicalize worktree", e))?;
    let masks = mask::collect(&worktree)?;
    let profile = maintainer_profile(spec, &worktree, &masks);

    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-p").arg(&profile).arg("--").arg(program).args(args);
    cmd.current_dir(&worktree);
    cmd.env_clear();
    apply_env(&mut cmd, spec);
    let status = cmd.status().map_err(Error::Exec)?;
    Ok(code(status))
}

fn apply_env(cmd: &mut Command, spec: &Spec) {
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.env("HOME", &spec.worktree); // no access to the real home
    cmd.env("TMPDIR", "/tmp");
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
pub fn maintainer_profile(spec: &Spec, worktree: &Path, masks: &[std::path::PathBuf]) -> String {
    let wt = sbpl_quote(&worktree.to_string_lossy());
    let mut p = String::new();
    p.push_str("(version 1)\n(deny default)\n");
    // Diagnostics off; we never want the sandbox to prompt.
    p.push_str("(deny file-write* file-read* (with no-report))\n");
    // Read system paths and dyld.
    p.push_str("(allow process-exec* (regex #\"^/(usr|bin|sbin|opt|System|Library)/\"))\n");
    p.push_str("(allow file-read* (regex #\"^/(usr|bin|sbin|opt|System|Library|private/etc|private/var/db)/\"))\n");
    p.push_str("(allow file-read-metadata)\n");
    p.push_str("(allow sysctl-read)\n");
    // Worktree read-write (and the scratch TMPDIR).
    let _ = writeln!(p, "(allow file-read* file-write* (subpath {wt}))");
    p.push_str("(allow file-read* file-write* (subpath \"/private/tmp\"))\n");
    p.push_str("(allow file-write* file-read* (subpath \"/private/var/folders\"))\n");
    for p2 in &spec.rw_paths {
        let _ = writeln!(p, 
            "(allow file-read* file-write* (subpath {}))",
            sbpl_quote(&p2.to_string_lossy())
        );
    }
    // Mask secret-shaped / git-ignored files: explicit deny wins over the
    // worktree allow above.
    for m in masks {
        let _ = writeln!(p, 
            "(deny file-read* file-write* (subpath {}))",
            sbpl_quote(&m.to_string_lossy())
        );
    }
    // Network: loopback gateway port only (no general outbound).
    if let Some(port) = spec.gateway_loopback_port {
        let _ = writeln!(p, 
            "(allow network-outbound (remote ip \"localhost:{port}\"))"
        );
    }
    if let Some(sock) = &spec.gateway_socket {
        let _ = writeln!(p, 
            "(allow network-outbound (literal (subpath {})))",
            sbpl_quote(&sock.to_string_lossy())
        );
    }
    // Denials we make explicit for clarity (already covered by deny default):
    p.push_str("(deny mach-lookup)\n");
    p.push_str("(deny network-inbound)\n");
    p.push_str("(allow signal (target same-sandbox))\n");
    p
}

/// Donor self-lockdown profile (§15.2a): deny process-exec/process-fork, limit
/// files to the state dir (rw) + CA roots (ro), network outbound to 443 + relay
/// (+ loopback gateway bind).
pub fn donor_profile(policy: &DonorPolicy) -> String {
    let state = sbpl_quote(&policy.state_dir.to_string_lossy());
    let mut p = String::new();
    p.push_str("(version 1)\n(deny default)\n");
    p.push_str("(deny process-exec*)\n(deny process-fork)\n");
    let _ = writeln!(p, "(allow file-read* file-write* (subpath {state}))");
    for ro in &policy.ro_paths {
        let _ = writeln!(p, 
            "(allow file-read* (subpath {}))",
            sbpl_quote(&ro.to_string_lossy())
        );
    }
    p.push_str("(allow file-read* (regex #\"^/(usr/lib|System/Library)/\"))\n");
    let _ = writeln!(p, 
        "(allow network-outbound (remote tcp \"*:443\") (remote tcp \"*:{}\"))",
        policy.relay_port
    );
    if let Some(gw) = policy.gateway_port {
        let _ = writeln!(p, 
            "(allow network-inbound (local tcp \"localhost:{gw}\"))"
        );
    }
    p.push_str("(deny mach-lookup)\n");
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
            let code = match crate::sys_macos::apply_profile(VALIDATOR_PROFILE) {
                Ok(()) => run(child_fd),
                Err(_) => 71,
            };
            crate::sys_macos::exit_immediately(code);
        }
    }
}

const VALIDATOR_PROFILE: &str = "(version 1)\n(deny default)\n(deny process-exec*)\n(deny process-fork)\n(deny file*)\n(deny network*)\n";

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
