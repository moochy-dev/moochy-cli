//! Donor side (CONTRACT §15.2): the whole Moochy background process locks itself
//! down after start-up ([`lockdown_self`]), and a single-use jailed child parses
//! the only hostile bytes ([`spawn_validator`]).

use std::os::unix::io::{AsRawFd as _, RawFd};

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, RestrictSelfAttr, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, path_beneath_rules,
};
use rustix::process::{Pid, WaitOptions, waitpid};

use crate::{DonorPolicy, Error, LockdownReport, Validator, seccomp, sys};

fn setup(what: &'static str, err: std::io::Error) -> Error {
    Error::Setup { what, err }
}

fn ll(what: &'static str, e: landlock::RulesetError) -> Error {
    setup(what, std::io::Error::other(e.to_string()))
}

/// Highest Landlock ABI this build negotiates against. The crate clamps to what
/// the running kernel supports (best-effort), so this is just a ceiling.
const ABI_CEIL: ABI = ABI::V5;

/// CONTRACT §15.2a.
pub fn lockdown_self(policy: &DonorPolicy) -> Result<LockdownReport, Error> {
    if policy.unsafe_no_lockdown {
        eprintln!(
            "moochy: WARNING --unsafe-no-lockdown: the background process is NOT sandboxed. \
             Debugging only; never serve pooled compute like this."
        );
        return Ok(LockdownReport::default());
    }

    // 1) Landlock FS + network cage, applied to every thread. This also turns on
    //    no_new_privs (required before seccomp TSYNC below).
    let mut report = build_landlock(policy)?;

    // 2) seccomp "zero commands" deny-list on all threads. no_new_privs is now
    //    set (by Landlock, or we set it explicitly if Landlock was unavailable).
    if !report.no_new_privs {
        rustix::thread::set_no_new_privs(true).map_err(|e| setup("no_new_privs", e.into()))?;
        report.no_new_privs = true;
    }
    for prog in seccomp::donor_filter()? {
        seccompiler::apply_filter_all_threads(&prog)
            .map_err(|e| setup("seccomp apply", std::io::Error::other(e.to_string())))?;
    }
    report.seccomp = true;
    Ok(report)
}

fn build_landlock(policy: &DonorPolicy) -> Result<LockdownReport, Error> {
    let abi = ABI_CEIL;
    let mut report = LockdownReport {
        abi: abi as i32,
        ..Default::default()
    };

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| ll("landlock fs handle", e))?;

    // Network restriction exists only on ABI ≥ 4. Best-effort: on older kernels
    // this is dropped and we record landlock_net = None.
    let want_net = true;
    if want_net {
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(|e| ll("landlock net handle", e))?;
    }
    // Deny abstract-unix-socket and signal reach to processes outside the domain
    // (ABI ≥ 6; best-effort).
    ruleset = ruleset
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(|e| ll("landlock scope", e))?;

    let created = ruleset.create().map_err(|e| ll("landlock create", e))?;

    // rw on the state dir; ro on CA roots + whatever else the policy lists.
    let created = created
        .add_rules(path_beneath_rules(
            [policy.state_dir.clone()],
            AccessFs::from_all(abi),
        ))
        .map_err(|e| ll("landlock state rule", e))?;
    let created = created
        .add_rules(path_beneath_rules(
            policy.ro_paths.iter().filter(|p| p.exists()).cloned(),
            AccessFs::from_read(abi),
        ))
        .map_err(|e| ll("landlock ro rule", e))?;

    // Outbound TCP: providers (443) and the relay port. Bind: the loopback
    // gateway port (§15.4). Everything else is refused.
    let mut created = created
        .add_rule(NetPort::new(443, AccessNet::ConnectTcp))
        .map_err(|e| ll("landlock connect 443", e))?;
    created = created
        .add_rule(NetPort::new(policy.relay_port, AccessNet::ConnectTcp))
        .map_err(|e| ll("landlock connect relay", e))?;
    if let Some(gw) = policy.gateway_port {
        created = created
            .add_rule(NetPort::new(gw, AccessNet::BindTcp))
            .map_err(|e| ll("landlock bind gateway", e))?;
    }

    let status = created
        .no_new_privs(true)
        .all_threads(true)
        .map_err(|e| ll("landlock all_threads", e))?
        .restrict_self()
        .map_err(|e| ll("landlock restrict_self", e))?;

    report.no_new_privs = status.no_new_privs;
    report.landlock_fs = status.ruleset != RulesetStatus::NotEnforced;
    report.landlock_net = if report.landlock_fs {
        Some(status.ruleset == RulesetStatus::FullyEnforced)
    } else {
        None
    };
    if !report.landlock_fs {
        // Fail closed: the FS cage is the point. (Network alone is not enough.)
        return Err(Error::Unsupported(
            "Landlock is not available on this kernel; the donor cannot cage its filesystem",
        ));
    }
    Ok(report)
}

/// CONTRACT §15.2b: fork a jailed validator child and hand it one end of a
/// socketpair.
pub fn spawn_validator<F>(run: F) -> Result<Validator, Error>
where
    F: FnOnce(RawFd) -> i32 + Send,
{
    // Build everything that allocates *before* the fork (the child must not
    // touch the allocator between fork and seccomp, see sys.rs).
    let prog = seccomp::validator_filter()?;
    let (parent_sock, child_sock) =
        std::os::unix::net::UnixStream::pair().map_err(|e| setup("socketpair", e))?;
    let child_fd = child_sock.as_raw_fd();

    // SAFETY: the child path below performs only syscalls that are either
    // pre-built (the seccomp program) or allocation-free until it calls `run`;
    // `run` is the caller's parser, which the seccomp allowlist constrains.
    match sys::fork().map_err(|e| setup("fork", e))? {
        sys::Fork::Parent(pid) => {
            drop(child_sock);
            Ok(Validator {
                sock: parent_sock,
                child_pid: pid,
            })
        }
        sys::Fork::Child => {
            drop(parent_sock);
            let code = jail_and_run_validator(&prog, child_fd, run);
            sys::exit_immediately(code);
        }
    }
}

/// Runs in the forked child: apply rlimits + empty-ish Landlock + the allowlist
/// seccomp, then call the caller's parser. Any failure exits non-zero (fail
/// closed); any disallowed syscall is killed by seccomp.
fn jail_and_run_validator<F>(prog: &seccompiler::BpfProgram, fd: RawFd, run: F) -> i32
where
    F: FnOnce(RawFd) -> i32,
{
    use rustix::process::{Resource, Rlimit, setrlimit};
    // Tight rlimits: no new files, bounded memory, no core.
    let lim = |res, v| {
        let _ = setrlimit(
            res,
            Rlimit {
                current: Some(v),
                maximum: Some(v),
            },
        );
    };
    // The socketpair end is already open; cap NOFILE low so the parser cannot
    // acquire many descriptors even before seccomp (defense in depth).
    lim(Resource::Nofile, 16);
    lim(Resource::Core, 0);
    lim(Resource::As, 1 << 30); // 1 GiB

    // Empty Landlock domain: handle every access but add no rules → no path is
    // reachable at all (the validator needs no filesystem).
    if let Err(e) = empty_landlock() {
        eprintln!("moochy validator: landlock failed: {e}");
        return 71;
    }
    // Allowlist seccomp (current thread only; the child is single-threaded).
    if let Err(e) = seccompiler::apply_filter(prog) {
        eprintln!("moochy validator: seccomp failed: {e}");
        return 71;
    }
    run(fd)
}

fn empty_landlock() -> Result<(), Error> {
    let abi = ABI_CEIL;
    let created = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| ll("landlock fs handle", e))?
        .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
        .map_err(|e| ll("landlock net handle", e))?
        .create()
        .map_err(|e| ll("landlock create", e))?;
    created
        .no_new_privs(true)
        .restrict_self()
        .map_err(|e| ll("landlock restrict_self", e))?;
    Ok(())
}

/// Wait for a child pid (raw) and return its exit code (128 + signal if killed).
pub fn wait_raw(pid_raw: i32) -> Result<i32, Error> {
    let pid = Pid::from_raw(pid_raw).ok_or(Error::Unsupported("invalid child pid"))?;
    wait_pid(pid)
}

/// Wait for a child pid and return its exit code (128 + signal if killed).
pub fn wait_pid(pid: Pid) -> Result<i32, Error> {
    loop {
        match waitpid(Some(pid), WaitOptions::empty()) {
            Ok(Some((_, status))) => {
                if let Some(code) = status.exit_status() {
                    return Ok(code as i32);
                }
                if let Some(sig) = status.terminating_signal() {
                    return Ok(128i32.saturating_add(sig as i32));
                }
                return Ok(-1);
            }
            Ok(None) => continue,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(setup("waitpid", e.into())),
        }
    }
}

