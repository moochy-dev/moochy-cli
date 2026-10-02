//! The only `unsafe` on macOS (CONTRACT §15 exception): `sandbox_init(3)` FFI,
//! `fork` and `_exit`. Everything else on macOS uses `std`/`Command`.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;

#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, errorbuf: *mut *mut libc::c_char)
        -> libc::c_int;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Apply an SBPL profile string to the current process. Irreversible.
pub fn apply_profile(profile: &str) -> io::Result<()> {
    let c = CString::new(profile).map_err(|_| io::Error::other("profile has NUL"))?;
    let mut err: *mut libc::c_char = std::ptr::null_mut();
    // SAFETY: `c` is a valid NUL-terminated C string for the call; `err` is a
    // valid out-pointer we free via sandbox_free_error.
    let r = unsafe { sandbox_init(c.as_ptr(), 0, &raw mut err) };
    if r == 0 {
        Ok(())
    } else {
        let msg = if err.is_null() {
            "sandbox_init failed".to_string()
        } else {
            // SAFETY: err points to a C string allocated by libsandbox.
            let s = unsafe { std::ffi::CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: free the libsandbox-allocated error buffer.
            unsafe { sandbox_free_error(err) };
            s
        };
        Err(io::Error::other(msg))
    }
}

pub enum Fork {
    Parent(i32),
    Child,
}

pub fn fork() -> io::Result<Fork> {
    // SAFETY: fork reads/writes no user memory; child-side contract per module.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Fork::Child),
        n => Ok(Fork::Parent(n)),
    }
}

pub fn exit_immediately(code: i32) -> ! {
    // SAFETY: _exit never returns and touches no user memory.
    unsafe { libc::_exit(code) }
}

/// Wait for a child pid; return exit code (128 + signal if killed).
pub fn wait_raw(pid: i32) -> io::Result<i32> {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waitpid writes only into `status`.
        let r = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if r == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(128i32.saturating_add(libc::WTERMSIG(status)));
        }
    }
}

/// The fd the validator child talks on after [`isolate_fds`].
pub const CHANNEL_FD: i32 = 3;

/// See the Linux twin: keep only `keep` (moved to fd 3), stdio to /dev/null,
/// close every other inherited fd. macOS has no close_range: close up to the
/// soft RLIMIT_NOFILE (capped at 65536).
pub fn isolate_fds(keep: i32) -> io::Result<()> {
    // SAFETY: plain fd syscalls on integers; single-threaded forked child.
    unsafe {
        let parked = libc::fcntl(keep, libc::F_DUPFD_CLOEXEC, 10);
        if parked < 0 {
            return Err(io::Error::last_os_error());
        }
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if null < 0 {
            return Err(io::Error::last_os_error());
        }
        for std_fd in 0..=2 {
            if libc::dup2(null, std_fd) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if libc::dup2(parked, CHANNEL_FD) < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let max = if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) == 0 {
            i32::try_from(lim.rlim_cur.min(65_536)).unwrap_or(65_536)
        } else {
            65_536
        };
        for fd in (CHANNEL_FD + 1)..max {
            libc::close(fd);
        }
    }
    Ok(())
}

/// Take ownership of [`CHANNEL_FD`] as a `UnixStream` in the validator child.
pub fn channel_stream() -> std::os::unix::net::UnixStream {
    use std::os::fd::FromRawFd as _;
    // SAFETY: after `isolate_fds`, CHANNEL_FD is open and owned by nobody else.
    unsafe { std::os::unix::net::UnixStream::from_raw_fd(CHANNEL_FD) }
}

/// Between fork and exec of `moochy run`'s `sandbox-exec`: `setsid` (own
/// session, no controlling terminal: A192) and the rlimits macOS enforces per
/// process (open files, core, CPU). `RLIMIT_NPROC` is per *user* on macOS
/// (it would cap the user's whole desktop) and `RLIMIT_AS` is not enforced, so
/// neither is set here (DESIGN.md).
pub fn session_and_limits(cmd: &mut std::process::Command, l: &crate::Limits) {
    use std::os::unix::process::CommandExt as _;
    let mut lims: Vec<(libc::c_int, u64)> = vec![(libc::RLIMIT_NOFILE, l.open_files), (libc::RLIMIT_CORE, l.core_bytes)];
    if l.cpu_seconds > 0 {
        lims.push((libc::RLIMIT_CPU, l.cpu_seconds));
    }
    // SAFETY: the closure runs in the forked child before exec and calls only
    // async-signal-safe setsid/setrlimit on data captured (allocated) before
    // the fork; it allocates nothing.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            for &(res, v) in &lims {
                let r = libc::rlimit { rlim_cur: v, rlim_max: v };
                if libc::setrlimit(res, &raw const r) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// `killpg(pgid, SIGKILL)`; a no-op for pgid ≤ 1.
pub fn killpg(pgid: i32) {
    if pgid > 1 {
        // SAFETY: killpg only sends a signal; it touches no memory.
        unsafe {
            libc::killpg(pgid, libc::SIGKILL);
        }
    }
}

static FORWARD_TO: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
const FORWARDED: [libc::c_int; 5] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT, libc::SIGWINCH];

extern "C" fn forward(sig: libc::c_int) {
    let pg = FORWARD_TO.load(std::sync::atomic::Ordering::Relaxed);
    if pg > 1 {
        // SAFETY: killpg is async-signal-safe and touches no memory.
        unsafe {
            libc::killpg(pg, sig);
        }
    }
}

/// While alive, the launcher passes Ctrl-C, Ctrl-\, SIGTERM, SIGHUP and window
/// resizes on to the run's process group (it has no controlling terminal, so
/// the tty no longer signals it) instead of dying and orphaning it. The
/// previous handlers come back on drop.
pub struct Forwarding(Vec<(libc::c_int, libc::sigaction)>);

pub fn forward_signals(pgid: i32) -> Forwarding {
    FORWARD_TO.store(pgid, std::sync::atomic::Ordering::Relaxed);
    let mut old = Vec::with_capacity(FORWARDED.len());
    for sig in FORWARDED {
        // SAFETY: sigaction structs are plain data, fully initialised here;
        // `forward` is an async-signal-safe extern "C" handler.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&raw mut sa.sa_mask);
            let mut prev: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, &raw const sa, &raw mut prev) == 0 {
                old.push((sig, prev));
            }
        }
    }
    Forwarding(old)
}

impl Drop for Forwarding {
    fn drop(&mut self) {
        for (sig, prev) in &self.0 {
            // SAFETY: restores the handler sigaction returned earlier.
            unsafe {
                libc::sigaction(*sig, prev, std::ptr::null_mut());
            }
        }
        FORWARD_TO.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// In a validator child forked by an already-caged zygote (macOS cannot stack a second
/// Seatbelt profile, A219): forbid further processes and bound CPU time with rlimits.
/// RLIMIT_NPROC is checked against the user's process count, so 0 makes every fork fail.
pub fn limit_validator_child() -> io::Result<()> {
    let set = |res: libc::c_int, v: libc::rlim_t| -> io::Result<()> {
        let lim = libc::rlimit { rlim_cur: v, rlim_max: v };
        // SAFETY: setrlimit reads `lim` only; lowering limits is always permitted.
        if unsafe { libc::setrlimit(res, &raw const lim) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    };
    set(libc::RLIMIT_NPROC, 0)?;
    set(libc::RLIMIT_CPU, 5)
}

