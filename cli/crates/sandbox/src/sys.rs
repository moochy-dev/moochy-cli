//! The **only** `unsafe` in `moochy-sandbox` (CONTRACT §15 exception).
//!
//! Everything else in the crate uses the memory-safe wrappers of `rustix`,
//! `landlock` and `seccompiler`. This module exposes the two primitives those
//! crates deliberately do not make safe — `fork` and `_exit` — behind documented
//! wrappers, plus nothing else. Keep it tiny; every block is justified inline.
//!
//! Safety discipline for the child side of a `fork`: between `fork` and either
//! `execve` or `_exit`, the child must touch only async-signal-safe operations
//! and memory already allocated before the fork. Callers pre-build every
//! allocating artefact (the seccomp program, the Landlock ruleset fd) in the
//! parent and, in the child, perform syscalls only. See `donor.rs` / `linux.rs`.
#![allow(unsafe_code)]

use std::io;

/// Result of [`fork`].
pub enum Fork {
    /// We are the parent; carries the child pid (> 0).
    Parent(i32),
    /// We are the freshly-forked child.
    Child,
}

/// `fork(2)`. Memory-safe to call; the *child* path carries a logical contract
/// (reach `execve`/[`exit_immediately`] touching only async-signal-safe code and
/// memory allocated before the fork). Callers in this crate fork from a
/// single-threaded context or apply only pre-built syscalls in the child.
pub fn fork() -> io::Result<Fork> {
    // SAFETY: fork() reads/writes no user memory and has no memory-safety
    // precondition; the child-side contract above is enforced by callers.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Fork::Child),
        n => Ok(Fork::Parent(n)),
    }
}

/// `unshare(2)`, keeping the (deprecated-as-unsafe) rustix call confined here.
/// Safe when called from a single-threaded context (our forked children and the
/// userns probe), where it cannot desynchronize sibling threads.
pub fn unshare(flags: rustix::thread::UnshareFlags) -> rustix::io::Result<()> {
    // SAFETY: called only single-threaded; no other thread observes the changed
    // namespaces mid-flight.
    unsafe { rustix::thread::unshare_unsafe(flags) }
}

/// Register a `pre_exec` hook, confining the `unsafe` to this module.
///
/// # Safety
/// The hook runs in the forked child between fork and exec; it must honour the
/// same async-signal-safety contract as [`fork`].
pub fn set_pre_exec<F>(cmd: &mut std::process::Command, f: F)
where
    F: FnMut() -> io::Result<()> + Send + Sync + 'static,
{
    use std::os::unix::process::CommandExt as _;
    // SAFETY: `f` honours the child-side contract documented on its call site in
    // linux.rs (only namespace/mount syscalls, then pre-built seccomp/Landlock).
    unsafe {
        cmd.pre_exec(f);
    }
}

/// `_exit(2)` — terminate immediately without running atexit handlers, flushing
/// stdio, or unwinding. The correct way to leave a forked child.
pub fn exit_immediately(code: i32) -> ! {
    // SAFETY: _exit is always safe to call; it never returns and touches no
    // user memory. It is marked unsafe in libc only because it is an extern fn.
    unsafe { libc::_exit(code) }
}

/// Bring the loopback interface up in the current (fresh) network namespace:
/// `ioctl(SIOCGIFFLAGS/SIOCSIFFLAGS, "lo", IFF_UP)`. Needs CAP_NET_ADMIN over
/// the netns, which the namespace creator holds inside its user namespace.
pub fn loopback_up() -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")
        .or_else(|_| std::net::UdpSocket::bind("[::]:0"))
        .map_err(|e| io::Error::other(format!("loopback socket: {e}")))?;
    // SAFETY: `ifr` is a zeroed, properly sized `ifreq`; the kernel reads the
    // name and reads/writes `ifru_flags` only. The fd is valid for both calls.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (dst, src) in ifr.ifr_name.iter_mut().zip(b"lo\0") {
            *dst = libc::c_char::from_ne_bytes([*src]);
        }
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr) == -1 {
            return Err(io::Error::last_os_error());
        }
        // IFF_UP | IFF_RUNNING = 0x41: fits in c_short.
        #[allow(clippy::cast_possible_truncation)]
        let up = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ifr.ifr_ifru.ifru_flags |= up;
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &ifr) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// `prctl(PR_CAPBSET_DROP, cap)` — remove one capability from the bounding set
/// so that after `no_new_privs` no exec can ever regain it. Returns true on
/// success (or if the cap is already absent / out of range).
pub fn capbset_drop(cap: u32) -> bool {
    const PR_CAPBSET_DROP: i32 = 24;
    // SAFETY: prctl with these arguments only mutates this process's bounding
    // set; it reads/writes no user memory. EINVAL for unknown caps is benign.
    let r = unsafe { libc::prctl(PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) };
    r == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
}


/// The fd the validator child talks on after [`isolate_fds`].
pub const CHANNEL_FD: i32 = 3;

/// Validator child, before any sandbox step: keep only `keep` (moved to
/// [`CHANNEL_FD`]), point 0/1/2 at /dev/null, close every other fd the parent
/// held (relay TLS socket, provider sockets, outbox file …) so a compromised
/// parser cannot write into them.
pub fn isolate_fds(keep: i32) -> io::Result<()> {
    // SAFETY: plain fd syscalls on integers; no user memory beyond the path
    // literal. Single-threaded forked child.
    unsafe {
        // Park the channel above stdio first (keep might be 0..=2).
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
        // Everything above the channel: gone (parked + null included).
        if libc::syscall(libc::SYS_close_range, CHANNEL_FD + 1, u32::MAX, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Agent, just before `execve`: mark every fd ≥ 3 close-on-exec so nothing the
/// launcher held leaks into the sandbox (std's own exec-status pipe is already
/// CLOEXEC, so this never breaks spawn error reporting).
pub fn cloexec_from_3() -> io::Result<()> {
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    // SAFETY: close_range only toggles fd flags of this process.
    let r = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Take ownership of [`CHANNEL_FD`] as a `UnixStream` in the validator child.
pub fn channel_stream() -> std::os::unix::net::UnixStream {
    use std::os::fd::FromRawFd as _;
    // SAFETY: after `isolate_fds`, CHANNEL_FD is open, is the socketpair end,
    // and nothing else in this process owns it.
    unsafe { std::os::unix::net::UnixStream::from_raw_fd(CHANNEL_FD) }
}

/// Reaper: block `SIGWINCH` and return a signalfd for it, so terminal resizes
/// can be forwarded to the agent's session (the agent runs `setsid`, without a
/// controlling terminal, so the tty never signals it directly; A192).
pub fn winch_signalfd() -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd as _;
    // SAFETY: sigset_t is plain data initialised by sigemptyset; sigprocmask and
    // signalfd only read `set`. The returned fd is fresh and owned by nobody else.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGWINCH);
        if libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(std::os::fd::OwnedFd::from_raw_fd(fd))
    }
}

/// The kernel's Landlock ABI version (`landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)`); 0 when Landlock is unavailable. For
/// `moochy doctor` only: the sandbox itself negotiates through the `landlock`
/// crate.
pub fn landlock_abi() -> i32 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: with a NULL attr and size 0 the kernel reads no user memory and
    // returns the ABI version (or -1).
    let r = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<libc::c_void>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION)
    };
    i32::try_from(r).unwrap_or(0).max(0)
}
