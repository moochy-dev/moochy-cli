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

