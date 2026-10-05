//! seccomp-bpf filters (CONTRACT §15). Three profiles, all built with the safe
//! `seccompiler` compiler and applied with a trivial `prctl` (no allocation at
//! apply time, so they are safe to apply in a forked child).
//!
//! - [`agent_filter`] — maintainer `moochy run`: a **deny-list**. The agent may
//!   `execve` (it runs tools) but not the escape/vector syscalls.
//! - [`donor_filter`] — donor self-lockdown: a deny-list that *also* forbids
//!   `execve`/`execveat` — kernel-enforced "zero commands on donors" (§15.2a).
//! - [`validator_filter`] — the request validator child: an **allowlist** of
//!   read/write/memory/exit only; anything else kills the process (§15.2b).
//!
//! `TIOCSTI`/`TIOCLINUX` terminal-injection ioctls are filtered by comparing only
//! the low 32 bits of the request (the classic bubblewrap CVE-2017-5226 pitfall).

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

use crate::Error;

/// `kexec_file_load`, missing from the `libc` crate on aarch64-musl (a release
/// target). Numbers from the kernel's syscall tables.
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_KEXEC_FILE_LOAD: i64 = 320;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub(crate) const SYS_KEXEC_FILE_LOAD: i64 = 294; // asm-generic
#[cfg(target_env = "gnu")]
const _: () = assert!(SYS_KEXEC_FILE_LOAD == libc::SYS_kexec_file_load);

// ioctl requests that inject into a terminal or swap its line discipline (a kernel
// module autoload, and a tty the user still types into); compared as 32-bit (low word).
const TIOCSTI: u64 = 0x5412;
const TIOCLINUX: u64 = 0x541C;
const TIOCSETD: u64 = 0x5423;
// clone(2) namespace flags we refuse, every CLONE_NEW* (NEWUSER, NEWNS, NEWNET, NEWPID, NEWIPC,
// NEWUTS, NEWCGROUP): no nested namespace, whatever caps the kernel would ask for.
pub(crate) const CLONE_NEW: [u64; 7] = [0x1000_0000, 0x0002_0000, 0x4000_0000, 0x2000_0000, 0x0800_0000, 0x0400_0000, 0x0200_0000];
// Socket families the agent may open (jail review #1): Unix, IPv4, IPv6, netlink. Any other
// (AF_VSOCK to the hypervisor, AF_ALG, AF_PACKET, Bluetooth, …) is EPERM, which also stops the
// kernel autoloading its protocol module.
pub(crate) const SOCKET_FAMILIES: [u64; 4] = [libc::AF_UNIX as u64, libc::AF_INET as u64, libc::AF_INET6 as u64, libc::AF_NETLINK as u64];
// personality(2): only PER_LINUX (0) and the 0xffffffff query stay allowed.
const PER_QUERY: u64 = 0xffff_ffff;
/// `statmount`/`listmount` (Linux 6.8), not in the `libc` crate: one number on every arch.
pub(crate) const SYS_STATMOUNT: i64 = 457;
pub(crate) const SYS_LISTMOUNT: i64 = 458;
// mmap/mprotect PROT_EXEC bit (validator must never map executable memory).
const PROT_EXEC: u64 = 0x4;

fn arch() -> TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        TargetArch::aarch64
    }
    #[cfg(target_arch = "riscv64")]
    {
        TargetArch::riscv64
    }
}

fn setup(what: &'static str, e: impl std::fmt::Display) -> Error {
    Error::Setup {
        what,
        err: std::io::Error::other(e.to_string()),
    }
}

fn eq(arg: u8, len: SeccompCmpArgLen, val: u64) -> Result<SeccompRule, Error> {
    let cond = SeccompCondition::new(arg, len, SeccompCmpOp::Eq, val)
        .map_err(|e| setup("seccomp condition", e))?;
    SeccompRule::new(vec![cond]).map_err(|e| setup("seccomp rule", e))
}

fn masked_match(arg: u8, len: SeccompCmpArgLen, mask: u64, val: u64) -> Result<SeccompRule, Error> {
    let cond = SeccompCondition::new(arg, len, SeccompCmpOp::MaskedEq(mask), val)
        .map_err(|e| setup("seccomp condition", e))?;
    SeccompRule::new(vec![cond]).map_err(|e| setup("seccomp rule", e))
}

fn compile(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    mismatch: SeccompAction,
    matched: SeccompAction,
) -> Result<BpfProgram, Error> {
    let filter = SeccompFilter::new(rules, mismatch, matched, arch())
        .map_err(|e| setup("seccomp filter", e))?;
    filter.try_into().map_err(|e| setup("seccomp compile", e))
}

/// Rules shared by both deny-lists: the escape/vector syscalls plus terminal
/// injection and namespace re-entry. `extra` lets the donor add `execve`.
fn deny_common() -> Result<BTreeMap<i64, Vec<SeccompRule>>, Error> {
    let mut m: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // Unconditional denials.
    let unconditional = [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_mount_setattr,
        libc::SYS_bpf,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_kexec_load,
        SYS_KEXEC_FILE_LOAD,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        // io_uring: large kernel attack surface, and its ops bypass the
        // per-syscall filter (A195).
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // Jail review #6: another process's fds, kernel pointer comparison, other processes'
        // memory advice, superblock reconfiguration, quotas, clock steering, the mount tree
        // listing and the kernel log.
        libc::SYS_pidfd_getfd,
        libc::SYS_kcmp,
        libc::SYS_process_madvise,
        libc::SYS_fspick,
        libc::SYS_quotactl_fd,
        libc::SYS_clock_adjtime,
        SYS_LISTMOUNT,
        SYS_STATMOUNT,
        libc::SYS_syslog,
    ];
    for nr in unconditional {
        m.insert(nr, Vec::new());
    }
    // ioctl(TIOCSTI/TIOCLINUX/TIOCSETD): compare the low 32 bits only.
    m.insert(
        libc::SYS_ioctl,
        vec![
            eq(1, SeccompCmpArgLen::Dword, TIOCSTI)?,
            eq(1, SeccompCmpArgLen::Dword, TIOCLINUX)?,
            eq(1, SeccompCmpArgLen::Dword, TIOCSETD)?,
        ],
    );
    // clone(CLONE_NEW*): block nested namespaces (keep plain thread/process clone for the
    // agent's tools).
    m.insert(libc::SYS_clone, CLONE_NEW.iter().map(|f| masked_match(0, SeccompCmpArgLen::Qword, *f, *f)).collect::<Result<_, _>>()?);
    // One rule, all conditions true: a family outside the list, or a persona other than the default.
    let ne = |arg, val| SeccompCondition::new(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, val).map_err(|e| setup("seccomp condition", e));
    let socket = SOCKET_FAMILIES.iter().map(|f| ne(0, *f)).collect::<Result<_, _>>()?;
    m.insert(libc::SYS_socket, vec![SeccompRule::new(socket).map_err(|e| setup("seccomp rule", e))?]);
    m.insert(libc::SYS_personality, vec![SeccompRule::new(vec![ne(0, 0)?, ne(0, PER_QUERY)?]).map_err(|e| setup("seccomp rule", e))?]);
    Ok(m)
}

/// `clone3` answered with `ENOSYS` (its flags live in a struct seccomp cannot
/// inspect), so glibc falls back to `clone`, whose flags the deny-lists check.
/// Installed as its own filter: the kernel combines stacked filters and ERRNO
/// outranks ALLOW, so a distinct errno needs a distinct program.
pub fn clone3_filter() -> Result<BpfProgram, Error> {
    let mut m: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    m.insert(libc::SYS_clone3, Vec::new());
    compile(m, SeccompAction::Allow, SeccompAction::Errno(libc::ENOSYS as u32))
}

/// x86_64 only: x32-ABI syscalls (`nr | 0x4000_0000`) carry the same
/// `AUDIT_ARCH_X86_64`, so a deny-list keyed on x86_64 numbers (seccompiler
/// has no x32 handling) would miss e.g. an x32 `execve`. Refuse the whole x32
/// range; wrong-arch calls are killed by the stacked seccompiler program.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))] // tested on every arch (fuzzing.rs)
pub(crate) fn x32_filter() -> BpfProgram {
    use seccompiler::sock_filter;
    const LD_W_ABS: u16 = 0x20;
    const JGE_K: u16 = 0x35;
    const RET_K: u16 = 0x06;
    let ins = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    vec![
        ins(LD_W_ABS, 0, 0, 0), // seccomp_data.nr
        ins(JGE_K, 0, 1, 0x4000_0000),
        ins(RET_K, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM.unsigned_abs()),
        ins(RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

/// The deny-list programs, stacked: clone3 → ENOSYS, x32 → EPERM (x86_64), `m`.
fn deny_stack(m: BTreeMap<i64, Vec<SeccompRule>>) -> Result<Vec<BpfProgram>, Error> {
    let mut v = vec![clone3_filter()?];
    #[cfg(target_arch = "x86_64")]
    v.push(x32_filter());
    v.push(compile(m, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM.unsigned_abs()))?);
    Ok(v)
}

/// Maintainer-side agent deny-list. Denied calls fail with `EPERM` so the agent
/// stays alive and sees a normal error (robustness).
pub fn agent_filter() -> Result<Vec<BpfProgram>, Error> {
    deny_stack(deny_common()?)
}

/// Donor self-lockdown deny-list: everything [`agent_filter`] denies, **plus**
/// `execve`/`execveat` — "zero commands on donors" (§15.2a) — **plus** new Unix sockets (G22):
/// below Landlock ABI 9 nothing else stops a `connect()` to a pathname socket (the user D-Bus,
/// whose systemd `StartTransientUnit` runs commands; ssh-agent; docker.sock). The donor binds its
/// own sockets before the lockdown and gets validator channels over SCM_RIGHTS, so it needs no
/// new ones: `socket(AF_UNIX)` is refused, and `socketpair(AF_UNIX)` (tokio's signal pipe, the
/// zygote's validator channels) only for connected stream types, since a datagram socket can be
/// re-aimed with `sendto()`. Name resolution falls back from nss-resolve to DNS on loopback.
pub fn donor_filter() -> Result<Vec<BpfProgram>, Error> {
    let mut m = deny_common()?;
    m.insert(libc::SYS_execve, Vec::new());
    m.insert(libc::SYS_execveat, Vec::new());
    let af_unix = |arg| SeccompCondition::new(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::AF_UNIX as u64).map_err(|e| setup("seccomp condition", e));
    m.entry(libc::SYS_socket).or_default().push(SeccompRule::new(vec![af_unix(0)?]).map_err(|e| setup("seccomp rule", e))?);
    let dgram = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(0xf), libc::SOCK_DGRAM as u64).map_err(|e| setup("seccomp condition", e))?;
    m.insert(libc::SYS_socketpair, vec![SeccompRule::new(vec![af_unix(0)?, dgram]).map_err(|e| setup("seccomp rule", e))?]);
    deny_stack(m)
}

/// Validator-child allowlist (§15.2b): read/write/memory/exit only. `mmap`/
/// `mprotect` are allowed only without `PROT_EXEC`. Anything outside the list
/// kills the process, so an attempt to open a file or a socket is fatal and
/// observable.
pub fn validator_filter() -> Result<BpfProgram, Error> {
    let mut m: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // Unconditional allows: I/O on the inherited socketpair + process teardown
    // + the syscalls a pure-Rust parser needs (allocator, futex, RNG seeding).
    let allow = [
        libc::SYS_read,
        libc::SYS_write,
        // std's UnixStream I/O is send(MSG_NOSIGNAL)/recv = sendto/recvfrom on the
        // already-connected channel; the child cannot create or connect sockets.
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_munmap,
        // Vec growth past the mmap threshold reallocs via mremap (A200); it
        // cannot change protections.
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_getrandom,
        libc::SYS_madvise,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_ppoll,
        libc::SYS_nanosleep,
        libc::SYS_restart_syscall,
    ];
    for nr in allow {
        m.insert(nr, Vec::new());
    }
    // rseq is emitted by modern glibc startup; allow if present on this arch.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        m.insert(libc::SYS_rseq, Vec::new());
    }
    // fcntl: read-only queries only (std's debug fd-validity check on drop uses
    // F_GETFD). F_DUPFD / F_SETFL / locks stay fatal.
    m.insert(
        libc::SYS_fcntl,
        vec![
            eq(1, SeccompCmpArgLen::Dword, libc::F_GETFD as u64)?,
            eq(1, SeccompCmpArgLen::Dword, libc::F_GETFL as u64)?,
        ],
    );
    // mmap / mprotect: only without PROT_EXEC (prot is arg index 2).
    m.insert(
        libc::SYS_mmap,
        vec![masked_match(2, SeccompCmpArgLen::Dword, PROT_EXEC, 0)?],
    );
    m.insert(
        libc::SYS_mprotect,
        vec![masked_match(2, SeccompCmpArgLen::Dword, PROT_EXEC, 0)?],
    );
    compile(m, SeccompAction::KillProcess, SeccompAction::Allow)
}
