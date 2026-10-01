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

// ioctl requests that inject into a terminal; compared as 32-bit (low word).
const TIOCSTI: u64 = 0x5412;
const TIOCLINUX: u64 = 0x541C;
// clone(2) namespace flags we refuse (block nested-userns escape surface).
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWNS: u64 = 0x0002_0000;
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
        libc::SYS_kexec_file_load,
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
    ];
    for nr in unconditional {
        m.insert(nr, Vec::new());
    }
    // ioctl(TIOCSTI)/ioctl(TIOCLINUX): compare the low 32 bits only.
    m.insert(
        libc::SYS_ioctl,
        vec![
            eq(1, SeccompCmpArgLen::Dword, TIOCSTI)?,
            eq(1, SeccompCmpArgLen::Dword, TIOCLINUX)?,
        ],
    );
    // clone(CLONE_NEWUSER|CLONE_NEWNS): block nested namespaces (keep plain
    // thread/process clone for the agent's tools).
    m.insert(
        libc::SYS_clone,
        vec![
            masked_match(0, SeccompCmpArgLen::Qword, CLONE_NEWUSER, CLONE_NEWUSER)?,
            masked_match(0, SeccompCmpArgLen::Qword, CLONE_NEWNS, CLONE_NEWNS)?,
        ],
    );
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
#[cfg(target_arch = "x86_64")]
fn x32_filter() -> BpfProgram {
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
/// `execve`/`execveat` — "zero commands on donors" (§15.2a).
pub fn donor_filter() -> Result<Vec<BpfProgram>, Error> {
    let mut m = deny_common()?;
    m.insert(libc::SYS_execve, Vec::new());
    m.insert(libc::SYS_execveat, Vec::new());
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
