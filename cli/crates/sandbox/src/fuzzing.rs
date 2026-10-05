//! Fuzz oracles (dev-only: built under `cfg(test)` or cargo-fuzz's
//! `cfg(fuzzing)`, never shipped). `fuzz/` targets feed them arbitrary bytes;
//! the unit tests below feed them a fixed corpus plus pseudo-random inputs.
//!
//! - [`mask_glob`]: `mask::glob1` agrees with the recursive definition of a
//!   `*` glob.
//! - [`seccomp_tables`]: the compiled BPF of each profile, run by a small cBPF
//!   interpreter on an arbitrary `seccomp_data`, returns exactly what the
//!   policy (restated here, independently of `seccomp.rs`) says.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

/// `data` = pattern `\0` name; the linear matcher must agree with the
/// recursive definition of a `*` glob.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn mask_glob(data: &[u8]) {
    fn reference(p: &[u8], n: &[u8]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some((b'*', rest)) => (0..=n.len()).any(|i| reference(rest, &n[i..])),
            Some((c, rest)) => n.first() == Some(c) && reference(rest, &n[1..]),
        }
    }
    let text = String::from_utf8_lossy(data);
    let (pat, name) = text.split_once('\0').unwrap_or((&text, ""));
    if pat.len() > 24 || name.len() > 64 || pat.matches('*').count() > 4 {
        return; // keeps the exponential reference cheap
    }
    let want = reference(pat.as_bytes(), name.as_bytes());
    assert_eq!(crate::mask::glob1(pat, name), want, "glob {pat:?} vs {name:?}");
}

#[cfg(target_os = "linux")]
pub use bpf::seccomp_tables;

#[cfg(target_os = "linux")]
mod bpf {
    use seccompiler::{BpfProgram, sock_filter};
    use std::sync::OnceLock;

    const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const RET_KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    const fn errno(e: i32) -> u32 {
        libc::SECCOMP_RET_ERRNO | e as u32
    }

    #[cfg(target_arch = "x86_64")]
    const NATIVE_ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const NATIVE_ARCH: u32 = 0xC000_00B7;
    #[cfg(target_arch = "riscv64")]
    const NATIVE_ARCH: u32 = 0xC000_00F3;

    /// Policy: denied by both deny-lists, whatever the arguments.
    const DENY: &[i64] = &[
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
        crate::seccomp::SYS_KEXEC_FILE_LOAD,
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
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_pidfd_getfd,
        libc::SYS_kcmp,
        libc::SYS_process_madvise,
        libc::SYS_fspick,
        libc::SYS_quotactl_fd,
        libc::SYS_clock_adjtime,
        crate::seccomp::SYS_LISTMOUNT,
        crate::seccomp::SYS_STATMOUNT,
        libc::SYS_syslog,
    ];

    /// Policy: the validator's unconditional allowlist.
    const VALIDATOR_ALLOW: &[i64] = &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_munmap,
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
        libc::SYS_rseq,
    ];

    /// Numbers worth hitting often (policy edges + ordinary calls).
    const INTERESTING: &[i64] = &[
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_ioctl,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_fcntl,
        libc::SYS_openat,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_personality,
        libc::SYS_connect,
    ];

    struct Tables {
        agent: Vec<BpfProgram>,
        donor: Vec<BpfProgram>,
        validator: BpfProgram,
    }

    fn tables() -> &'static Tables {
        static T: OnceLock<Tables> = OnceLock::new();
        T.get_or_init(|| Tables {
            agent: crate::seccomp::agent_filter().expect("agent filter"),
            donor: crate::seccomp::donor_filter().expect("donor filter"),
            validator: crate::seccomp::validator_filter().expect("validator filter"),
        })
    }

    /// The classic-BPF subset seccompiler emits. Out-of-range loads, jumps past
    /// the end and unknown opcodes panic: each is a table bug.
    fn eval(prog: &[sock_filter], data: &[u8; 64]) -> u32 {
        assert!(!prog.is_empty() && prog.len() <= 4096, "program length {}", prog.len());
        let (mut a, mut pc) = (0u32, 0usize);
        loop {
            let i = &prog[pc];
            let k = i.k;
            let jump = |cond: bool| usize::from(if cond { i.jt } else { i.jf });
            pc += 1 + match i.code {
                0x20 => {
                    let off = k as usize;
                    assert!(off.is_multiple_of(4) && off + 4 <= 64, "load offset {off}");
                    a = u32::from_ne_bytes(data[off..off + 4].try_into().unwrap());
                    0
                }
                0x54 => {
                    a &= k;
                    0
                }
                0x05 => k as usize,
                0x15 => jump(a == k),
                0x25 => jump(a > k),
                0x35 => jump(a >= k),
                0x45 => jump(a & k != 0),
                0x06 => return k,
                c => panic!("unmodelled BPF opcode {c:#x} at {pc}"),
            };
        }
    }

    #[test]
    fn x32_filter_denies_the_x32_range_on_any_host() {
        let prog = crate::seccomp::x32_filter();
        let at = |nr: u32| {
            let mut sd = [0u8; 64];
            sd[0..4].copy_from_slice(&nr.to_ne_bytes());
            eval(&prog, &sd)
        };
        assert_eq!(at(59), RET_ALLOW);
        assert_eq!(at(0x3FFF_FFFF), RET_ALLOW);
        assert_eq!(at(0x4000_0000 | 0x208), errno(libc::EPERM)); // x32 execve (520)
        assert_eq!(at(u32::MAX), errno(libc::EPERM));
    }

    /// The kernel's choice among stacked filters: the lowest action value (as
    /// signed, so KILL_PROCESS wins); on a tie the newest (last) filter.
    fn run(progs: &[BpfProgram], data: &[u8; 64]) -> u32 {
        let action = |r: u32| (r & libc::SECCOMP_RET_ACTION_FULL).cast_signed();
        progs.iter().rev().map(|p| eval(p, data)).reduce(|best, r| if action(r) < action(best) { r } else { best }).unwrap()
    }

    fn deny_list_policy(nr: u32, args: &[u64; 6], donor: bool) -> u32 {
        let n = i64::from(nr);
        if cfg!(target_arch = "x86_64") && nr >= 0x4000_0000 {
            return errno(libc::EPERM); // x32 ABI
        }
        if n == libc::SYS_clone3 {
            return errno(libc::ENOSYS);
        }
        let exec = n == libc::SYS_execve || n == libc::SYS_execveat;
        let tty = n == libc::SYS_ioctl && matches!(args[1] as u32, 0x5412 | 0x541C | 0x5423); // TIOCSTI, TIOCLINUX, TIOCSETD
        let ns = n == libc::SYS_clone && args[0] & 0x7E02_0000 != 0; // every CLONE_NEW*
        // Unix, IPv4, IPv6, netlink only; the donor no new Unix socket and no Unix datagram pair.
        let family = args[0] as u32;
        let socket = n == libc::SYS_socket && (!matches!(family, 1 | 2 | 10 | 16) || (donor && family == 1));
        let pair = donor && n == libc::SYS_socketpair && family == 1 && args[1] as u32 & 0xf == 2;
        let persona = n == libc::SYS_personality && !matches!(args[0] as u32, 0 | 0xFFFF_FFFF);
        if DENY.contains(&n) || (donor && exec) || tty || ns || socket || pair || persona { errno(libc::EPERM) } else { RET_ALLOW }
    }

    fn validator_policy(nr: u32, args: &[u64; 6]) -> u32 {
        let n = i64::from(nr);
        let ok = VALIDATOR_ALLOW.contains(&n)
            || (n == libc::SYS_fcntl && matches!((args[1] as u32).cast_signed(), libc::F_GETFD | libc::F_GETFL))
            || ((n == libc::SYS_mmap || n == libc::SYS_mprotect) && args[2] as u32 & 0x4 == 0); // PROT_EXEC
        if ok { RET_ALLOW } else { RET_KILL }
    }

    fn word(d: &[u8], at: usize) -> u32 {
        let mut b = [0u8; 4];
        for (i, x) in b.iter_mut().enumerate() {
            *x = d.get(at + i).copied().unwrap_or(0);
        }
        u32::from_le_bytes(b)
    }

    /// `data`: [0] nr selector, [1..5] raw nr, [5] arch selector, [6..10] raw
    /// arch, [10..58] six u64 args (missing bytes are zero).
    pub fn seccomp_tables(data: &[u8]) {
        let sel = data.first().copied().unwrap_or(0);
        let nr = match usize::from(sel) {
            s if s < 0x80 => {
                let all: Vec<i64> = DENY.iter().chain(VALIDATOR_ALLOW).chain(INTERESTING).copied().collect();
                all[s % all.len()] as u32
            }
            _ => word(data, 1),
        };
        let foreign = data.get(5).is_some_and(|b| *b >= 0xF0) && word(data, 6) != NATIVE_ARCH;
        let arch = if foreign { word(data, 6) } else { NATIVE_ARCH };
        let mut args = [0u64; 6];
        for (i, a) in args.iter_mut().enumerate() {
            *a = u64::from(word(data, 10 + i * 8)) | (u64::from(word(data, 14 + i * 8)) << 32);
        }
        let mut sd = [0u8; 64];
        sd[0..4].copy_from_slice(&nr.to_ne_bytes());
        sd[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            sd[16 + i * 8..24 + i * 8].copy_from_slice(&a.to_ne_bytes());
        }
        let t = tables();
        let (agent, donor, validator) = (run(&t.agent, &sd), run(&t.donor, &sd), eval(&t.validator, &sd));
        if foreign {
            for (who, r) in [("agent", agent), ("donor", donor), ("validator", validator)] {
                assert_eq!(r, RET_KILL, "{who}: foreign arch {arch:#x} nr {nr} not killed");
            }
            return;
        }
        assert_eq!(agent, deny_list_policy(nr, &args, false), "agent nr {nr} args {args:x?}");
        assert_eq!(donor, deny_list_policy(nr, &args, true), "donor nr {nr} args {args:x?}");
        assert_eq!(validator, validator_policy(nr, &args), "validator nr {nr} args {args:x?}");
    }
}

#[cfg(test)]
mod tests {
    /// xorshift64*: deterministic pseudo-random bytes for the oracles.
    fn bytes(seed: &mut u64, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                *seed ^= *seed >> 12;
                *seed ^= *seed << 25;
                *seed ^= *seed >> 27;
                (seed.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
            })
            .collect()
    }

    #[test]
    fn mask_glob_oracle() {
        for pat in crate::mask::SECRET_PATTERNS {
            for name in [".env", ".env.local", "x.pem", "id_rsa", "credentials", "credentialsX", "a", "", "*", ".pem"] {
                super::mask_glob(format!("{pat}\0{name}").as_bytes());
            }
        }
        for c in ["*\0", "a*\0a", "*a\0a", "a*a\0a", "a*a\0aa", "ab*ba\0aba", "*.key\0.key", "x\0x", "**\0", "*a*\0bab", "*.t.*\0x.t.y", "a**b\0ab"] {
            super::mask_glob(c.as_bytes());
        }
        let mut seed = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            let mut b = bytes(&mut seed, 8);
            for x in &mut b {
                *x = b"a*.\0"[usize::from(*x % 4)];
            }
            super::mask_glob(&b);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_tables_oracle() {
        // Every listed number, with the arguments that flip each rule.
        let edges: [[u8; 8]; 12] = [
            [0; 8],
            0x5412u64.to_le_bytes(),                // TIOCSTI
            (0x5412u64 | 0xFFFF_0000_0000).to_le_bytes(), // TIOCSTI + high bits
            0x5423u64.to_le_bytes(),                // TIOCSETD
            0x1000_0000u64.to_le_bytes(),           // CLONE_NEWUSER
            0x4000_0000u64.to_le_bytes(),           // CLONE_NEWNET
            0x4u64.to_le_bytes(),                   // PROT_EXEC
            1u64.to_le_bytes(),                     // AF_UNIX
            2u64.to_le_bytes(),                     // AF_INET, SOCK_DGRAM
            40u64.to_le_bytes(),                    // AF_VSOCK
            0x0040_0000u64.to_le_bytes(),           // ADDR_NO_RANDOMIZE
            [0xFF; 8],
        ];
        for sel in 0u8..0x80 {
            for arg in &edges {
                let mut d = vec![sel, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                for _ in 0..6 {
                    d.extend_from_slice(arg);
                }
                super::seccomp_tables(&d);
            }
        }
        // x32 / huge numbers and a foreign arch.
        let mut d = vec![0xFF, 0x3B, 0, 0, 0x40, 0xFF, 0x03, 0, 0, 0x40];
        d.resize(58, 0);
        super::seccomp_tables(&d);
        d[5] = 0;
        super::seccomp_tables(&d);
        let mut seed = 0xD1B5_4A32_D192_ED03;
        for _ in 0..20_000 {
            super::seccomp_tables(&bytes(&mut seed, 58));
        }
    }
}
