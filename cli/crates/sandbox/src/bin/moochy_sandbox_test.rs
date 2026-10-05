//! Test driver for `moochy-sandbox`. Two roles:
//!  - **probes**: tiny actions used as the command *inside* a maintainer sandbox
//!    (`read`, `write`, `connect`, `exec`, `hardlink`, `tiocsti`).
//!  - **self-tests**: `donor` and `validator` call the library and report, so the
//!    integration tests can run them as a subprocess (the donor lockdown is
//!    irreversible and would otherwise kill the test runner).
//!
//! Raw syscalls here are for *attempting* denied operations to prove they fail;
//! this is a test binary, not the library hot path.
#![allow(unsafe_code)]
#![allow(clippy::print_stderr, clippy::print_stdout)]
// Test-only driver (never shipped, never on a hot path): AGENTS.md §3 exempts
// tests from the slicing/arithmetic/cast denies.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::map_unwrap_or,
    clippy::items_after_statements
)]

use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let rest = &args[2.min(args.len())..];
    match cmd {
        "read" => probe_read(rest),
        "write" => probe_write(rest),
        "stat" => probe_stat(rest),
        "connect" => probe_connect(rest),
        "http" => probe_http(rest),
        "proxy" => probe_proxy(rest),
        "exec" => probe_exec(rest),
        "hardlink" => probe_hardlink(rest),
        "symlink" => probe_symlink(rest),
        "tiocsti" => probe_tiocsti(),
        "env" => probe_env(rest),
        "exec-sh" => probe_exec_sh(rest),
        "sleep" => probe_sleep(rest),
        "forkbomb" => probe_forkbomb(),
        "memhog" => probe_memhog(),
        #[cfg(target_os = "linux")]
        "ptrace" => probe_ptrace(rest),
        #[cfg(target_os = "linux")]
        "sys" => probe_sys(),
        #[cfg(target_os = "linux")]
        "statfs" => probe_statfs(rest),
        #[cfg(target_os = "linux")]
        "landlock-abi" => probe_landlock_abi(),
        #[cfg(target_os = "linux")]
        "keyring-run" => keyring_run(rest),
        "unix-connect" => probe_unix_connect(rest),
        "rawtty" => probe_rawtty(),
        "run" => run_sandbox(rest),
        #[cfg(target_os = "linux")]
        "donor" => donor_selftest(rest),
        #[cfg(target_os = "linux")]
        "validator" => validator_selftest(rest),
        #[cfg(target_os = "macos")]
        "donor" => donor_selftest_macos(rest),
        #[cfg(target_os = "macos")]
        "validator" => validator_selftest_macos(rest),
        #[cfg(target_os = "macos")]
        "zygote" => zygote_selftest_macos(),
        other => {
            eprintln!("unknown subcommand: {other}");
            ExitCode::from(2)
        }
    }
}

fn ok() -> ExitCode {
    ExitCode::SUCCESS
}
fn no() -> ExitCode {
    ExitCode::FAILURE
}

fn probe_read(a: &[String]) -> ExitCode {
    let Some(p) = a.first() else { return ExitCode::from(2) };
    match std::fs::read(p) {
        Ok(b) => {
            println!("read-ok {p} len={}", b.len());
            ok()
        }
        Err(e) => {
            println!("read-fail {p} {e}");
            no()
        }
    }
}

fn probe_write(a: &[String]) -> ExitCode {
    let Some(p) = a.first() else { return ExitCode::from(2) };
    match std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(p) {
        Ok(mut f) => match f.write_all(b"moochy") {
            Ok(()) => {
                println!("write-ok {p}");
                ok()
            }
            Err(e) => {
                println!("write-fail {p} {e}");
                no()
            }
        },
        Err(e) => {
            println!("write-fail {p} {e}");
            no()
        }
    }
}

fn probe_stat(a: &[String]) -> ExitCode {
    let Some(p) = a.first() else { return ExitCode::from(2) };
    match std::fs::symlink_metadata(p) {
        Ok(_) => {
            println!("stat-ok {p}");
            ok()
        }
        Err(e) => {
            println!("stat-fail {p} {e}");
            no()
        }
    }
}

fn probe_connect(a: &[String]) -> ExitCode {
    let Some(addr) = a.first() else { return ExitCode::from(2) };
    use std::net::TcpStream;
    use std::time::Duration;
    let Ok(sa) = addr.parse() else {
        println!("connect-badaddr {addr}");
        return ExitCode::from(2);
    };
    match TcpStream::connect_timeout(&sa, Duration::from_millis(800)) {
        Ok(_) => {
            println!("connect-ok {addr}");
            ok()
        }
        Err(e) => {
            println!("connect-fail {addr} {e}");
            no()
        }
    }
}

fn probe_exec(a: &[String]) -> ExitCode {
    let Some(prog) = a.first() else { return ExitCode::from(2) };
    match std::process::Command::new(prog).arg("-c").arg("true").status() {
        Ok(s) => {
            println!("exec-ran {prog} {s:?}");
            ok()
        }
        Err(e) => {
            println!("exec-fail {prog} {e}");
            no()
        }
    }
}

fn probe_hardlink(a: &[String]) -> ExitCode {
    let (Some(src), Some(dst)) = (a.first(), a.get(1)) else { return ExitCode::from(2) };
    match std::fs::hard_link(src, dst) {
        Ok(()) => {
            // Did we actually get the real content, or the masked empty file?
            let len = std::fs::metadata(dst).map(|m| m.len()).unwrap_or(0);
            println!("hardlink-ok {src} {dst} len={len}");
            ok()
        }
        Err(e) => {
            println!("hardlink-fail {src} {dst} {e}");
            no()
        }
    }
}

fn probe_symlink(a: &[String]) -> ExitCode {
    let (Some(src), Some(dst)) = (a.first(), a.get(1)) else { return ExitCode::from(2) };
    match std::os::unix::fs::symlink(src, dst).and_then(|()| {
        let mut s = String::new();
        std::fs::File::open(dst)?.read_to_string(&mut s)?;
        Ok(s.len())
    }) {
        Ok(n) => {
            println!("symlink-read {src} {dst} len={n}");
            ok()
        }
        Err(e) => {
            println!("symlink-fail {src} {dst} {e}");
            no()
        }
    }
}

fn probe_tiocsti() -> ExitCode {
    let ch = libc::c_char::from_ne_bytes(*b"x");
    // SAFETY: attempt the injection ioctl on stdin (the platform's own TIOCSTI number);
    // seccomp (Linux) or the session/profile (macOS) must block it.
    let r = unsafe { libc::ioctl(0, libc::TIOCSTI, std::ptr::addr_of!(ch)) };
    if r == 0 {
        println!("tiocsti-ok (INJECTION SUCCEEDED — bad)");
        ok()
    } else {
        let e = std::io::Error::last_os_error();
        println!("tiocsti-fail {e}");
        no()
    }
}

fn probe_env(a: &[String]) -> ExitCode {
    let Some(k) = a.first() else { return ExitCode::from(2) };
    match std::env::var(k) {
        Ok(v) => {
            println!("env-present {k} len={}", v.len());
            ok()
        }
        Err(_) => {
            println!("env-absent {k}");
            no()
        }
    }
}

/// `sys`: try each call the jail's seccomp must refuse, with harmless arguments, and print the
/// errno (0 = it ran). Unfiltered, none of these fails with EPERM for an unprivileged process
/// (except `fspick`, which needs CAP_SYS_ADMIN): EPERM here means the filter answered.
#[cfg(target_os = "linux")]
fn probe_sys() -> ExitCode {
    fn report(name: &str, r: libc::c_long) {
        let e = if r < 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) } else { 0 };
        println!("sys {name} errno={e}");
    }
    // SAFETY: every call gets invalid fds, an invalid type or a NULL buffer the kernel rejects
    // before touching memory; personality only changes this short-lived probe; a socket that
    // opens is closed at once; clone with CLONE_THREAD but no CLONE_SIGHAND creates nothing.
    unsafe {
        report("pidfd_getfd", libc::syscall(libc::SYS_pidfd_getfd, -1, -1, 0));
        let me = libc::getpid();
        report("kcmp", libc::syscall(libc::SYS_kcmp, me, me, 99, 0, 0));
        report("personality", libc::syscall(libc::SYS_personality, 0x0040_0000)); // ADDR_NO_RANDOMIZE
        report("personality-query", libc::syscall(libc::SYS_personality, 0xFFFF_FFFFu32));
        report("process_madvise", libc::syscall(libc::SYS_process_madvise, -1, 0, 0, 0, 0));
        report("fspick", libc::syscall(libc::SYS_fspick, -1, c"".as_ptr(), 0));
        report("quotactl_fd", libc::syscall(libc::SYS_quotactl_fd, -1, 0, 0, 0));
        let mut tx = [0u8; 512];
        report("clock_adjtime", libc::syscall(libc::SYS_clock_adjtime, 999, tx.as_mut_ptr()));
        report("listmount", libc::syscall(458, 0, 0, 0, 0));
        report("statmount", libc::syscall(457, 0, 0, 0, 0));
        report("syslog", libc::syscall(libc::SYS_syslog, 10, 0, 0)); // SYSLOG_ACTION_SIZE_BUFFER
        let ldisc: libc::c_int = 0;
        report("tiocsetd", libc::c_long::from(libc::ioctl(0, 0x5423, &raw const ldisc)));
        for (name, flag) in [("newnet", 0x4000_0000), ("newpid", 0x2000_0000), ("newipc", 0x0800_0000), ("newuts", 0x0400_0000), ("newcgroup", 0x0200_0000)] {
            report(&format!("clone-{name}"), libc::syscall(libc::SYS_clone, flag | libc::CLONE_THREAD, 0, 0, 0, 0));
        }
        for (name, domain, ty) in [
            ("vsock", 40, libc::SOCK_STREAM),
            ("alg", 38, libc::SOCK_SEQPACKET),
            ("inet", libc::AF_INET, libc::SOCK_STREAM),
            ("unix", libc::AF_UNIX, libc::SOCK_STREAM),
            ("netlink", libc::AF_NETLINK, libc::SOCK_RAW),
        ] {
            let fd = libc::socket(domain, ty | libc::SOCK_CLOEXEC, 0);
            report(&format!("socket-{name}"), libc::c_long::from(fd));
            if fd >= 0 {
                libc::close(fd);
            }
        }
    }
    ok()
}

/// `statfs <path>`: size in bytes and inode count of the filesystem holding `path`.
#[cfg(target_os = "linux")]
fn probe_statfs(a: &[String]) -> ExitCode {
    let Some(p) = a.first() else { return ExitCode::from(2) };
    let c = std::ffi::CString::new(p.as_str()).unwrap_or_default();
    // SAFETY: statvfs fills a zeroed, properly sized struct from a valid C string.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &raw mut st) } != 0 {
        println!("statfs-fail {p} {}", std::io::Error::last_os_error());
        return no();
    }
    println!("statfs {p} bytes={} files={}", st.f_blocks * st.f_frsize, st.f_files);
    ok()
}

/// `landlock-abi`: this kernel's Landlock ABI (0 = none).
#[cfg(target_os = "linux")]
fn probe_landlock_abi() -> ExitCode {
    // SAFETY: NULL attr, size 0, LANDLOCK_CREATE_RULESET_VERSION: the kernel reads no memory.
    let r = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<libc::c_void>(), 0usize, 1u32) };
    println!("landlock-abi {}", r.max(0));
    ok()
}

/// `keyring-run <run args…>`: in a fresh session keyring, add a key only its possessors may
/// see (perm 0x3f000000), then act as `run`: a jail that keeps the session shows it in
/// /proc/keys.
#[cfg(target_os = "linux")]
fn keyring_run(a: &[String]) -> ExitCode {
    // SAFETY: keyctl/add_key with valid C strings and a 1-byte payload.
    let id = unsafe {
        libc::syscall(libc::SYS_keyctl, 1, std::ptr::null::<libc::c_char>()); // KEYCTL_JOIN_SESSION_KEYRING
        libc::syscall(libc::SYS_add_key, c"user".as_ptr(), c"moochy-probe-key".as_ptr(), b"x".as_ptr(), 1usize, -3) // KEY_SPEC_SESSION_KEYRING
    };
    // SAFETY: KEYCTL_SETPERM on the key just made.
    if id < 0 || unsafe { libc::syscall(libc::SYS_keyctl, 5, id, 0x3f00_0000u32) } < 0 {
        println!("keyring-unavailable {}", std::io::Error::last_os_error());
        return ok();
    }
    run_sandbox(a.get(1..).unwrap_or_default())
}

/// `unix-connect <path>`: connect to a pathname Unix socket.
fn probe_unix_connect(a: &[String]) -> ExitCode {
    let Some(p) = a.first() else { return ExitCode::from(2) };
    match std::os::unix::net::UnixStream::connect(p) {
        Ok(_) => {
            println!("unix-connect-ok {p}");
            ok()
        }
        Err(e) => {
            println!("unix-connect-fail {p} {e}");
            no()
        }
    }
}

/// `rawtty`: put the terminal on stdin in raw mode without echo, as a TUI agent does, and exit.
fn probe_rawtty() -> ExitCode {
    // SAFETY: tcgetattr/tcsetattr on fd 0 with a zeroed termios the call fills in.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &raw mut t) } != 0 {
        println!("rawtty-fail {}", std::io::Error::last_os_error());
        return no();
    }
    t.c_lflag &= !(libc::ECHO | libc::ICANON);
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw const t) } != 0 {
        println!("rawtty-fail {}", std::io::Error::last_os_error());
        return no();
    }
    println!("rawtty-ok");
    ok()
}

// ───────────────────────── self-tests (Linux) ─────────────────────────

#[cfg(target_os = "linux")]
fn donor_selftest(a: &[String]) -> ExitCode {
    use std::path::PathBuf;
    let state = a.first().cloned().unwrap_or_else(|| "/tmp".into());
    let relay_port: u16 = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(8443);

    let canary = a.get(2).cloned().unwrap_or_default();
    let gw_port: Option<u16> = a.get(3).and_then(|s| s.parse().ok());
    // A copied binary inside the (writable) state dir: exec must still fail.
    let copy = format!("{state}/true-copy");
    let _ = std::fs::copy("/bin/true", &copy);
    let mut policy = moochy_sandbox::DonorPolicy::new(PathBuf::from(&state), relay_port);
    policy.gateway_port = gw_port;
    // G22: a pathname socket like the user D-Bus, here in the (Landlock-writable) state dir.
    let bus = format!("{state}/bus.sock");
    let _ = std::fs::remove_file(&bus);
    let _bus = std::os::unix::net::UnixListener::bind(&bus);
    match moochy_sandbox::lockdown_self(&policy) {
        Ok(r) => println!(
            "lockdown-ok nnp={} seccomp={} fs={} net={:?} abi={}",
            r.no_new_privs, r.seccomp, r.landlock_fs, r.landlock_net, r.abi
        ),
        Err(e) => {
            println!("lockdown-fail {e}");
            return ExitCode::from(71);
        }
    }

    // Exec must be denied (EPERM), several ways.
    report_exec_denied("sh", exec_path(c"/bin/sh"));
    report_exec_denied("env", exec_path(c"/usr/bin/env"));
    let copy_c = std::ffi::CString::new(copy.clone()).unwrap_or_default();
    report_exec_denied("copied-binary", exec_path(&copy_c));
    report_exec_denied("execveat-fd", exec_via_fd(&copy_c));
    report_exec_denied("memfd", exec_via_memfd());

    // Reading an existing secret outside the state dir must fail.
    match std::fs::read(&canary) {
        Ok(_) => println!("canary-read-ok (BAD) {canary}"),
        Err(e) => println!("canary-read-fail {e}"),
    }
    // No new Unix socket reaches a pathname socket; connected pairs still work.
    match std::os::unix::net::UnixStream::connect(&bus) {
        Ok(_) => println!("unix-connect-ok (BAD)"),
        Err(e) => println!("unix-connect-fail {e}"),
    }
    match std::os::unix::net::UnixDatagram::unbound() {
        Ok(_) => println!("unix-dgram-ok (BAD)"),
        Err(e) => println!("unix-dgram-fail {e}"),
    }
    match std::os::unix::net::UnixDatagram::pair() {
        Ok(_) => println!("unix-dgram-pair-ok (BAD)"),
        Err(e) => println!("unix-dgram-pair-fail {e}"),
    }
    match std::os::unix::net::UnixStream::pair() {
        Ok(_) => println!("unix-pair-ok"),
        Err(e) => println!("unix-pair-fail (BAD) {e}"),
    }
    // Writing inside the state dir still works (outbox).
    match std::fs::write(format!("{state}/outbox.probe"), b"x") {
        Ok(()) => println!("state-write-ok"),
        Err(e) => println!("state-write-fail (BAD) {e}"),
    }

    // Connecting to a non-allowed port must fail.
    use std::net::{TcpListener, TcpStream, ToSocketAddrs as _};
    use std::time::Duration;
    if let Ok(sa) = "127.0.0.1:9".parse() {
        match TcpStream::connect_timeout(&sa, Duration::from_millis(300)) {
            Ok(_) => println!("connect9-ok (BAD)"),
            Err(e) => println!("connect9-fail {e}"),
        }
    }
    // The donor must still resolve provider hosts and reach them on 443.
    let host = std::env::var("MOOCHY_DNS_PROBE_HOST").unwrap_or_else(|_| "api.anthropic.com".into());
    match (host.as_str(), 443).to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            let ok443 = addrs.iter().any(|sa| TcpStream::connect_timeout(sa, Duration::from_secs(5)).is_ok());
            if ok443 {
                println!("dns-ok https-connect-ok");
            } else {
                println!("dns-ok https-connect-fail (BAD) {addrs:?}");
            }
        }
        Err(e) => println!("dns-fail (BAD) {e}"),
    }
    if let Some(p) = gw_port {
        match TcpListener::bind(("127.0.0.1", p)) {
            Ok(_) => println!("gw-bind-ok"),
            Err(e) => println!("gw-bind-fail (BAD) {e}"),
        }
    }
    match TcpListener::bind("127.0.0.1:0") {
        Ok(_) => println!("bind-other-ok (BAD)"),
        Err(e) => println!("bind-other-fail {e}"),
    }
    ok()
}

#[cfg(target_os = "linux")]
fn report_exec_denied(label: &str, errno: i32) {
    if errno == 0 {
        println!("exec-{label} SUCCEEDED (BAD)");
    } else {
        println!("exec-{label}-denied errno={errno}");
    }
}

/// Try `execve(path)`, return errno (0 means it unexpectedly succeeded).
#[cfg(target_os = "linux")]
fn exec_path(path: &std::ffi::CStr) -> i32 {
    let argv: [*const libc::c_char; 2] = [path.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: execve either replaces the process (never returns) or fails.
    unsafe {
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

#[cfg(target_os = "linux")]
fn exec_via_fd(path: &std::ffi::CStr) -> i32 {
    // SAFETY: open a readable binary and attempt execveat on the fd.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            println!("execveat-open-failed {}", std::io::Error::last_os_error());
            return -1;
        }
        let empty = c"";
        let argv: [*const libc::c_char; 1] = [std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        libc::syscall(
            libc::SYS_execveat,
            fd,
            empty.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        libc::close(fd);
        e
    }
}

#[cfg(target_os = "linux")]
fn exec_via_memfd() -> i32 {
    // SAFETY: create an anonymous memfd and attempt to execve it.
    unsafe {
        let fd = libc::memfd_create(c"m".as_ptr(), 0);
        if fd < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        }
        let path = format!("/proc/self/fd/{fd}\0");
        let argv: [*const libc::c_char; 1] = [std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        libc::execve(path.as_ptr().cast(), argv.as_ptr(), envp.as_ptr());
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        libc::close(fd);
        e
    }
}

/// `validator echo|open|socket`. `echo`: the child reads a length-prefixed
/// request, parses it with allocation + a HashMap (RNG seeding), and writes the
/// reversed bytes back — proves the allowlist is enough for real parsing.
/// `open`/`socket`: the child attempts the forbidden call; seccomp must kill it
/// (SIGSYS) before it can report anything.
#[cfg(target_os = "linux")]
fn validator_selftest(a: &[String]) -> ExitCode {
    let mode = a.first().cloned().unwrap_or_else(|| "echo".into());
    if mode == "fds" || mode == "stream" {
        return validator_fds_and_stream(&mode);
    }
    let m2 = mode.clone();
    let v = moochy_sandbox::spawn_validator(move |fd: RawFd| -> i32 {
        match m2.as_str() {
            "open" => {
                let _ = std::fs::File::open("/etc/hostname");
                write_fd(fd, b"OPENED\n");
                0
            }
            "socket" => {
                let _ = std::net::TcpStream::connect("127.0.0.1:9");
                write_fd(fd, b"SOCKET\n");
                0
            }
            _ => {
                let mut hdr = [0u8; 4];
                if read_fd(fd, &mut hdr) != 4 {
                    return 3;
                }
                let n = u32::from_be_bytes(hdr) as usize;
                let mut body = vec![0u8; n];
                if read_fd(fd, &mut body) != n {
                    return 4;
                }
                let mut seen = std::collections::HashMap::new();
                for b in &body {
                    *seen.entry(*b).or_insert(0u32) += 1;
                }
                body.reverse();
                write_fd(fd, &(body.len() as u32).to_be_bytes());
                write_fd(fd, &body);
                0
            }
        }
    });
    let mut v = match v {
        Ok(v) => v,
        Err(e) => {
            println!("validator-spawn-fail {e}");
            return ExitCode::from(71);
        }
    };
    let mut out = Vec::new();
    if mode == "echo" {
        let req = b"moochy-request";
        let _ = v.sock.write_all(&(req.len() as u32).to_be_bytes());
        let _ = v.sock.write_all(req);
    }
    let _ = v.sock.read_to_end(&mut out);
    let code = v.wait().unwrap_or(-1);
    println!("validator-{mode} exit={code} out={:?}", String::from_utf8_lossy(&out));
    let good = match mode.as_str() {
        "echo" => code == 0 && out.ends_with(b"tseuqer-yhcoom"),
        _ => code == 128 + 31 && out.is_empty(), // SIGSYS, nothing written
    };
    if good { ok() } else { no() }
}

#[cfg(target_os = "linux")]
fn read_fd(fd: RawFd, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        // SAFETY: fd is the inherited socketpair end; the slice is valid.
        let r = unsafe { libc::read(fd, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if r <= 0 {
            break;
        }
        got += r as usize;
    }
    got
}

#[cfg(target_os = "linux")]
fn write_fd(fd: RawFd, msg: &[u8]) {
    // SAFETY: fd is the inherited socketpair end, valid for the call.
    unsafe {
        libc::write(fd, msg.as_ptr().cast(), msg.len());
    }
}

/// `run <worktree> [--ro P]... [--gw SOCK] [--token T] [--nproc N] [--mem B] -- CMD ARGS...`
fn run_sandbox(a: &[String]) -> ExitCode {
    use std::path::PathBuf;
    let Some(wt) = a.first() else { return ExitCode::from(2) };
    let mut spec = moochy_sandbox::Spec::new(PathBuf::from(wt));
    let mut i = 1;
    let mut cmd: Vec<std::ffi::OsString> = Vec::new();
    while let Some(arg) = a.get(i) {
        let val = a.get(i + 1).cloned().unwrap_or_default();
        match arg.as_str() {
            "--ro" => spec.ro_paths.push(PathBuf::from(val)),
            "--rw" => spec.rw_paths.push(PathBuf::from(val)),
            "--gw" => spec.gateway_socket = Some(PathBuf::from(val)),
            "--gw-port" => spec.gateway_loopback_port = val.parse().ok(),
            "--token" => spec.run_token = Some(val),
            "--git-writable" => {
                spec.git_writable = true;
                i += 1;
                continue;
            }
            "--nproc" => spec.limits.processes = val.parse().unwrap_or(64),
            "--mem" => spec.limits.memory_bytes = val.parse().unwrap_or(1 << 30),
            "--mem-total" => spec.limits.memory_total_bytes = val.parse().unwrap_or(0),
            "--cpu-percent" => spec.limits.cpu_percent = val.parse().unwrap_or(0),
            "--allow-host" => spec.allow_hosts.push(val),
            "--wall" => spec.limits.wall_seconds = val.parse().unwrap_or(0),
            "--env" => {
                if let Some((k, v)) = val.split_once('=') {
                    spec.env.insert(k.into(), v.into());
                }
            }
            "--" => {
                cmd = a[i + 1..].iter().map(Into::into).collect();
                break;
            }
            _ => {
                eprintln!("bad flag {arg}");
                return ExitCode::from(2);
            }
        }
        i += 2;
    }
    let Some((prog, rest)) = cmd.split_first() else { return ExitCode::from(2) };
    match spec.run(prog, rest) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(255)),
        Err(e) => {
            eprintln!("moochy-sandbox: {e}");
            ExitCode::from(125)
        }
    }
}

fn probe_sleep(a: &[String]) -> ExitCode {
    let secs: u64 = a.first().and_then(|s| s.parse().ok()).unwrap_or(1);
    std::thread::sleep(std::time::Duration::from_secs(secs));
    ok()
}

/// Bounded fork bomb: try to create many children; report how many succeeded.
fn probe_forkbomb() -> ExitCode {
    let mut kids = Vec::new();
    let mut failed = false;
    for _ in 0..2000 {
        match std::process::Command::new("/proc/self/exe").arg("sleep").arg("5").spawn() {
            Ok(c) => kids.push(c),
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    println!("forkbomb spawned={} hit_limit={failed}", kids.len());
    for mut k in kids {
        let _ = k.kill();
        let _ = k.wait();
    }
    if failed { ok() } else { no() }
}

/// Allocate and touch memory until refused; report.
fn probe_memhog() -> ExitCode {
    let mut v: Vec<Vec<u8>> = Vec::new();
    for i in 0..64u32 {
        let mut chunk = Vec::new();
        if chunk.try_reserve_exact(64 << 20).is_err() {
            println!("memhog refused after {} MiB", i * 64);
            return ok();
        }
        chunk.resize(64 << 20, 1u8);
        v.push(chunk);
    }
    println!("memhog allocated 4096 MiB (no limit hit)");
    no()
}

/// Try to ptrace-attach to a pid (e.g. our parent).
#[cfg(target_os = "linux")]
fn probe_ptrace(a: &[String]) -> ExitCode {
    let pid: i32 = a.first().and_then(|s| s.parse().ok()).unwrap_or(1);
    // SAFETY: PTRACE_ATTACH with no data pointers; we detach if it worked.
    let r = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) };
    if r == 0 {
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };
        println!("ptrace-ok {pid} (BAD)");
        ok()
    } else {
        println!("ptrace-fail {pid} {}", std::io::Error::last_os_error());
        no()
    }
}

/// `http <ip:port>`: one HTTP/1.0 GET; prints the status line and body length.
fn probe_http(a: &[String]) -> ExitCode {
    let Some(addr) = a.first() else { return ExitCode::from(2) };
    let res = (|| -> std::io::Result<String> {
        let sa = addr.parse().map_err(|_| std::io::Error::other("bad addr"))?;
        let mut s = std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(2))?;
        s.write_all(b"GET /v1/models HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")?;
        let mut out = String::new();
        s.read_to_string(&mut out)?;
        Ok(out)
    })();
    match res {
        Ok(body) => {
            println!("http-ok {addr} {}", body.lines().next().unwrap_or("").trim());
            ok()
        }
        Err(e) => {
            println!("http-fail {addr} {e}");
            no()
        }
    }
}

/// `proxy <addr|env> <host:port>`: send a CONNECT through the proxy at `addr`
/// (`env`: the one `HTTPS_PROXY` names) and print its status line.
fn probe_proxy(a: &[String]) -> ExitCode {
    let (Some(addr), Some(target)) = (a.first(), a.get(1)) else { return ExitCode::from(2) };
    let from_env = std::env::var("HTTPS_PROXY").unwrap_or_default();
    let addr = if addr == "env" { from_env.trim_start_matches("http://").trim_end_matches('/') } else { addr.as_str() };
    let res = (|| -> std::io::Result<String> {
        let sa = addr.parse().map_err(|_| std::io::Error::other("bad addr"))?;
        let mut s = std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(2))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(20)))?;
        write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")?;
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string())
    })();
    match res {
        Ok(line) => {
            println!("proxy-status {target} {line}");
            ok()
        }
        Err(e) => {
            println!("proxy-fail {target} {e}");
            no()
        }
    }
}

/// macOS donor self-test (Seatbelt via `sandbox_init`): `donor <state> <relay_port> <canary> [gw_port]`.
/// After the lockdown nothing can be spawned, only the state dir is reachable, and
/// outbound TCP is limited to 443 + the relay port; DNS for providers still works.
#[cfg(target_os = "macos")]
fn donor_selftest_macos(a: &[String]) -> ExitCode {
    use std::net::{TcpListener, TcpStream, ToSocketAddrs as _};
    use std::path::PathBuf;
    use std::time::Duration;
    let state = a.first().cloned().unwrap_or_else(|| "/tmp".into());
    let relay_port: u16 = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(8443);
    let canary = a.get(2).cloned().unwrap_or_default();
    let gw_port: Option<u16> = a.get(3).and_then(|s| s.parse().ok());
    let copy = format!("{state}/true-copy");
    let _ = std::fs::copy("/usr/bin/true", &copy);
    let mut policy = moochy_sandbox::DonorPolicy::new(PathBuf::from(&state), relay_port);
    policy.gateway_port = gw_port;
    match moochy_sandbox::lockdown_self(&policy) {
        Ok(r) => println!("lockdown-ok fs={} net={:?}", r.landlock_fs, r.landlock_net),
        Err(e) => {
            println!("lockdown-fail {e}");
            return ExitCode::from(71);
        }
    }
    for (label, prog) in [("sh", "/bin/sh"), ("env", "/usr/bin/env"), ("copied-binary", copy.as_str())] {
        match std::process::Command::new(prog).arg("-c").arg("true").status() {
            Ok(st) => println!("exec-{label} SUCCEEDED (BAD) {st:?}"),
            Err(e) => println!("exec-{label}-denied {e}"),
        }
    }
    match std::fs::read(&canary) {
        Ok(_) => println!("canary-read-ok (BAD) {canary}"),
        Err(e) => println!("canary-read-fail {e}"),
    }
    match std::fs::write(format!("{state}/outbox.probe"), b"x") {
        Ok(()) => println!("state-write-ok"),
        Err(e) => println!("state-write-fail (BAD) {e}"),
    }
    if let Ok(sa) = "127.0.0.1:9".parse() {
        match TcpStream::connect_timeout(&sa, Duration::from_millis(300)) {
            Ok(_) => println!("connect9-ok (BAD)"),
            Err(e) => println!("connect9-fail {e}"),
        }
    }
    match ("api.anthropic.com", 443).to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(sa) => match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
                Ok(_) => println!("dns-ok https-connect-ok"),
                Err(e) => println!("dns-ok https-connect-fail (BAD) {e}"),
            },
            None => println!("dns-empty (BAD)"),
        },
        Err(e) => println!("dns-fail (BAD) {e}"),
    }
    if let Some(p) = gw_port {
        match TcpListener::bind(("127.0.0.1", p)) {
            Ok(_) => println!("gw-bind-ok"),
            Err(e) => println!("gw-bind-fail (BAD) {e}"),
        }
    }
    match TcpListener::bind("127.0.0.1:0") {
        Ok(_) => println!("bind-other-ok (BAD)"),
        Err(e) => println!("bind-other-fail {e}"),
    }
    ok()
}

/// macOS validator self-test: `validator echo|open|socket`. The child runs under
/// the no-file/no-network/no-exec profile; `echo` must round-trip, `open` and
/// `socket` must be refused (the child reports, then exits 0).
#[cfg(target_os = "macos")]
fn validator_selftest_macos(a: &[String]) -> ExitCode {
    use std::os::unix::io::{FromRawFd as _, RawFd};
    let mode = a.first().cloned().unwrap_or_else(|| "echo".into());
    let m2 = mode.clone();
    let v = moochy_sandbox::spawn_validator(move |fd: RawFd| -> i32 {
        // SAFETY (test-only): the child owns the inherited socketpair end.
        let mut sock = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        match m2.as_str() {
            "open" => {
                let r = std::fs::File::open("/etc/hosts").is_ok();
                let _ = sock.write_all(if r { b"OPEN-ALLOWED" } else { b"OPEN-DENIED" });
                0
            }
            "socket" => {
                let r = std::net::TcpStream::connect("1.1.1.1:443").is_ok();
                let _ = sock.write_all(if r { b"SOCKET-ALLOWED" } else { b"SOCKET-DENIED" });
                0
            }
            "exec" => {
                let r = std::process::Command::new("/usr/bin/true").status().is_ok();
                let _ = sock.write_all(if r { b"EXEC-ALLOWED" } else { b"EXEC-DENIED" });
                0
            }
            "fork" => {
                // SAFETY (test-only): a bare fork; a child that appears exits at once.
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    // SAFETY: immediate exit in the forked child.
                    unsafe { libc::_exit(0) };
                }
                let _ = sock.write_all(if pid > 0 { b"FORK-ALLOWED" } else { b"FORK-DENIED" });
                0
            }
            _ => {
                let mut hdr = [0u8; 4];
                if sock.read_exact(&mut hdr).is_err() {
                    return 3;
                }
                let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
                if sock.read_exact(&mut body).is_err() {
                    return 4;
                }
                let mut seen = std::collections::HashMap::new();
                for b in &body {
                    *seen.entry(*b).or_insert(0u32) += 1;
                }
                body.reverse();
                let _ = sock.write_all(&(body.len() as u32).to_be_bytes());
                let _ = sock.write_all(&body);
                0
            }
        }
    });
    let mut v = match v {
        Ok(v) => v,
        Err(e) => {
            println!("validator-spawn-fail {e}");
            return ExitCode::from(71);
        }
    };
    if mode == "echo" {
        let req = b"moochy-request";
        let _ = v.sock.write_all(&(req.len() as u32).to_be_bytes());
        let _ = v.sock.write_all(req);
    }
    let mut out = Vec::new();
    let _ = v.sock.read_to_end(&mut out);
    let code = v.wait().unwrap_or(-1);
    println!("validator-{mode} exit={code} out={:?}", String::from_utf8_lossy(&out));
    let good = match mode.as_str() {
        "echo" => code == 0 && out.ends_with(b"tseuqer-yhcoom"),
        _ => out.ends_with(b"-DENIED"),
    };
    if good { ok() } else { no() }
}

/// `validator fds`: the parent holds an open, writable file; the child tries to
/// write to that fd number (it must have been closed: EBADF) — proves no parent
/// fd (relay/provider sockets, outbox) survives into the validator.
/// `validator stream`: the safe `spawn_validator_with` entry point round-trips.
#[cfg(target_os = "linux")]
fn validator_fds_and_stream(mode: &str) -> ExitCode {
    use std::os::fd::AsRawFd as _;
    let leak_path = std::env::temp_dir().join(format!("moochy-fdleak-{}", std::process::id()));
    let leak = std::fs::File::create(&leak_path).unwrap_or_else(|_| std::process::exit(2));
    // Park it on a high fd so it cannot alias the child's channel (fd 3).
    let leak_fd = unsafe { libc::fcntl(leak.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 50) };
    let v = if mode == "fds" {
        moochy_sandbox::spawn_validator_with(move |mut ch| {
            let r = unsafe { libc::write(leak_fd, b"LEAK".as_ptr().cast(), 4) };
            let _ = ch.write_all(if r == 4 { b"WROTE" } else { b"EBADF" });
            0
        })
    } else {
        moochy_sandbox::spawn_validator_with(|mut ch| {
            let mut b = [0u8; 4];
            if ch.read_exact(&mut b).is_err() {
                return 3;
            }
            let _ = ch.write_all(&b.map(|x| x.to_ascii_uppercase()));
            0
        })
    };
    let mut v = match v {
        Ok(v) => v,
        Err(e) => {
            println!("validator-spawn-fail {e}");
            return ExitCode::from(71);
        }
    };
    if mode == "stream" {
        let _ = v.sock.write_all(b"ping");
    }
    let mut out = Vec::new();
    let _ = v.sock.read_to_end(&mut out);
    let code = v.wait().unwrap_or(-1);
    drop(leak);
    unsafe { libc::close(leak_fd) };
    let leaked = std::fs::read(&leak_path).map(|b| !b.is_empty()).unwrap_or(true);
    let _ = std::fs::remove_file(&leak_path);
    println!("validator-{mode} exit={code} out={:?} leaked={leaked}", String::from_utf8_lossy(&out));
    let good = match mode {
        "fds" => code == 0 && out == b"EBADF" && !leaked,
        _ => code == 0 && out == b"PING",
    };
    if good { ok() } else { no() }
}

/// `exec-sh <snippet>`: run `/bin/sh -c <snippet>`, forward its exit status.
fn probe_exec_sh(a: &[String]) -> ExitCode {
    let Some(snippet) = a.first() else { return ExitCode::from(2) };
    match std::process::Command::new("/bin/sh").arg("-c").arg(snippet).status() {
        Ok(s) if s.success() => ok(),
        _ => no(),
    }
}

/// macOS validator zygote (A219): cage this process like the node's zygote, then fork several
/// single-use validators from it. `echo` must work; open/socket/exec/fork must be denied.
#[cfg(target_os = "macos")]
fn zygote_selftest_macos() -> ExitCode {
    let policy = moochy_sandbox::DonorPolicy::new(std::path::PathBuf::from("/dev/null"), 0);
    if let Err(e) = moochy_sandbox::lockdown_zygote(&policy) {
        println!("zygote-lockdown-fail {e}");
        return ExitCode::from(71);
    }
    let mut all = true;
    for mode in ["echo", "open", "socket", "exec", "fork", "echo"] {
        let ok = validator_selftest_macos(&[mode.to_owned()]) == ok();
        all &= ok;
    }
    if all { ok() } else { no() }
}
