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

use std::io::{Read, Write};
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
        "exec" => probe_exec(rest),
        "hardlink" => probe_hardlink(rest),
        "symlink" => probe_symlink(rest),
        "tiocsti" => probe_tiocsti(),
        "env" => probe_env(rest),
        #[cfg(target_os = "linux")]
        "donor" => donor_selftest(rest),
        #[cfg(target_os = "linux")]
        "validator" => validator_selftest(),
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
    match std::fs::File::open(p).and_then(|mut f| {
        let mut buf = [0u8; 1];
        f.read(&mut buf)
    }) {
        Ok(_) => {
            println!("read-ok {p}");
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
    const TIOCSTI: libc::c_ulong = 0x5412;
    let ch: libc::c_char = b'x' as libc::c_char;
    // SAFETY: attempt the injection ioctl on stdin; seccomp should block it.
    let r = unsafe { libc::ioctl(0, TIOCSTI, std::ptr::addr_of!(ch)) };
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

// ───────────────────────── self-tests (Linux) ─────────────────────────

#[cfg(target_os = "linux")]
fn donor_selftest(a: &[String]) -> ExitCode {
    use std::path::PathBuf;
    let state = a.first().cloned().unwrap_or_else(|| "/tmp".into());
    let relay_port: u16 = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(8443);

    let mut policy = moochy_sandbox::DonorPolicy::new(PathBuf::from(&state), relay_port);
    policy.ro_paths = vec![PathBuf::from("/etc/ssl/certs")];
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
    report_exec_denied("execveat-fd", exec_via_fd());
    report_exec_denied("memfd", exec_via_memfd());

    // Reading a secret outside the state dir must fail.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let ssh = format!("{home}/.ssh/id_ed25519");
    match std::fs::File::open(&ssh) {
        Ok(_) => println!("ssh-read-ok (BAD) {ssh}"),
        Err(e) => println!("ssh-read-fail {e}"),
    }

    // Connecting to a non-allowed port must fail.
    use std::net::TcpStream;
    use std::time::Duration;
    if let Ok(sa) = "127.0.0.1:9".parse() {
        match TcpStream::connect_timeout(&sa, Duration::from_millis(300)) {
            Ok(_) => println!("connect9-ok (BAD)"),
            Err(e) => println!("connect9-fail {e}"),
        }
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
fn exec_via_fd() -> i32 {
    // SAFETY: open a known binary and attempt execveat on the fd.
    unsafe {
        let fd = libc::open(c"/bin/true".as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            // can't even open it (Landlock); treat as denied path to exec.
            return libc::EPERM;
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

#[cfg(target_os = "linux")]
fn validator_selftest() -> ExitCode {
    // The child tries to open a file and a socket; both must fail (seccomp kills
    // it on the socket syscall). It writes one status byte before dying, if it
    // can; the parent reports what it saw.
    let v = moochy_sandbox::spawn_validator(|fd: RawFd| -> i32 {
        // No filesystem: open must fail.
        let opened = std::fs::File::open("/etc/hostname").is_ok();
        // Report the FS result over the socket before attempting a socket (which
        // the seccomp allowlist kills).
        let msg: &[u8] = if opened { b"FOPEN\n" } else { b"NOOPEN\n" };
        write_fd(fd, msg);
        // This syscall is not in the allowlist → process is killed here.
        let _ = std::net::TcpStream::connect("127.0.0.1:9");
        write_fd(fd, b"SOCKET\n"); // should never be reached
        0
    });
    let mut v = match v {
        Ok(v) => v,
        Err(e) => {
            println!("validator-spawn-fail {e}");
            return ExitCode::from(71);
        }
    };
    let mut buf = Vec::new();
    let _ = v.sock.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    print!("validator-output: {text}");
    let code = v.wait().unwrap_or(-1);
    println!("validator-exit {code}");
    // Expect: NOOPEN present, SOCKET absent, killed by signal (code >= 128).
    if text.contains("NOOPEN") && !text.contains("SOCKET") {
        ok()
    } else {
        no()
    }
}

#[cfg(target_os = "linux")]
fn write_fd(fd: RawFd, msg: &[u8]) {
    // SAFETY: fd is the inherited socketpair end, valid for the call.
    unsafe {
        libc::write(fd, msg.as_ptr().cast(), msg.len());
    }
}
