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
        "sleep" => probe_sleep(rest),
        "forkbomb" => probe_forkbomb(),
        "memhog" => probe_memhog(),
        "ptrace" => probe_ptrace(rest),
        "run" => run_sandbox(rest),
        #[cfg(target_os = "linux")]
        "donor" => donor_selftest(rest),
        #[cfg(target_os = "linux")]
        "validator" => validator_selftest(rest),
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

    let canary = a.get(2).cloned().unwrap_or_default();
    // A copied binary inside the (writable) state dir: exec must still fail.
    let copy = format!("{state}/true-copy");
    let _ = std::fs::copy("/bin/true", &copy);
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
    let copy_c = std::ffi::CString::new(copy.clone()).unwrap_or_default();
    report_exec_denied("copied-binary", exec_path(&copy_c));
    report_exec_denied("execveat-fd", exec_via_fd(&copy_c));
    report_exec_denied("memfd", exec_via_memfd());

    // Reading an existing secret outside the state dir must fail.
    match std::fs::read(&canary) {
        Ok(_) => println!("canary-read-ok (BAD) {canary}"),
        Err(e) => println!("canary-read-fail {e}"),
    }
    // Writing inside the state dir still works (outbox).
    match std::fs::write(format!("{state}/outbox.probe"), b"x") {
        Ok(()) => println!("state-write-ok"),
        Err(e) => println!("state-write-fail (BAD) {e}"),
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
            "--nproc" => spec.limits.processes = val.parse().unwrap_or(64),
            "--mem" => spec.limits.memory_bytes = val.parse().unwrap_or(1 << 30),
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
