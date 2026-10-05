//! E2E-style tests for `moochy-sandbox` (CONTRACT §15.3, feeding E93–E97).
//!
//! Real processes only: every check runs the `moochy-sandbox-test` binary as a
//! subprocess (the launcher), which builds the sandbox and runs a probe inside
//! it. mo-e2e can lift each `e9x_*` test 1:1 into a Go scenario by running the
//! same binary with the same arguments and matching the same output lines.
//!
//! When the host cannot create the sandbox (unprivileged user namespaces
//! restricted, no Landlock), each test prints `SKIP pending: <reason>` and
//! returns; see API.md "Host requirements" for the AppArmor fix.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::collapsible_if
)]

use std::io::{Read, Write};
use std::net::ToSocketAddrs as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_moochy-sandbox-test");

fn bin_dir() -> PathBuf {
    Path::new(BIN).parent().unwrap().to_path_buf()
}

/// A fresh per-test scratch area: `wt/` (the worktree) and `outside/` (a
/// sibling dir holding a canary that must stay invisible).
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("moochy-sbx-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("wt")).unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/canary"), b"TOP-SECRET").unwrap();
        Self { root }
    }
    fn wt(&self) -> PathBuf {
        self.root.join("wt")
    }
    fn path(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_bin(args: &[&str]) -> Out {
    let o = Command::new(BIN).args(args).current_dir("/").output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// `run <wt> --ro <bin dir> [extra…] -- <BIN> <probe…>`
fn sandboxed(f: &Fixture, extra: &[&str], probe: &[&str]) -> Out {
    let wt = f.wt();
    let bd = bin_dir();
    let mut args = vec!["run", wt.to_str().unwrap(), "--ro", bd.to_str().unwrap()];
    args.extend_from_slice(extra);
    args.push("--");
    args.push(BIN);
    args.extend_from_slice(probe);
    run_bin(&args)
}

/// Returns a skip reason when this host cannot build the sandbox at all.
fn unavailable() -> Option<String> {
    let f = Fixture::new("probe");
    let o = sandboxed(&f, &[], &["stat", "/"]);
    if o.code == 0 {
        return None;
    }
    // Only a genuine host limitation may skip; any other setup failure is a bug.
    let err = o.stderr.trim();
    assert!(
        err.contains("restricted") || err.contains("unsupported"),
        "sandbox setup failed (not a host limitation): {err}"
    );
    Some(format!("sandbox unavailable on this host: {err}"))
}

macro_rules! require_sandbox {
    () => {
        if let Some(why) = unavailable() {
            eprintln!("SKIP pending: {why}");
            return;
        }
    };
}

fn has(o: &Out, needle: &str) -> bool {
    o.stdout.contains(needle)
}

// ───────────────────────────── E93: filesystem ─────────────────────────────

#[test]
fn e93_worktree_rw_secrets_and_outside_invisible() {
    require_sandbox!();
    let f = Fixture::new("e93");
    let out_file = f.path("wt/edited.txt");

    // Edits the worktree, and the edit is visible on the host.
    let o = sandboxed(&f, &[], &["write", &out_file]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert_eq!(std::fs::read(&out_file).unwrap(), b"moochy");

    // Outside the view: sibling dir, real home, ssh/aws dirs.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    for p in [
        f.path("outside/canary"),
        format!("{home}/.ssh/id_ed25519"),
        format!("{home}/.aws/credentials"),
        format!("{home}/.bashrc"),
    ] {
        let o = sandboxed(&f, &[], &["read", &p]);
        assert_ne!(o.code, 0, "readable inside: {p}: {}", o.stdout);
    }
    // System dirs are read-only; nothing outside the worktree changes.
    for p in ["/usr/moochy-probe", "/etc/moochy-probe"] {
        let o = sandboxed(&f, &[], &["write", p]);
        assert_ne!(o.code, 0, "writable inside: {p}");
        assert!(!Path::new(p).exists());
    }
    let o = sandboxed(&f, &[], &["write", &f.path("outside/new")]);
    assert_ne!(o.code, 0);
    assert!(!Path::new(&f.path("outside/new")).exists());
}

#[test]
fn e93_symlinked_paths_and_private_tmp() {
    require_sandbox!();
    let f = Fixture::new("e93link");
    std::fs::create_dir_all(f.root.join("real-rw")).unwrap();
    std::os::unix::fs::symlink(f.root.join("real-rw"), f.root.join("link-rw")).unwrap();
    // A listed rw path that is a symlink: the real dir is mounted, the link works.
    let o = sandboxed(&f, &["--rw", &f.path("link-rw")], &["write", &f.path("link-rw/a")]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert_eq!(std::fs::read(f.root.join("real-rw/a")).unwrap(), b"moochy");

    // /tmp inside is private: the host's /tmp files are invisible and nothing
    // written there reaches the host.
    let host_tmp = std::env::temp_dir().join(format!("moochy-hosttmp-{}", std::process::id()));
    std::fs::write(&host_tmp, b"host").unwrap();
    let o = sandboxed(&f, &[], &["read", host_tmp.to_str().unwrap()]);
    assert_ne!(o.code, 0, "host /tmp visible inside: {}", o.stdout);
    let inner = format!("/tmp/moochy-inner-{}", std::process::id());
    let o = sandboxed(&f, &[], &["write", &inner]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(!Path::new(&inner).exists(), "write to /tmp inside reached the host");
    let _ = std::fs::remove_file(&host_tmp);
    // /dev/shm exists and is writable (private).
    let o = sandboxed(&f, &[], &["write", "/dev/shm/moochy-probe"]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
}

// ───────────────────────────── E94: network ─────────────────────────────

/// Host-side stand-in for the gateway on a Unix socket: replies 200 to anything.
fn fake_gateway(sock: &Path) -> std::thread::JoinHandle<()> {
    let l = std::os::unix::net::UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().take(4) {
            let Ok(mut c) = c else { continue };
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    })
}

#[test]
fn e94_only_gateway_reachable_and_no_host_env() {
    require_sandbox!();
    let f = Fixture::new("e94");
    let sock = f.root.join("gw.sock");
    let _gw = fake_gateway(&sock);
    let port = "18094";
    let gw = ["--gw", sock.to_str().unwrap(), "--gw-port", port];

    let o = sandboxed(&f, &gw, &["http", "127.0.0.1:18094"]);
    assert!(has(&o, "http-ok") && has(&o, "200 OK"), "{}{}", o.stdout, o.stderr);

    // Any other destination fails: another loopback port, a public IP.
    for dst in ["127.0.0.1:18095", "1.1.1.1:443", "10.0.0.1:80"] {
        let o = sandboxed(&f, &gw, &["connect", dst]);
        assert!(has(&o, "connect-fail"), "{dst}: {}", o.stdout);
    }

    // The parent's environment is not inherited (no provider key inside).
    let o = Command::new(BIN)
        .args(["run", f.wt().to_str().unwrap(), "--ro", bin_dir().to_str().unwrap(), "--", BIN, "env", "ANTHROPIC_API_KEY"])
        .env("ANTHROPIC_API_KEY", "sk-must-not-leak")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("env-absent"));
}

// ───────────────────────────── E95: containment ─────────────────────────────

#[test]
fn e95_process_and_memory_limits() {
    require_sandbox!();
    let f = Fixture::new("e95lim");
    let o = sandboxed(&f, &["--nproc", "64"], &["forkbomb"]);
    assert!(has(&o, "hit_limit=true"), "{}{}", o.stdout, o.stderr);
    let o = sandboxed(&f, &["--mem", "536870912"], &["memhog"]);
    assert!(has(&o, "memhog refused"), "{}{}", o.stdout, o.stderr);
}

#[test]
fn e95_terminal_injection_and_ptrace_denied() {
    require_sandbox!();
    let f = Fixture::new("e95sys");
    let o = sandboxed(&f, &[], &["tiocsti"]);
    assert!(has(&o, "tiocsti-fail"), "{}", o.stdout);
    let o = sandboxed(&f, &[], &["ptrace", "1"]);
    assert!(has(&o, "ptrace-fail"), "{}", o.stdout);
}

#[test]
fn e95_wall_deadline() {
    require_sandbox!();
    let f = Fixture::new("e95wall");
    let t = Instant::now();
    let o = sandboxed(&f, &["--wall", "1"], &["sleep", "30"]);
    assert_eq!(o.code, 124);
    assert!(t.elapsed() < Duration::from_secs(10));
}

/// Count live processes whose command line contains `marker`.
fn live_with(marker: &str) -> usize {
    let mut n = 0;
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        if let Ok(cmd) = std::fs::read(e.path().join("cmdline")) {
            if String::from_utf8_lossy(&cmd).replace('\0', " ").contains(marker) {
                n += 1;
            }
        }
    }
    n
}

#[test]
fn e95_descendants_die_with_launcher() {
    require_sandbox!();
    let f = Fixture::new("e95die");
    let marker = format!("sleep 7{}", std::process::id() % 1000);
    let secs = marker.trim_start_matches("sleep ");
    let script = format!("{BIN} sleep {secs} & {BIN} sleep {secs} & wait");
    let mut launcher = Command::new(BIN)
        .args(["run", f.wt().to_str().unwrap(), "--ro", bin_dir().to_str().unwrap(), "--", "/bin/sh", "-c", &script])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let t = Instant::now();
    while live_with(&format!("moochy-sandbox-test {marker}")) < 2 && t.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(live_with(&format!("moochy-sandbox-test {marker}")) >= 2, "descendants never started");
    launcher.kill().unwrap(); // SIGKILL: no cleanup code runs in the launcher
    let _ = launcher.wait();
    let t = Instant::now();
    while live_with(&format!("moochy-sandbox-test {marker}")) > 0 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(live_with(&format!("moochy-sandbox-test {marker}")), 0, "descendants survived the launcher");
}

// ───────────────────────────── E96: donor lockdown ─────────────────────────────

#[test]
fn e96_donor_lockdown_zero_commands_fs_net() {
    let f = Fixture::new("e96");
    let state = f.root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let o = run_bin(&["donor", state.to_str().unwrap(), "8443", &f.path("outside/canary"), "18796"]);
    if has(&o, "lockdown-fail") {
        eprintln!("SKIP pending: {}", o.stdout.trim());
        return;
    }
    assert!(has(&o, "lockdown-ok") && has(&o, "seccomp=true") && has(&o, "fs=true"), "{}", o.stdout);
    // Exec is denied (EPERM) every way: shell, env, a copied binary, execveat
    // through an fd, and a memfd.
    for label in ["sh", "env", "copied-binary", "execveat-fd", "memfd"] {
        assert!(has(&o, &format!("exec-{label}-denied errno=1")), "{label}: {}", o.stdout);
    }
    assert!(!o.stdout.contains("SUCCEEDED"), "{}", o.stdout);
    assert!(has(&o, "canary-read-fail"), "{}", o.stdout);
    assert!(has(&o, "state-write-ok"), "{}", o.stdout);
    // The loopback gateway port may be bound; any other port may not.
    assert!(has(&o, "gw-bind-ok"), "{}", o.stdout);
    // Port rules need the Landlock network ABI (>= 4, Linux 6.7): older kernels
    // keep the filesystem cage and seccomp only (CONTRACT §15.2).
    if has(&o, "net=Some(true)") {
        assert!(has(&o, "connect9-fail"), "{}", o.stdout);
        assert!(has(&o, "bind-other-fail"), "{}", o.stdout);
    } else {
        eprintln!("SKIP pending: no Landlock network ABI on this kernel; port rules not checked");
    }
    // After lockdown the donor still resolves provider hosts and reaches :443.
    if ("api.anthropic.com", 443).to_socket_addrs().is_ok() {
        assert!(has(&o, "dns-ok https-connect-ok"), "{}", o.stdout);
    } else {
        eprintln!("SKIP pending: host has no DNS/Internet; DNS-after-lockdown not checked");
    }
}

#[test]
fn e96_validator_parses_but_cannot_open_files_or_sockets() {
    let o = run_bin(&["validator", "echo"]);
    if has(&o, "validator-spawn-fail") {
        eprintln!("SKIP pending: {}", o.stdout.trim());
        return;
    }
    assert_eq!(o.code, 0, "echo: {}{}", o.stdout, o.stderr);
    // No parent fd survives into the child; the safe stream API works.
    for mode in ["fds", "stream"] {
        let o = run_bin(&["validator", mode]);
        assert_eq!(o.code, 0, "{mode}: {}{}", o.stdout, o.stderr);
    }
    for mode in ["open", "socket"] {
        let o = run_bin(&["validator", mode]);
        // Killed by seccomp (SIGSYS = 31 → 159) before writing anything.
        assert!(has(&o, &format!("validator-{mode} exit=159 out=\"\"")), "{mode}: {}", o.stdout);
    }
}

// ─────────────────── E97: secret masking, git paths, run token ───────────────────

#[test]
fn e97_secret_files_masked_against_read_link_and_symlink() {
    require_sandbox!();
    let f = Fixture::new("e97mask");
    let wt = f.wt();
    std::fs::write(wt.join(".env"), b"API_KEY=real").unwrap();
    std::fs::create_dir_all(wt.join("deploy")).unwrap();
    std::fs::write(wt.join("deploy/server.pem"), b"-----BEGIN-----").unwrap();
    std::fs::write(wt.join("README.md"), b"hello").unwrap();

    for rel in [".env", "deploy/server.pem"] {
        let o = sandboxed(&f, &[], &["read", &f.path(&format!("wt/{rel}"))]);
        assert!(has(&o, "len=0"), "{rel} visible: {}", o.stdout);
    }
    let o = sandboxed(&f, &[], &["read", &f.path("wt/README.md")]);
    assert!(has(&o, "len=5"), "{}", o.stdout);

    // A hard link created inside cannot reach the real inode (cross-mount).
    let o = sandboxed(&f, &[], &["hardlink", &f.path("wt/.env"), &f.path("wt/env-link")]);
    assert!(has(&o, "hardlink-fail") || has(&o, "len=0"), "{}", o.stdout);
    // A symlink created inside resolves through the mask: empty.
    let o = sandboxed(&f, &[], &["symlink", &f.path("wt/.env"), &f.path("wt/env-sym")]);
    assert!(has(&o, "len=0") || has(&o, "symlink-fail"), "{}", o.stdout);
    // The host file is untouched.
    assert_eq!(std::fs::read(wt.join(".env")).unwrap(), b"API_KEY=real");
}

#[test]
fn e97_git_ignored_masked_and_git_exec_paths_read_only() {
    require_sandbox!();
    let f = Fixture::new("e97git");
    let wt = f.wt();
    let git = |args: &[&str]| Command::new("git").arg("-C").arg(&wt).args(args).output().map(|o| o.status.success());
    if git(&["init", "-q", "--template="]).ok() != Some(true) {
        eprintln!("SKIP pending: git not available");
        return;
    }
    std::fs::write(wt.join(".gitignore"), b"local.json\n").unwrap();
    std::fs::write(wt.join("local.json"), b"{\"token\":1}").unwrap();

    let o = sandboxed(&f, &[], &["read", &f.path("wt/local.json")]);
    assert!(has(&o, "len=0"), "git-ignored file visible: {}", o.stdout);
    // Default: the whole .git is read-only — no hook, no config, and no
    // `commondir` (which would redirect the host's git to agent-written config).
    for rel in [".git/hooks/pre-commit", ".git/config", ".git/commondir", ".git/HEAD.new"] {
        let o = sandboxed(&f, &[], &["write", &f.path(&format!("wt/{rel}"))]);
        assert!(has(&o, "write-fail"), "{rel} writable: {}", o.stdout);
    }
    assert!(!wt.join(".git/hooks/pre-commit").exists());
    assert!(!wt.join(".git/commondir").exists());
    // Opt-in git_writable: git can write its own files, hooks/config stay read-only.
    let o = sandboxed(&f, &["--git-writable"], &["write", &f.path("wt/.git/HEAD.new")]);
    assert!(has(&o, "write-ok"), "{}", o.stdout);
    // G20: also every path git reads config, hooks or a redirect from, existing or not.
    for rel in [".git/hooks/pre-commit", ".git/config", ".git/commondir", ".git/config.worktree", ".git/info/attributes", ".git/modules/m/config", ".git/worktrees/w/commondir", ".git/remotes/origin"] {
        let o = sandboxed(&f, &["--git-writable"], &["write", &f.path(&format!("wt/{rel}"))]);
        assert!(has(&o, "write-fail"), "{rel} writable with git_writable: {}", o.stdout);
    }
    assert!(!wt.join(".git/commondir").exists(), "the `.` commondir is removed after the run");
    assert_eq!(git(&["status", "--short"]).ok(), Some(true), "the host's git still works");
    // F21: a config holding a token reads empty inside (the mask beats the .git bind).
    let cfg = wt.join(".git/config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str("[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic eC1hY2Nlc3M=\n");
    std::fs::write(&cfg, text).unwrap();
    let o = sandboxed(&f, &[], &["read", &f.path("wt/.git/config")]);
    assert!(has(&o, "len=0"), "credential config visible: {}", o.stdout);
}

#[test]
fn e97_linked_worktree_read_only_and_isolated() {
    require_sandbox!();
    let f = Fixture::new("e97lw");
    let main = f.root.join("main");
    let git = |dir: &Path, args: &[&str]| {
        Command::new("git").arg("-C").arg(dir).args(["-c", "user.email=t@t", "-c", "user.name=t"]).args(args).output().is_ok_and(|o| o.status.success())
    };
    std::fs::create_dir_all(&main).unwrap();
    if !git(&main, &["init", "-q", "--template="]) {
        eprintln!("SKIP pending: git not available");
        return;
    }
    std::fs::write(main.join("main-only.txt"), b"main").unwrap();
    assert!(git(&main, &["add", "."]) && git(&main, &["commit", "-qm", "init"]));
    // Our worktree is `wt` (the fixture's worktree path), a sibling is `other`.
    std::fs::remove_dir_all(f.wt()).unwrap();
    assert!(git(&main, &["worktree", "add", "-q", f.wt().to_str().unwrap(), "-b", "mine"]));
    assert!(git(&main, &["worktree", "add", "-q", f.root.join("other").to_str().unwrap(), "-b", "theirs"]));

    // git reads work inside.
    let wt = f.path("wt");
    let o = sandboxed(&f, &[], &["exec-sh", &format!("cd {wt} && git status --short && git log --oneline >/dev/null && echo GIT-OK")]);
    assert!(o.stdout.contains("GIT-OK"), "{}{}", o.stdout, o.stderr);
    // Other worktrees' gitdirs and the main worktree's files are not visible.
    let common = main.join(".git").canonicalize().unwrap();
    for p in [common.join("worktrees/other/HEAD"), main.join("main-only.txt"), f.root.join("other/main-only.txt")] {
        let o = sandboxed(&f, &[], &["read", p.to_str().unwrap()]);
        assert_ne!(o.code, 0, "visible inside: {}", p.display());
    }
    // Read-only: no write to the shared repo, no rewrite of the `.git` file.
    for p in [common.join("objects/probe"), common.join("worktrees/wt/HEAD"), f.wt().join(".git")] {
        let o = sandboxed(&f, &[], &["write", p.to_str().unwrap()]);
        assert!(has(&o, "write-fail"), "writable: {}: {}", p.display(), o.stdout);
    }
}

#[test]
fn e97_run_token_only_inside_and_gone_after_run() {
    require_sandbox!();
    let f = Fixture::new("e97tok");
    let o = sandboxed(&f, &["--token", "tok-e97"], &["env", "MOOCHY_RUN_TOKEN"]);
    assert!(has(&o, "env-present MOOCHY_RUN_TOKEN len=7"), "{}", o.stdout);
    // Not leaked to the launcher's environment, and no process holds it after
    // the run (every sandbox process is gone).
    assert!(std::env::var_os("MOOCHY_RUN_TOKEN").is_none());
    assert_eq!(live_with("tok-e97"), 0);
}

#[test]
fn e97_every_git_read_only_placeholder_and_change_notice() {
    require_sandbox!();
    // No .git at all: `git init` inside must not plant a repo for the host's git.
    let f = Fixture::new("e97ph");
    let o = sandboxed(&f, &[], &["exec-sh", &format!("cd {} && git init -q . ; mkdir .git/hooks", f.path("wt"))]);
    assert_ne!(o.code, 0, "{}{}", o.stdout, o.stderr);
    let o = sandboxed(&f, &[], &["write", &f.path("wt/.git/config")]);
    assert!(has(&o, "write-fail"), "{}", o.stdout);
    assert!(!f.wt().join(".git").exists(), "placeholder left behind");
    assert!(!o.stderr.contains("moochy: notice"), "spurious notice: {}", o.stderr);

    // A nested repo (submodule / vendored): read-only too.
    let sub = f.wt().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    if !Command::new("git").arg("-C").arg(&sub).args(["init", "-q", "--template="]).status().is_ok_and(|s| s.success()) {
        eprintln!("SKIP pending: git not available");
        return;
    }
    for rel in ["wt/sub/.git/config", "wt/sub/.git/hooks/pre-commit", "wt/sub/.git/commondir"] {
        let o = sandboxed(&f, &[], &["write", &f.path(rel)]);
        assert!(has(&o, "write-fail"), "{rel} writable: {}", o.stdout);
    }
    // A new .git planted in a subdirectory can't be blocked by mounts: the run
    // says so on its way out.
    let o = sandboxed(&f, &[], &["exec-sh", &format!("mkdir -p {}/deep/.git && echo planted", f.path("wt"))]);
    assert!(has(&o, "planted"), "{}{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("moochy: notice: git metadata changed") && o.stderr.contains("deep/.git"), "{}", o.stderr);
}

#[test]
fn e93_refuses_to_expose_root_or_home() {
    require_sandbox!();
    let f = Fixture::new("e93home");
    let home = std::env::var("HOME").unwrap();
    for wt in ["/", home.as_str()] {
        let o = run_bin(&["run", wt, "--ro", bin_dir().to_str().unwrap(), "--", BIN, "stat", "/"]);
        assert_eq!(o.code, 125, "{wt}: {}{}", o.stdout, o.stderr);
        assert!(o.stderr.contains("would expose"), "{}", o.stderr);
    }
    // The Moochy home is protected by default (here via $MOOCHY_HOME): a
    // worktree containing it is refused.
    let mh = f.root.join("mh");
    std::fs::create_dir_all(&mh).unwrap();
    let o = Command::new(BIN)
        .args(["run", f.root.to_str().unwrap(), "--ro", bin_dir().to_str().unwrap(), "--", BIN, "stat", "/"])
        .env("MOOCHY_HOME", &mh)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(125), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("would expose"));
    let parent = Path::new(&home).parent().unwrap().to_str().unwrap().to_string();
    let o = sandboxed(&f, &["--ro", &parent], &["stat", "/"]);
    assert_eq!(o.code, 125, "{}{}", o.stdout, o.stderr);
}

// ───────────────────────────── E94: --allow-host ─────────────────────────────

#[test]
fn e94_allow_host_proxy_exact_hosts_only() {
    require_sandbox!();
    let f = Fixture::new("e94proxy");
    // Off by default: nothing listens on the proxy port.
    let o = sandboxed(&f, &[], &["connect", "127.0.0.1:3128"]);
    assert!(has(&o, "connect-fail"), "{}", o.stdout);
    // Only exact names are accepted.
    let o = sandboxed(&f, &["--allow-host", "*.example.com"], &["stat", "/"]);
    assert_eq!(o.code, 125, "{}{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("not an exact DNS host name"), "{}", o.stderr);

    let allow = ["--allow-host", "example.com", "--allow-host", "127.0.0.1.nip.io"];
    let o = sandboxed(&f, &allow, &["env", "HTTPS_PROXY"]);
    assert!(has(&o, "env-present HTTPS_PROXY"), "{}", o.stdout);
    for target in ["evil.example.org:443", "example.com:22", "127.0.0.1:443"] {
        let o = sandboxed(&f, &allow, &["proxy", "127.0.0.1:3128", target]);
        assert!(has(&o, "403"), "{target}: {}{}", o.stdout, o.stderr);
    }
    // Through the address HTTPS_PROXY names (what package managers use).
    let o = sandboxed(&f, &allow, &["proxy", "env", "evil.example.org:443"]);
    assert!(has(&o, "403"), "{}{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("refused evil.example.org:443"), "{}", o.stderr);
    // The proxy is the only new route: direct connections still fail.
    let o = sandboxed(&f, &allow, &["connect", "1.1.1.1:443"]);
    assert!(has(&o, "connect-fail"), "{}", o.stdout);
    if ("example.com", 443).to_socket_addrs().is_err() {
        eprintln!("SKIP pending: host has no DNS/Internet; allowed tunnel not checked");
        return;
    }
    let o = sandboxed(&f, &allow, &["proxy", "127.0.0.1:3128", "example.com:443"]);
    assert!(has(&o, "200"), "{}{}", o.stdout, o.stderr);
    // An allowlisted name that resolves to loopback (DNS rebinding) is refused.
    if ("127.0.0.1.nip.io", 443).to_socket_addrs().is_ok_and(|mut a| a.all(|a| a.ip().is_loopback())) {
        let o = sandboxed(&f, &allow, &["proxy", "127.0.0.1:3128", "127.0.0.1.nip.io:443"]);
        assert!(has(&o, "403"), "{}{}", o.stdout, o.stderr);
    }
}

// ───────────────────────────── E95: cgroup v2 ─────────────────────────────

/// Pids whose argv is exactly `BIN sleep <secs>`.
fn sleepers(secs: &str) -> Vec<u32> {
    let want = format!("{BIN}\0sleep\0{secs}\0");
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| std::fs::read(format!("/proc/{pid}/cgroup")).is_ok())
        .filter(|pid| std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| c == want.as_bytes()))
        .collect()
}

#[test]
fn e95_cgroup_limits_when_delegated() {
    require_sandbox!();
    let scope = |args: &[&str]| {
        Command::new("systemd-run").args(["--user", "--scope", "-q", "--"]).args(args).output()
    };
    if !scope(&["true"]).is_ok_and(|o| o.status.success()) {
        eprintln!("SKIP pending: no systemd user manager (delegated cgroup) on this host");
        return;
    }
    // cgroup v1 / hybrid hosts have no unified hierarchy to delegate: rlimits
    // only, by design (CONTRACT §15.1, `moochy doctor` says so).
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        eprintln!("SKIP pending: no cgroup v2 unified hierarchy on this host");
        return;
    }
    let f = Fixture::new("e95cg");
    let secs = format!("6{}", std::process::id() % 1000);
    let wt = f.wt();
    let bd = bin_dir();
    let mut launcher = Command::new("systemd-run")
        .args(["--user", "--scope", "-q", "--", BIN, "run", wt.to_str().unwrap(), "--ro", bd.to_str().unwrap()])
        .args(["--nproc", "77", "--mem-total", "268435456", "--cpu-percent", "150", "--", BIN, "sleep", &secs])
        .spawn()
        .unwrap();
    let t = Instant::now();
    let mut agent = Vec::new();
    while agent.is_empty() && t.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
        agent = sleepers(&secs);
    }
    let pid = *agent.first().expect("agent never started");
    let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    let rel = cg.lines().find_map(|l| l.strip_prefix("0::")).unwrap().trim().to_string();
    let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    assert!(dir.file_name().unwrap().to_string_lossy().starts_with("moochy-run-"), "not in a run cgroup: {rel}");
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).map(|s| s.trim().to_string()).unwrap_or_default();
    assert_eq!(read("pids.max"), "77");
    assert_eq!(read("memory.max"), "268435456");
    if dir.join("cpu.max").exists() {
        assert_eq!(read("cpu.max"), "150000 100000");
    }
    launcher.kill().unwrap();
    let _ = launcher.wait();
    // Launcher SIGKILLed: the sandbox dies (PDEATHSIG) and the next run sweeps
    // the empty cgroup; a normal run removes its own.
    let o = Command::new("systemd-run")
        .args(["--user", "--scope", "-q", "--", BIN, "run", wt.to_str().unwrap(), "--ro", bd.to_str().unwrap()])
        .args(["--mem", "0", "--mem-total", "268435456", "--", BIN, "memhog"])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout);
    // memory.max (swap 0) stops the hog: OOM-killed (137) or refused.
    assert!(o.status.code() == Some(137) || out.contains("memhog refused"), "{:?} {out}", o.status);
    let t = Instant::now();
    while dir.exists() && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!dir.exists(), "stale run cgroup not swept: {}", dir.display());
}
