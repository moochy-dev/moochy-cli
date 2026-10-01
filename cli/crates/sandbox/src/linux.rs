//! Maintainer side (CONTRACT §15.1): run a command and everything it spawns
//! inside an unprivileged user/mount/PID/net/IPC/UTS-namespace jail with a
//! `pivot_root` minimal view, Landlock FS second layer, seccomp, dropped caps,
//! rlimits and `no_new_privs`. Fails closed.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, path_beneath_rules,
};
use rustix::fs::{Mode, OFlags};
use rustix::mount::{
    MountFlags, MountPropagationFlags, mount, mount_bind_recursive, mount_change, mount_remount,
};
use rustix::thread::UnshareFlags;

use crate::{Error, Spec, mask, seccomp, sys};

const ABI_CEIL: ABI = ABI::V5;

fn setup(what: &'static str, err: std::io::Error) -> Error {
    Error::Setup { what, err }
}
fn io(what: &'static str) -> impl Fn(rustix::io::Errno) -> Error {
    move |e| Error::Setup {
        what,
        err: e.into(),
    }
}

/// CONTRACT §15.1 entry point.
pub fn run(spec: &Spec, program: &OsStr, args: &[OsString]) -> Result<i32, Error> {
    if spec.unsafe_no_sandbox {
        eprintln!(
            "moochy: WARNING --unsafe-no-sandbox: running WITHOUT a sandbox. \
             Pooled compute output is hostile (CONTRACT §15.4). Debugging only."
        );
        return run_unsandboxed(spec, program, args);
    }
    preflight()?;

    // Everything that needs the host (walk the fs, run git, randomness) happens
    // here in the parent. The child only consumes these.
    let base = ScratchDir::new()?;
    let worktree = spec
        .worktree
        .canonicalize()
        .map_err(|e| setup("canonicalize worktree", e))?;
    let masks = mask::collect(&worktree)?;
    let git = crate::git::view(&worktree, spec.git_writable);
    let (uid, gid) = (rustix::process::getuid(), rustix::process::getgid());
    let mut proxy = if spec.allow_hosts.is_empty() {
        None
    } else {
        let allow = crate::proxy::Allowlist::new(&spec.allow_hosts)?;
        Some(crate::proxy::Proxy::bind(base.path().join("proxy.sock"), allow)?)
    };
    let cgroup = {
        let mut id = [0u8; 8];
        getrandom(&mut id)?;
        crate::cgroup::Cgroup::create(&spec.limits, &crate::hex(&id))
    };

    let plan = Plan {
        base: base.path().to_path_buf(),
        worktree,
        ro_paths: spec.ro_paths.iter().filter_map(|p| Bind::resolve(p)).collect(),
        rw_paths: spec.rw_paths.iter().filter_map(|p| Bind::resolve(p)).collect(),
        gateway_socket: match &spec.gateway_socket {
            Some(s) => Some(s.canonicalize().map_err(|e| setup("canonicalize gateway socket", e))?),
            None => None,
        },
        gateway_port: spec.gateway_loopback_port,
        proxy_socket: proxy.as_ref().map(|p| p.sock().to_path_buf()),
        cgroup_procs: cgroup.as_ref().map(crate::cgroup::Cgroup::procs),
        cwd: spec.cwd.clone(),
        git,
        masks,
        uid_raw: uid.as_raw(),
        gid_raw: gid.as_raw(),
        limits: spec.limits,
        launcher_pid: std::process::id(),
    };

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    for (k, v) in build_env(spec) {
        cmd.env(k, v);
    }
    // No current_dir: the target path only exists after pivot_root, so the agent
    // branch chdirs itself below.

    let agent_filter = seccomp::agent_filter()?;
    // The closure runs in the forked child. Up to the inner fork it only performs
    // namespace/mount syscalls; the agent branch applies pre-built seccomp/
    // Landlock then returns to let std `execve`. The parent branch waits and
    // `_exit`s without returning. See module + sys.rs docs.
    sys::set_pre_exec(&mut cmd, move || child_main(&plan, &agent_filter));

    let mut child = cmd.spawn().map_err(Error::Exec)?;
    if let Some(p) = proxy.as_mut() {
        p.start();
    }
    let status = child.wait().map_err(Error::Exec)?;
    drop(proxy);
    drop(cgroup);
    drop(base);
    Ok(exit_code(status))
}

fn exit_code(s: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    if let Some(c) = s.code() {
        c
    } else if let Some(sig) = s.signal() {
        128i32.saturating_add(sig)
    } else {
        -1
    }
}

/// Fields the child closure needs; all owned so nothing borrows across the fork.
struct Plan {
    base: PathBuf,
    worktree: PathBuf,
    ro_paths: Vec<Bind>,
    rw_paths: Vec<Bind>,
    gateway_socket: Option<PathBuf>,
    gateway_port: Option<u16>,
    /// Host socket of the `--allow-host` proxy (in the scratch dir).
    proxy_socket: Option<PathBuf>,
    /// `cgroup.procs` of the run's cgroup, when a delegated one exists.
    cgroup_procs: Option<PathBuf>,
    cwd: Option<PathBuf>,
    git: crate::git::GitView,
    masks: Vec<PathBuf>,
    uid_raw: u32,
    gid_raw: u32,
    limits: crate::Limits,
    /// Launcher pid, to close the PDEATHSIG race (parent died before prctl).
    launcher_pid: u32,
}

/// The pre_exec closure. Returns `Ok(())` only in the agent branch (std then
/// execs). Any error aborts the spawn (fail closed).
fn child_main(plan: &Plan, filter: &[seccompiler::BpfProgram]) -> std::io::Result<()> {
    // Into the run's cgroup first, so every descendant is counted (graceful:
    // rlimits remain if the move fails).
    if let Some(procs) = &plan.cgroup_procs {
        let _ = std::fs::write(procs, b"0");
    }
    enter_namespaces(plan).map_err(to_io)?;
    // Inside the new (empty) netns: `lo` up and the bridge listeners bound before
    // the agent exists, so the agent can never squat a port.
    let listeners = bridge_listeners(plan).map_err(to_io)?;

    // Fork: the child becomes PID 1 in the new PID namespace (it is the agent);
    // the current process stays outside and reaps it. Both branches reach execve
    // or _exit with only syscalls; the agent branch's allocations (Landlock)
    // happen before seccomp, in a child that is single-threaded here.
    match sys::fork()? {
        sys::Fork::Parent(agent_pid) => {
            // Reaper: serve the gateway bridge, wait for the agent, propagate its
            // code. Never returns.
            let timed_out = supervise(&listeners, agent_pid, plan.limits.wall_seconds);
            if timed_out {
                let _ = rustix::process::kill_process(
                    rustix::process::Pid::from_raw(agent_pid).unwrap_or(rustix::process::Pid::INIT),
                    rustix::process::Signal::KILL,
                );
            }
            let code = crate::donor::wait_raw(agent_pid).unwrap_or(-1);
            let code = if timed_out { WALL_TIMEOUT_EXIT } else { code };
            sys::exit_immediately(code);
        }
        sys::Fork::Child => {
            drop(listeners);
            build_view(plan).map_err(to_io)?;
            harden_agent(plan, filter).map_err(to_io)?;
            Ok(()) // → std performs execve(program, argv, envp)
        }
    }
}

// ───────────────────────── gateway bridge ─────────────────────────
//
// Agents speak HTTP to `127.0.0.1:<port>`. The reaper lives in the sandbox netns
// (but outside its PID namespace and seccomp/Landlock cage) and splices every
// loopback connection to the gateway Unix socket bind-mounted at
// GATEWAY_SOCK_PATH (and, with `--allow-host`, the proxy port to PROXY_SOCK_PATH).
// pivot_root moved the reaper's root along with the agent's, so those paths
// resolve in the sandbox view. No other route exists.

/// Max concurrent bridged connections.
const BRIDGE_MAX_CONNS: usize = 64;
/// Per-direction buffer; a chunk is forwarded as soon as it is read.
const BRIDGE_BUF: usize = 64 * 1024;

/// A loopback listener inside the sandbox netns and the socket it splices to.
type Listener = (std::net::TcpListener, &'static str);

fn bridge_listeners(plan: &Plan) -> Result<Vec<Listener>, Error> {
    let mut v = Vec::new();
    if let Some(port) = plan.gateway_port {
        v.push((port, crate::GATEWAY_SOCK_PATH));
    }
    if plan.proxy_socket.is_some() {
        v.push((crate::PROXY_LOOPBACK_PORT, crate::PROXY_SOCK_PATH));
    }
    if !v.is_empty() {
        sys::loopback_up().map_err(|e| setup("loopback up", e))?;
    }
    v.into_iter()
        .map(|(port, target)| {
            let l = std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|e| setup("bind bridge port", e))?;
            l.set_nonblocking(true).map_err(|e| setup("bridge nonblocking", e))?;
            Ok((l, target))
        })
        .collect()
}

/// One direction of a bridged connection: bytes read from `from` not yet
/// written to `to`.
struct Half {
    buf: Box<[u8]>,
    len: usize,
    off: usize,
    eof: bool,
}

struct Conn {
    tcp: std::net::TcpStream,
    unix: std::os::unix::net::UnixStream,
    up: Half,   // tcp → unix
    down: Half, // unix → tcp
}

/// Single-threaded bridge (threads are impossible here: after
/// `unshare(CLONE_NEWPID)` the kernel refuses CLONE_THREAD). Polls the listener,
/// every connection and a pidfd for the agent; returns when the agent exits.
/// Exit code when the wall-clock deadline kills the run (as `timeout(1)`).
pub const WALL_TIMEOUT_EXIT: i32 = 124;

/// The reaper's loop: serve the gateway bridge (if any) and watch the agent
/// through a pidfd until it exits or the wall-clock deadline passes. Returns
/// true on deadline. Threads are impossible here (after `unshare(CLONE_NEWPID)`
/// the kernel refuses CLONE_THREAD), hence one poll loop.
fn supervise(listeners: &[Listener], agent_pid: i32, wall_seconds: u64) -> bool {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use std::os::fd::AsFd as _;
    use std::time::{Duration, Instant};
    let Some(pid) = rustix::process::Pid::from_raw(agent_pid) else { return false };
    let Ok(pidfd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) else {
        return false; // fall back to a plain waitpid in the caller
    };
    let deadline = (wall_seconds > 0).then(|| Instant::now().checked_add(Duration::from_secs(wall_seconds))).flatten();
    let mut conns: Vec<Conn> = Vec::new();
    loop {
        let timeout = deadline.map(|d| {
            let left = d.saturating_duration_since(Instant::now());
            Timespec { tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX), tv_nsec: i64::from(left.subsec_nanos()) }
        });
        let mut fds: Vec<PollFd<'_>> =
            Vec::with_capacity(conns.len().saturating_mul(2).saturating_add(listeners.len()).saturating_add(1));
        fds.push(PollFd::new(&pidfd, PollFlags::IN));
        for (l, _) in listeners {
            fds.push(PollFd::new(l, PollFlags::IN));
        }
        for c in &conns {
            fds.push(PollFd::from_borrowed_fd(c.tcp.as_fd(), interest(&c.up, &c.down)));
            fds.push(PollFd::from_borrowed_fd(c.unix.as_fd(), interest(&c.down, &c.up)));
        }
        if poll(&mut fds, timeout.as_ref()).is_err() {
            continue; // EINTR
        }
        let agent_done = fds.first().is_some_and(|f| !f.revents().is_empty());
        // Listener i sits at fds[i + 1] (≤ 2 listeners: gateway, proxy).
        let ready = [1usize, 2].map(|i| i <= listeners.len() && fds.get(i).is_some_and(|f| !f.revents().is_empty()));
        drop(fds);
        if agent_done {
            return false;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return true;
        }
        for ((l, target), _) in listeners.iter().zip(ready).filter(|(_, r)| *r) {
            accept_all(l, target, &mut conns);
        }
        conns.retain_mut(pump);
    }
}

fn interest(read_half: &Half, write_half: &Half) -> rustix::event::PollFlags {
    use rustix::event::PollFlags;
    let mut f = PollFlags::empty();
    if !read_half.eof && read_half.len == 0 {
        f |= PollFlags::IN;
    }
    if write_half.len > write_half.off {
        f |= PollFlags::OUT;
    }
    f
}

fn accept_all(l: &std::net::TcpListener, target: &str, conns: &mut Vec<Conn>) {
    while let Ok((tcp, _)) = l.accept() {
        if conns.len() >= BRIDGE_MAX_CONNS {
            continue; // bounded: refuse (drop) rather than queue
        }
        let Ok(unix) = std::os::unix::net::UnixStream::connect(target) else {
            continue;
        };
        if tcp.set_nonblocking(true).is_err() || unix.set_nonblocking(true).is_err() {
            continue;
        }
        let _ = tcp.set_nodelay(true);
        let half = || Half { buf: vec![0u8; BRIDGE_BUF].into_boxed_slice(), len: 0, off: 0, eof: false };
        conns.push(Conn { tcp, unix, up: half(), down: half() });
    }
}

/// Move bytes both ways without blocking; false = connection finished.
fn pump(c: &mut Conn) -> bool {
    let a = step(&mut c.up, &mut c.tcp, &mut c.unix);
    let b = step(&mut c.down, &mut c.unix, &mut c.tcp);
    match (a, b) {
        (Ok(()), Ok(())) => !(c.up.eof && c.down.eof && c.up.len == 0 && c.down.len == 0),
        _ => false,
    }
}

fn step(h: &mut Half, from: &mut impl std::io::Read, to: &mut impl Shut) -> std::io::Result<()> {
    use std::io::ErrorKind::{Interrupted, WouldBlock};
    if h.len == 0 && !h.eof {
        match from.read(&mut h.buf) {
            Ok(0) => {
                h.eof = true;
                let _ = to.shut();
            }
            Ok(n) => {
                h.len = n;
                h.off = 0;
            }
            Err(e) if matches!(e.kind(), WouldBlock | Interrupted) => {}
            Err(e) => return Err(e),
        }
    }
    while h.off < h.len {
        let pending = h.buf.get(h.off..h.len).unwrap_or(&[]);
        match to.write(pending) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => h.off = h.off.saturating_add(n),
            Err(e) if matches!(e.kind(), WouldBlock | Interrupted) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    h.len = 0;
    h.off = 0;
    Ok(())
}

/// Write side that can be half-closed once its source hits EOF.
trait Shut: std::io::Write {
    fn shut(&mut self) -> std::io::Result<()>;
}
impl Shut for std::net::TcpStream {
    fn shut(&mut self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}
impl Shut for std::os::unix::net::UnixStream {
    fn shut(&mut self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

/// std only forwards an errno from `pre_exec`, so print the precise reason here
/// (the child is single-threaded at this point) and keep the OS errno if any.
fn to_io(e: Error) -> std::io::Error {
    let msg = format!("moochy-sandbox: {e}\n");
    let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
    match e {
        Error::Setup { err, .. } if err.raw_os_error().is_some() => err,
        _ => std::io::Error::from_raw_os_error(libc::EPERM),
    }
}

/// Child, pre-fork: new namespaces, uid/gid maps, the pivoted minimal view.
/// Reaper, pre-fork: new namespaces, uid/gid maps, hostname.
fn enter_namespaces(plan: &Plan) -> Result<(), Error> {
    // Die with the launcher (`moochy run`); its death then cascades: reaper →
    // PID 1 (its own PDEATHSIG) → the whole PID namespace.
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(io("reaper pdeathsig"))?;
    let ppid = rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get().unsigned_abs());
    if ppid != plan.launcher_pid {
        return Err(Error::Unsupported("launcher exited during sandbox setup"));
    }
    sys::unshare(
        UnshareFlags::NEWUSER
            | UnshareFlags::NEWNS
            | UnshareFlags::NEWPID
            | UnshareFlags::NEWNET
            | UnshareFlags::NEWIPC
            | UnshareFlags::NEWUTS
            | UnshareFlags::NEWCGROUP,
    )
    .map_err(io("unshare"))?;

    write_id_maps(plan.uid_raw, plan.gid_raw)?;
    let _ = rustix::system::sethostname(b"moochy");
    Ok(())
}

/// Agent (PID 1 of the new pid ns), pre-exec: build the pivoted minimal view.
/// Runs here, not in the reaper, so the fresh `/proc` belongs to the new pid
/// namespace and is mounted while the host procfs is still visible (the kernel
/// refuses a procfs mount in a userns otherwise).
fn build_view(plan: &Plan) -> Result<(), Error> {

    // All mounts private so nothing propagates back to the host.
    mount_change("/", MountPropagationFlags::PRIVATE | MountPropagationFlags::REC)
        .map_err(io("make-rprivate"))?;

    let root = plan.base.join("root");
    mkdir(&root)?;
    // tmpfs as the new root skeleton.
    tmpfs(&root, c"mode=0755")?;

    // Private tmpfs home + tmp FIRST, so a worktree that lives under /tmp (or
    // any bind below) is mounted on top of them, not hidden underneath.
    for (dir, opts) in [("tmp", c"mode=1777"), ("home/sandbox", c"mode=0700"), ("run/moochy", c"mode=0755")] {
        let t = root.join(dir);
        mkdir_p(&t)?;
        tmpfs(&t, opts)?;
    }

    // Read-only system paths, read-write extras, the worktree. Mounts always
    // use the canonical target (a symlinked path would otherwise mount nothing
    // or the wrong thing); a real already inside a bound ancestor of the same
    // mode is not bound twice. Links are recreated after every mount.
    let mut bound: Vec<(&Path, bool)> = Vec::new();
    for (b, rw) in plan.ro_paths.iter().map(|b| (b, false)).chain(plan.rw_paths.iter().map(|b| (b, true))) {
        if !bound.iter().any(|(r, w)| *w == rw && b.real.starts_with(r)) {
            bind_into(&root, &b.real, rw)?;
            bound.push((&b.real, rw));
        }
    }
    bind_into(&root, &plan.worktree, true)?;
    for b in plan.ro_paths.iter().chain(plan.rw_paths.iter()) {
        if let Some(link) = &b.link {
            link_into(&root, link, &b.real)?;
        }
    }

    // Mask secret-shaped / git-ignored files inside the worktree (§15.4).
    apply_masks(&root, plan)?;
    // Git paths whose content the HOST later executes (hooks; `core.fsmonitor`,
    // `core.hooksPath`, aliases in config): read-only inside, so code written by
    // the agent can never run outside the sandbox on the user's next `git`.
    for p in &plan.git.read_only {
        bind_into(&root, p, false)?;
    }
    if let Some(l) = &plan.git.linked {
        bind_linked_gitdir(&root, l)?;
    }


    // Minimal /dev, with a private /dev/shm (POSIX shm, Python multiprocessing).
    setup_dev(&root)?;
    let shm = root.join("dev/shm");
    mkdir_p(&shm)?;
    tmpfs(&shm, c"mode=1777")?;

    // Gateway Unix socket bridged in read-write (the one allowed channel).
    if let Some(sock) = &plan.gateway_socket {
        let dst = root.join("run/moochy/gateway.sock");
        touch(&dst)?;
        mount_bind_recursive(sock, &dst).map_err(io("bind gateway socket"))?;
    }
    if let Some(sock) = &plan.proxy_socket {
        let dst = root.join(crate::PROXY_SOCK_PATH.trim_start_matches('/'));
        touch(&dst)?;
        mount_bind_recursive(sock, &dst).map_err(io("bind proxy socket"))?;
    }

    // /proc of the NEW pid namespace, mounted before the host procfs goes away.
    let proc_dir = root.join("proc");
    mkdir_p(&proc_dir)?;
    mount("proc", &proc_dir, "proc", MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC, None)
        .map_err(io("mount /proc"))?;

    pivot_into(&root)
}

/// Write single-entry uid/gid maps for the new user namespace (identity-map the
/// caller's uid/gid to 0 inside). `setgroups` must be denied before gid_map.
fn write_id_maps(uid: u32, gid: u32) -> Result<(), Error> {
    std::fs::write("/proc/self/setgroups", b"deny").map_err(|e| setup("setgroups deny", e))?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1").as_bytes())
        .map_err(|e| setup("uid_map", e))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1").as_bytes())
        .map_err(|e| setup("gid_map", e))?;
    Ok(())
}

/// Linked worktree: the shared commondir read-only, other worktrees' gitdirs
/// hidden under an empty read-only tmpfs, this worktree's gitdir read-only.
fn bind_linked_gitdir(root: &Path, l: &crate::git::Linked) -> Result<(), Error> {
    if let Some(common) = &l.commondir {
        bind_into(root, common, false)?;
    }
    match &l.worktrees_dir {
        Some(wts) if l.gitdir.parent() == Some(wts.as_path()) => {
            let t = root.join(wts.strip_prefix("/").unwrap_or(wts));
            tmpfs(&t, c"mode=0755")?;
            bind_into(root, &l.gitdir, false)?;
            mount_remount(&t, MountFlags::RDONLY, "").map_err(io("remount worktrees ro"))?;
        }
        Some(wts) => {
            let t = root.join(wts.strip_prefix("/").unwrap_or(wts));
            tmpfs(&t, c"mode=0755")?;
            mount_remount(&t, MountFlags::RDONLY, "").map_err(io("remount worktrees ro"))?;
            bind_into(root, &l.gitdir, false)?;
        }
        None => bind_into(root, &l.gitdir, false)?,
    }
    Ok(())
}

/// A path the caller listed, resolved on the host: `real` is canonical (what we
/// mount and what Landlock rules name); `link` is the listed path when it went
/// through a symlink (`/bin -> usr/bin`, `~/tools -> /opt/x`), recreated inside.
#[derive(Debug)]
struct Bind {
    link: Option<PathBuf>,
    real: PathBuf,
}

impl Bind {
    /// None when the path does not exist (optional defaults like `/lib64`).
    fn resolve(p: &Path) -> Option<Self> {
        let real = p.canonicalize().ok()?;
        let link = (real != p).then(|| p.to_path_buf());
        Some(Self { link, real })
    }
}

/// Recreate `link -> real` inside the new root unless that path already exists
/// there (e.g. it is itself a mounted real, or below one).
fn link_into(root: &Path, link: &Path, real: &Path) -> Result<(), Error> {
    let dst = root.join(link.strip_prefix("/").unwrap_or(link));
    if std::fs::symlink_metadata(&dst).is_ok() {
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        mkdir_p(parent)?;
    }
    match std::os::unix::fs::symlink(real, &dst) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(setup("symlink", e)),
    }
}

/// Bind the canonical host path `src` into `root` at the same absolute path.
fn bind_into(root: &Path, src: &Path, writable: bool) -> Result<(), Error> {
    let rel = src.strip_prefix("/").unwrap_or(src);
    let dst = root.join(rel);
    let meta = std::fs::metadata(src).map_err(|e| setup("stat bind src", e))?;
    if meta.is_dir() {
        mkdir_p(&dst)?;
    } else {
        if let Some(parent) = dst.parent() {
            mkdir_p(parent)?;
        }
        touch(&dst)?;
    }
    mount_bind_recursive(src, &dst).map_err(io("bind"))?;
    if !writable {
        // Mount-level read-only too (defense in depth atop Landlock).
        mount_remount(&dst, MountFlags::RDONLY | MountFlags::BIND, "").map_err(io("remount ro"))?;
    }
    Ok(())
}

/// Overmount each masked path with an empty read-only file/dir so neither the
/// content nor a hardlink/rename/symlink made inside can reach it: path
/// resolution always traverses the top (empty) mount (§15.4).
fn apply_masks(root: &Path, plan: &Plan) -> Result<(), Error> {
    if plan.masks.is_empty() {
        return Ok(());
    }
    let empty_dir = plan.base.join("empty");
    let empty_file = plan.base.join("empty_file");
    for (target_is_dir, p) in plan
        .masks
        .iter()
        .map(|p| (p.is_dir(), p))
        .collect::<Vec<_>>()
    {
        let rel = p.strip_prefix("/").unwrap_or(p);
        let dst = root.join(rel);
        if !dst.exists() {
            continue; // not in the view
        }
        let src: &Path = if target_is_dir { &empty_dir } else { &empty_file };
        mount_bind_recursive(src, &dst).map_err(io("bind mask"))?;
        mount_remount(&dst, MountFlags::RDONLY | MountFlags::BIND, "").map_err(io("remount mask ro"))?;
    }
    Ok(())
}

/// Private tmpfs with an explicit mode (the default would be a sticky 1777).
fn tmpfs(target: &Path, opts: &std::ffi::CStr) -> Result<(), Error> {
    mount("tmpfs", target, "tmpfs", MountFlags::NOSUID | MountFlags::NODEV, opts).map_err(io("mount tmpfs"))
}

fn setup_dev(root: &Path) -> Result<(), Error> {
    let dev = root.join("dev");
    mkdir_p(&dev)?;
    tmpfs(&dev, c"mode=0755")?;
    for node in ["null", "zero", "full", "random", "urandom"] {
        let src = PathBuf::from("/dev").join(node);
        let dst = dev.join(node);
        touch(&dst)?;
        mount_bind_recursive(&src, &dst).map_err(io("bind /dev node"))?;
    }
    Ok(())
}

/// `pivot_root` into `root`, detach the old root, chdir to `/`.
fn pivot_into(root: &Path) -> Result<(), Error> {
    let oldroot = root.join(".oldroot");
    mkdir(&oldroot)?;
    rustix::process::pivot_root(root, &oldroot).map_err(io("pivot_root"))?;
    rustix::process::chdir("/").map_err(io("chdir /"))?;
    rustix::mount::unmount("/.oldroot", rustix::mount::UnmountFlags::DETACH)
        .map_err(io("detach oldroot"))?;
    let _ = std::fs::remove_dir("/.oldroot");
    Ok(())
}

/// Agent branch (PID 1 in the new ns): /proc, rlimits, pdeathsig, new session,
/// drop capabilities, Landlock FS layer, no_new_privs, seccomp. Then returns.
fn harden_agent(plan: &Plan, filter: &[seccompiler::BpfProgram]) -> Result<(), Error> {
    chdir_into_worktree(plan)?;
    apply_rlimits(&plan.limits)?;

    // Die with our reaper parent; detach from any controlling terminal (blocks
    // TIOCSTI injection into the launching shell).
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(io("pdeathsig"))?;
    let _ = rustix::process::setsid();

    // Nothing the launcher held may leak into the agent across execve.
    sys::cloexec_from_3().map_err(|e| setup("cloexec fds", e))?;
    drop_all_caps();
    landlock_agent(plan)?;
    rustix::thread::set_no_new_privs(true).map_err(io("no_new_privs"))?;
    for prog in filter {
        seccompiler::apply_filter(prog)
            .map_err(|e| setup("seccomp apply", std::io::Error::other(e.to_string())))?;
    }
    Ok(())
}

fn chdir_into_worktree(plan: &Plan) -> Result<(), Error> {
    rustix::process::chdir(plan.cwd.as_ref().unwrap_or(&plan.worktree)).map_err(io("chdir"))?;
    Ok(())
}

fn apply_rlimits(l: &crate::Limits) -> Result<(), Error> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let set = |res, v: u64| {
        if v > 0 {
            let _ = setrlimit(res, Rlimit { current: Some(v), maximum: Some(v) });
        }
    };
    set(Resource::As, l.memory_bytes);
    set(Resource::Cpu, l.cpu_seconds);
    setrlimit(Resource::Nofile, Rlimit { current: Some(l.open_files), maximum: Some(l.open_files) })
        .map_err(io("rlimit nofile"))?;
    setrlimit(Resource::Nproc, Rlimit { current: Some(l.processes), maximum: Some(l.processes) })
        .map_err(io("rlimit nproc"))?;
    set(Resource::Core, l.core_bytes);
    Ok(())
}

/// Drop every capability from the bounding set so no exec can regain privilege.
fn drop_all_caps() {
    // Best-effort: iterate the known capability range and drop each.
    for cap in 0..64u32 {
        let _ = drop_bounding_cap(cap);
    }
}

fn drop_bounding_cap(cap: u32) -> std::io::Result<()> {
    // PR_CAPBSET_DROP = 24. rustix exposes this via remove_capability_from_bounding_set
    // but keyed by its Capability enum; iterating raw is simpler and total.
    let r = unsafe_prctl_capbset_drop(cap);
    if r { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

// Thin shim so the raw prctl stays out of the hot modules; defined in sys.
fn unsafe_prctl_capbset_drop(cap: u32) -> bool {
    sys::capbset_drop(cap)
}

fn landlock_agent(plan: &Plan) -> Result<(), Error> {
    let abi = ABI_CEIL;
    // Network (ABI >= 4): TCP connect only to the gateway bridge port; the empty
    // netns is the first layer. Scope (ABI >= 6): no abstract-socket or signal
    // reach outside the sandbox domain. Both best-effort on older kernels.
    let created = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(ll("fs handle"))?
        .handle_access(AccessNet::ConnectTcp)
        .map_err(ll("net handle"))?
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(ll("scope"))?
        .create()
        .map_err(ll("create"))?;
    let proxy_port = plan.proxy_socket.as_ref().map(|_| crate::PROXY_LOOPBACK_PORT);
    let created = created
        .add_rules(
            plan.gateway_port
                .into_iter()
                .chain(proxy_port)
                .map(|p| Ok::<_, landlock::RulesetError>(NetPort::new(p, AccessNet::ConnectTcp))),
        )
        .map_err(ll("net rule"))?;
    // Read-only: system paths (now at "/..."); read-write: worktree, rw extras,
    // /tmp, home, /run/moochy (gateway + its socket).
    let created = created
        .add_rules(path_beneath_rules(
            ["/"].iter().map(PathBuf::from),
            AccessFs::from_read(abi),
        ))
        .map_err(ll("ro root rule"))?;
    let rw: Vec<PathBuf> = std::iter::once(plan.worktree.clone())
        .chain(plan.rw_paths.iter().map(|b| b.real.clone()))
        .chain(["/tmp", "/home/sandbox", "/run/moochy", "/dev/shm", "/dev/null", "/dev/zero", "/dev/full"].map(PathBuf::from))
        .collect();
    let created = created
        .add_rules(path_beneath_rules(rw, AccessFs::from_all(abi)))
        .map_err(ll("rw rule"))?;
    let status = created
        .no_new_privs(false) // we set it ourselves right after
        .restrict_self()
        .map_err(ll("restrict_self"))?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(Error::Unsupported("Landlock unavailable; FS second layer missing"));
    }
    Ok(())
}

fn ll(what: &'static str) -> impl Fn(landlock::RulesetError) -> Error {
    move |e| setup(what, std::io::Error::other(e.to_string()))
}

/// Preflight: the kernel features we require, with an actionable error when
/// unprivileged user namespaces are blocked (Ubuntu AppArmor restriction).
fn preflight() -> Result<(), Error> {
    let restrict = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .is_ok_and(|s| s.trim() == "1");
    // Probe: can we create a user namespace at all?
    if let Err(e) = probe_userns() {
        if restrict {
            return Err(Error::UserNsRestricted(apparmor_fix()));
        }
        return Err(setup("user namespace probe", e));
    }
    Ok(())
}

fn probe_userns() -> std::io::Result<()> {
    // Fork a child that just tries unshare(NEWUSER) and reports via exit code.
    // SAFETY: child only calls unshare + _exit.
    match sys::fork()? {
        sys::Fork::Child => {
            // Exercise the real first steps: Ubuntu's AppArmor restriction lets
            // unshare(NEWUSER) succeed but strips the namespace's capabilities,
            // so only the id maps / a mount change reveal it.
            let uid = rustix::process::getuid().as_raw();
            let gid = rustix::process::getgid().as_raw();
            let ok = sys::unshare(UnshareFlags::NEWUSER | UnshareFlags::NEWNS).is_ok()
                && write_id_maps(uid, gid).is_ok()
                && mount_change("/", MountPropagationFlags::PRIVATE | MountPropagationFlags::REC).is_ok();
            sys::exit_immediately(i32::from(!ok));
        }
        sys::Fork::Parent(pid) => match crate::donor::wait_raw(pid) {
            Ok(0) => Ok(()),
            _ => Err(std::io::Error::other("unshare(NEWUSER) failed")),
        },
    }
}

/// The exact fix `moochy doctor` prints: a per-binary AppArmor profile for the
/// binary that is actually running (never the global sysctl).
pub fn apparmor_fix() -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map_or_else(|| "/usr/local/bin/moochy".to_string(), |p| p.to_string_lossy().into_owned());
    format!(
        "Unprivileged user namespaces are restricted on this host \
         (kernel.apparmor_restrict_unprivileged_userns=1). Grant `userns` to this binary only \
         with /etc/apparmor.d/moochy:\n\n\
         abi <abi/4.0>,\n\
         include <tunables/global>\n\
         profile moochy {exe} flags=(unconfined) {{\n  userns,\n  include if exists <local/moochy>\n}}\n\n\
         then run: sudo apparmor_parser -r /etc/apparmor.d/moochy\n\
         (Do NOT set the sysctl to 0: that hands the permission to every program on the host.)"
    )
}

fn build_env(spec: &Spec) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = vec![
        ("PATH".into(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()),
        ("HOME".into(), "/home/sandbox".into()),
        ("TMPDIR".into(), "/tmp".into()),
        ("USER".into(), "sandbox".into()),
        ("TERM".into(), std::env::var_os("TERM").unwrap_or_else(|| "xterm".into())),
    ];
    if !spec.allow_hosts.is_empty() && !spec.unsafe_no_sandbox {
        let url = format!("http://127.0.0.1:{}", crate::PROXY_LOOPBACK_PORT);
        for k in ["HTTPS_PROXY", "https_proxy"] {
            env.push((k.into(), url.clone().into()));
        }
        for k in ["NO_PROXY", "no_proxy"] {
            env.push((k.into(), "127.0.0.1,localhost".into()));
        }
    }
    for (k, v) in &spec.env {
        env.push((k.clone(), v.clone()));
    }
    if let Some(tok) = &spec.run_token {
        env.push((crate::RUN_TOKEN_ENV.into(), tok.into()));
    }
    env
}

fn run_unsandboxed(spec: &Spec, program: &OsStr, args: &[OsString]) -> Result<i32, Error> {
    let mut cmd = Command::new(program);
    cmd.args(args).env_clear();
    for (k, v) in build_env(spec) {
        cmd.env(k, v);
    }
    cmd.current_dir(&spec.worktree);
    let status = cmd.status().map_err(Error::Exec)?;
    Ok(exit_code(status))
}

// ───────────────────────── small fs helpers ─────────────────────────

fn mkdir(p: &Path) -> Result<(), Error> {
    match rustix::fs::mkdir(p, Mode::from_raw_mode(0o755)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(setup("mkdir", e.into())),
    }
}
fn mkdir_p(p: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(p).map_err(|e| setup("mkdir_p", e))
}
fn touch(p: &Path) -> Result<(), Error> {
    if let Some(parent) = p.parent() {
        mkdir_p(parent)?;
    }
    match rustix::fs::open(
        p,
        OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    ) {
        Ok(_) | Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(setup("touch", e.into())),
    }
}

/// A unique scratch directory removed on drop. Holds the root skeleton and the
/// empty mask sources. Lives in `$TMPDIR` (or `/tmp`).
struct ScratchDir(PathBuf);
impl ScratchDir {
    fn new() -> Result<Self, Error> {
        let mut buf = [0u8; 8];
        getrandom(&mut buf)?;
        let name = format!("moochy-run-{}", crate::hex(&buf));
        let dir = std::env::temp_dir().join(name);
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| setup("scratch mkdir", e))?;
        }
        std::fs::create_dir(dir.join("empty")).map_err(|e| setup("scratch empty", e))?;
        std::fs::write(dir.join("empty_file"), b"").map_err(|e| setup("scratch empty_file", e))?;
        Ok(Self(dir))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn getrandom(buf: &mut [u8]) -> Result<(), Error> {
    use std::io::Read as _;
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| setup("urandom", e))?;
    f.read_exact(buf).map_err(|e| setup("urandom read", e))
}


// Keep the OsStr import used even if future edits drop a usage.
#[allow(dead_code)]
fn _os(_: &OsStr) -> &[u8] {
    OsStr::new("").as_bytes()
}
