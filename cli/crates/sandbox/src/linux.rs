//! Maintainer side (CONTRACT §15.1): run a command and everything it spawns
//! inside an unprivileged user/mount/PID/net/IPC/UTS-namespace jail with a
//! `pivot_root` minimal view, Landlock FS second layer, seccomp, dropped caps,
//! rlimits and `no_new_privs`. Fails closed.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
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
    let (uid, gid) = (rustix::process::getuid(), rustix::process::getgid());

    let plan = Plan {
        base: base.path().to_path_buf(),
        worktree,
        ro_paths: spec.ro_paths.iter().filter(|p| p.exists()).cloned().collect(),
        rw_paths: spec.rw_paths.clone(),
        gateway_socket: spec.gateway_socket.clone(),
        masks,
        uid_raw: uid.as_raw(),
        gid_raw: gid.as_raw(),
        limits: spec.limits,
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
    let status = child.wait().map_err(Error::Exec)?;
    drop(base);
    Ok(exit_code(&status))
}

fn exit_code(s: &std::process::ExitStatus) -> i32 {
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
    ro_paths: Vec<PathBuf>,
    rw_paths: Vec<PathBuf>,
    gateway_socket: Option<PathBuf>,
    masks: Vec<PathBuf>,
    uid_raw: u32,
    gid_raw: u32,
    limits: crate::Limits,
}

/// The pre_exec closure. Returns `Ok(())` only in the agent branch (std then
/// execs). Any error aborts the spawn (fail closed).
fn child_main(plan: &Plan, filter: &seccompiler::BpfProgram) -> std::io::Result<()> {
    build_namespaces_and_view(plan).map_err(to_io)?;

    // Fork: the child becomes PID 1 in the new PID namespace (it is the agent);
    // the current process stays outside and reaps it. Both branches reach execve
    // or _exit with only syscalls; the agent branch's allocations (Landlock)
    // happen before seccomp, in a child that is single-threaded here.
    match sys::fork()? {
        sys::Fork::Parent(agent_pid) => {
            // Reaper: wait for the agent, propagate its code. Never returns.
            let code = crate::donor::wait_raw(agent_pid).unwrap_or(-1);
            sys::exit_immediately(code);
        }
        sys::Fork::Child => {
            harden_agent(plan, filter).map_err(to_io)?;
            Ok(()) // → std performs execve(program, argv, envp)
        }
    }
}

fn to_io(e: Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Child, pre-fork: new namespaces, uid/gid maps, the pivoted minimal view.
fn build_namespaces_and_view(plan: &Plan) -> Result<(), Error> {
    sys::unshare(
        UnshareFlags::NEWUSER
            | UnshareFlags::NEWNS
            | UnshareFlags::NEWPID
            | UnshareFlags::NEWNET
            | UnshareFlags::NEWIPC
            | UnshareFlags::NEWUTS,
    )
    .map_err(io("unshare"))?;

    write_id_maps(plan.uid_raw, plan.gid_raw)?;
    let _ = rustix::system::sethostname(b"moochy");

    // All mounts private so nothing propagates back to the host.
    mount_change("/", MountPropagationFlags::PRIVATE | MountPropagationFlags::REC)
        .map_err(io("make-rprivate"))?;

    let root = plan.base.join("root");
    mkdir(&root)?;
    // tmpfs as the new root skeleton.
    mount("tmpfs", &root, "tmpfs", MountFlags::NOSUID | MountFlags::NODEV, None)
        .map_err(io("mount root tmpfs"))?;

    // Read-only system paths (visibility only; Landlock enforces read-only).
    for p in &plan.ro_paths {
        bind_into(&root, p, false)?;
    }
    // Read-write extras + the worktree.
    for p in &plan.rw_paths {
        bind_into(&root, p, true)?;
    }
    bind_into(&root, &plan.worktree, true)?;

    // Mask secret-shaped / git-ignored files inside the worktree (§15.4).
    apply_masks(&root, plan)?;

    // Private tmpfs home + tmp.
    for (dir, mode) in [("tmp", 0o1777u32), ("home/sandbox", 0o700), ("run/moochy", 0o755)] {
        let t = root.join(dir);
        mkdir_p(&t)?;
        mount("tmpfs", &t, "tmpfs", MountFlags::NOSUID | MountFlags::NODEV, None)
            .map_err(io("mount tmpfs"))?;
        let _ = mode;
    }

    // Minimal /dev.
    setup_dev(&root)?;

    // Gateway Unix socket bridged in read-write (the one allowed channel).
    if let Some(sock) = &plan.gateway_socket {
        let dst = root.join("run/moochy/gateway.sock");
        touch(&dst)?;
        mount_bind_recursive(sock, &dst).map_err(io("bind gateway socket"))?;
    }

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

/// Bind `src` (host absolute path) into `root` at the same absolute path.
fn bind_into(root: &Path, src: &Path, writable: bool) -> Result<(), Error> {
    let rel = src.strip_prefix("/").unwrap_or(src);
    let dst = root.join(rel);
    let meta = std::fs::symlink_metadata(src).map_err(|e| setup("stat bind src", e))?;
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

fn setup_dev(root: &Path) -> Result<(), Error> {
    let dev = root.join("dev");
    mkdir_p(&dev)?;
    mount("tmpfs", &dev, "tmpfs", MountFlags::NOSUID, None).map_err(io("mount /dev"))?;
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
fn harden_agent(plan: &Plan, filter: &seccompiler::BpfProgram) -> Result<(), Error> {
    // /proc of the NEW pid namespace (we are a task in it now).
    mkdir_p(Path::new("/proc")).ok();
    mount("proc", "/proc", "proc", MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC, None)
        .map_err(io("mount /proc"))?;

    chdir_into_worktree(plan)?;
    apply_rlimits(&plan.limits)?;

    // Die with our reaper parent; detach from any controlling terminal (blocks
    // TIOCSTI injection into the launching shell).
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(io("pdeathsig"))?;
    let _ = rustix::process::setsid();

    drop_all_caps();
    landlock_agent(plan)?;
    rustix::thread::set_no_new_privs(true).map_err(io("no_new_privs"))?;
    seccompiler::apply_filter(filter)
        .map_err(|e| setup("seccomp apply", std::io::Error::other(e.to_string())))?;
    Ok(())
}

fn chdir_into_worktree(plan: &Plan) -> Result<(), Error> {
    rustix::process::chdir(&plan.worktree).map_err(io("chdir worktree"))?;
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
    let created = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(ll("fs handle"))?
        .create()
        .map_err(ll("create"))?;
    // Read-only: system paths (now at "/..."); read-write: worktree, rw extras,
    // /tmp, home, /run/moochy (gateway + its socket).
    let created = created
        .add_rules(path_beneath_rules(
            ["/"].iter().map(PathBuf::from),
            AccessFs::from_read(abi),
        ))
        .map_err(ll("ro root rule"))?;
    let rw: Vec<PathBuf> = std::iter::once(plan.worktree.clone())
        .chain(plan.rw_paths.iter().cloned())
        .chain([PathBuf::from("/tmp"), PathBuf::from("/home/sandbox"), PathBuf::from("/run/moochy")])
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
        .ok()
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
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
            let ok = sys::unshare(UnshareFlags::NEWUSER).is_ok();
            sys::exit_immediately(i32::from(!ok));
        }
        sys::Fork::Parent(pid) => match crate::donor::wait_raw(pid) {
            Ok(0) => Ok(()),
            _ => Err(std::io::Error::other("unshare(NEWUSER) failed")),
        },
    }
}

/// The exact fix `moochy doctor` prints (AppArmor per-binary profile).
pub fn apparmor_fix() -> String {
    "Unprivileged user namespaces are restricted on this host \
     (kernel.apparmor_restrict_unprivileged_userns=1). Install a per-binary AppArmor \
     profile that grants `userns` to the moochy binary only, e.g. in \
     /etc/apparmor.d/moochy:\n\n\
     abi <abi/4.0>,\n\
     include <tunables/global>\n\
     profile moochy /usr/local/bin/moochy flags=(unconfined) {\n  userns,\n  \
     include if exists <local/moochy>\n}\n\n\
     then: sudo apparmor_parser -r /etc/apparmor.d/moochy\n\
     (Do NOT set the sysctl to 0 globally; that weakens the whole host.)"
        .to_string()
}

fn build_env(spec: &Spec) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = vec![
        ("PATH".into(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()),
        ("HOME".into(), "/home/sandbox".into()),
        ("TMPDIR".into(), "/tmp".into()),
        ("USER".into(), "sandbox".into()),
        ("TERM".into(), std::env::var_os("TERM").unwrap_or_else(|| "xterm".into())),
    ];
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
    Ok(exit_code(&status))
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
        Ok(_) => Ok(()),
        Err(rustix::io::Errno::EXIST) => Ok(()),
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
        let name = format!("moochy-run-{}", hex(&buf));
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir(&dir).map_err(|e| setup("scratch mkdir", e))?;
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

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

// Keep the OsStr import used even if future edits drop a usage.
#[allow(dead_code)]
fn _os(_: &OsStr) -> &[u8] {
    OsStr::new("").as_bytes()
}
