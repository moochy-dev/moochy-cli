//! cgroup v2 limits for one run (CONTRACT §15.1: "cgroup v2 limits when a
//! delegated cgroup is available"). Graceful: without one, rlimits stay the
//! only limits and the run proceeds.
//!
//! The launcher's own cgroup holds the launcher, so (no-internal-process rule)
//! controllers can't be enabled below it. The run's cgroup is created as its
//! **sibling** instead, in the parent, when the parent is ours: writable and
//! already delegating controllers to its children. That is the case under a
//! systemd user manager (`user@UID.service/app.slice`, tmux/terminal scopes,
//! `systemd-run --user --scope`), not under a root-owned login `session-N.scope`.
//! The sandbox's first process moves itself in before `unshare`, so every
//! descendant is inside; at the end `cgroup.kill` takes out anything left and
//! the directory is removed.

use std::path::{Path, PathBuf};

use rustix::fs::{Access, access};

const ROOT: &str = "/sys/fs/cgroup";
const PREFIX: &str = "moochy-run-";

/// The parent of our own cgroup, if we may create the run's cgroup in it.
pub fn delegated_parent() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    let own = Path::new(ROOT).join(rel.trim().trim_start_matches('/'));
    let parent = own.parent().filter(|p| p.starts_with(ROOT))?;
    let ctl = std::fs::read_to_string(parent.join("cgroup.subtree_control")).ok()?;
    if !ctl.split_whitespace().any(|c| matches!(c, "memory" | "pids" | "cpu")) {
        return None;
    }
    access(parent, Access::WRITE_OK | Access::EXEC_OK).ok()?;
    // Migration needs write access to the common ancestor's cgroup.procs.
    access(parent.join("cgroup.procs"), Access::WRITE_OK).ok()?;
    Some(parent.to_path_buf())
}

/// One run's cgroup; killed and removed on drop.
pub struct Cgroup(PathBuf);

impl Cgroup {
    /// `None` (graceful) when no delegated cgroup exists or it can't be made.
    /// Each limit is written only where its controller is delegated.
    pub fn create(limits: &crate::Limits, id: &str) -> Option<Self> {
        let parent = delegated_parent()?;
        sweep_stale(&parent);
        let dir = parent.join(format!("{PREFIX}{}-{id}", std::process::id()));
        std::fs::create_dir(&dir).ok()?;
        let cg = Self(dir);
        if limits.processes > 0 {
            cg.set("pids.max", &limits.processes.to_string());
        }
        if limits.memory_total_bytes > 0 {
            cg.set("memory.max", &limits.memory_total_bytes.to_string());
            cg.set("memory.swap.max", "0"); // else memory.max just swaps
        }
        if let Some(quota) = u64::from(limits.cpu_percent).checked_mul(1000).filter(|q| *q > 0) {
            cg.set("cpu.max", &format!("{quota} 100000"));
        }
        Some(cg)
    }

    /// The file the sandbox's first process writes `0` to, to move itself in.
    pub fn procs(&self) -> PathBuf {
        self.0.join("cgroup.procs")
    }

    fn set(&self, file: &str, value: &str) {
        let p = self.0.join(file);
        if p.exists() {
            let _ = std::fs::write(p, value);
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = std::fs::write(self.0.join("cgroup.kill"), "1");
        // Killed tasks leave the cgroup asynchronously; rmdir is EBUSY until then.
        for _ in 0..200 {
            if std::fs::remove_dir(&self.0).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// Remove run cgroups left by a SIGKILLed launcher: only those whose launcher
/// pid is gone (a concurrent run's cgroup may still be empty during its setup),
/// and rmdir fails on a non-empty one anyway.
fn sweep_stale(parent: &Path) {
    let Ok(rd) = std::fs::read_dir(parent) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.strip_prefix(PREFIX)).and_then(|r| r.split('-').next()) else {
            continue;
        };
        if pid.parse::<u32>().is_ok() && !Path::new("/proc").join(pid).exists() {
            let _ = std::fs::remove_dir(e.path());
        }
    }
}
