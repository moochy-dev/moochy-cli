//! `moochy doctor` lines for the sandbox (CONTRACT §15.1: "detect and explain"):
//! host support, the Landlock ABI and what it covers, cgroup limits, and the
//! exact paths masked in a worktree. Ready to print: every path is escaped
//! (repo file names are untrusted text, never raw terminal bytes).

use std::path::Path;

/// How `moochy doctor` should mark a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Ok,
    /// Works, with a limitation worth knowing.
    Note,
    /// `moochy run` will refuse.
    Fail,
}

#[derive(Clone, Debug)]
pub struct Line {
    pub level: Level,
    pub topic: &'static str,
    pub text: String,
}

fn line(level: Level, topic: &'static str, text: impl Into<String>) -> Line {
    Line { level, topic, text: text.into() }
}

/// Untrusted text (a path) as printable ASCII.
fn esc(s: &str) -> String {
    s.chars().flat_map(char::escape_debug).collect()
}

/// Masked paths listed per worktree at most (the count is always given).
const MASKS_SHOWN: usize = 50;

/// Host support, then (with `worktree`) what the agent will not see there.
#[must_use]
pub fn doctor(worktree: Option<&Path>) -> Vec<Line> {
    let mut v = host();
    if let Some(wt) = worktree {
        masks(wt, &mut v);
    }
    v
}

#[cfg(target_os = "linux")]
fn host() -> Vec<Line> {
    let mut v = Vec::new();
    v.push(match crate::linux::preflight() {
        Ok(()) => line(Level::Ok, "sandbox", "unprivileged user namespaces available: `moochy run` can build its sandbox"),
        Err(crate::Error::UserNsRestricted(fix)) => line(Level::Fail, "sandbox", fix),
        Err(e) => line(Level::Fail, "sandbox", e.to_string()),
    });
    let abi = crate::sys::landlock_abi();
    let missing = missing_layers(abi, true);
    v.push(match (abi, missing.is_empty()) {
        (0, _) => line(Level::Fail, "landlock", "Landlock unavailable: `moochy run` and the donor lockdown refuse"),
        (_, true) => line(Level::Ok, "landlock", format!("ABI {abi}: every layer the sandbox uses")),
        (_, false) => line(Level::Note, "landlock", format!("ABI {abi}; not on this kernel: {}", missing.join(", "))),
    });
    v.push(match crate::cgroup::delegated_parent() {
        Some(p) => line(Level::Ok, "cgroup", format!("run limits (memory, pids, cpu) in {}", esc(&p.to_string_lossy()))),
        None => line(
            Level::Note,
            "cgroup",
            "no delegated cgroup: rlimits only (run from a systemd user session, e.g. `systemd-run --user --scope moochy run …`)",
        ),
    });
    v
}

/// The Landlock layers above ABI 1 this kernel lacks; `donor` adds the donor-only one.
#[cfg(target_os = "linux")]
pub(crate) fn missing_layers(abi: i32, donor: bool) -> Vec<String> {
    [(4, "TCP port rules", false), (6, "abstract-socket and signal scoping", false), (8, "all-thread enforcement for the donor", true), (9, "pathname UNIX socket rules", false)]
        .into_iter()
        .filter(|(n, _, d)| abi < *n && (donor || !d))
        .map(|(n, what, _)| format!("{what} (ABI {n})"))
        .collect()
}

#[cfg(target_os = "macos")]
fn host() -> Vec<Line> {
    vec![if Path::new("/usr/bin/sandbox-exec").exists() {
        line(Level::Ok, "sandbox", "Seatbelt (sandbox-exec) available: `moochy run` can build its sandbox")
    } else {
        line(Level::Fail, "sandbox", "/usr/bin/sandbox-exec not found: `moochy run` refuses")
    }]
}

fn masks(wt: &Path, v: &mut Vec<Line>) {
    let root = wt.canonicalize().unwrap_or_else(|_| wt.to_path_buf());
    match crate::mask::collect(&root) {
        Ok(m) => {
            v.push(line(Level::Ok, "masks", format!("{} path(s) hidden from the agent in {}", m.len(), esc(&root.to_string_lossy()))));
            for p in m.iter().take(MASKS_SHOWN) {
                v.push(line(Level::Ok, "masks", format!("  {}", esc(&p.strip_prefix(&root).unwrap_or(p).to_string_lossy()))));
            }
            if m.len() > MASKS_SHOWN {
                v.push(line(Level::Ok, "masks", format!("  … and {} more", m.len().saturating_sub(MASKS_SHOWN))));
            }
        }
        Err(e) => v.push(line(Level::Fail, "masks", esc(&e.to_string()))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    #[test]
    fn mask_paths_are_escaped_and_relative() {
        let root = std::env::temp_dir().join(format!("moochy-doctor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("id_rsa\x1b[2J"), b"x").unwrap();
        let v = super::doctor(Some(&root));
        let m: Vec<_> = v.iter().filter(|l| l.topic == "masks").collect();
        assert!(m[0].text.starts_with("1 path(s)"), "{m:?}");
        assert_eq!(m[1].text, "  id_rsa\\u{1b}[2J");
        assert!(v.iter().all(|l| !l.text.contains('\x1b')));
        let _ = std::fs::remove_dir_all(&root);
    }
}
