//! What of a worktree's git metadata the agent may see and write (§15.1/§15.4).
//!
//! Git trusts files under `$GIT_DIR` that make the *host* run code later:
//! `hooks/`, `config` (`core.fsmonitor`, `core.hooksPath`, aliases), and
//! `commondir`, which any repo honours and which redirects config and hooks
//! to another directory. An agent able to create `$GIT_DIR/commondir` gets code
//! run on the host's next `git status` (an IDE polls it constantly), and no mount
//! can block one new filename in a writable dir. Hence:
//!
//! - **default**: the whole `.git` is read-only inside (git reads work; commits
//!   happen outside, or with the opt-in below). Same choice as Codex.
//! - **`git_writable`**: `.git` writable except every path git reads config, hooks or a
//!   redirect from ([`GIT_TRUSTED`], G20). A mount can only cover a name that exists, so a
//!   missing one is created first: an empty dir, an empty `config.worktree`, and a `commondir`
//!   of `.` (git reads that as "this dir"; an empty one makes git die), which the caller
//!   removes after the run. Residual: a `rebase-merge/` todo list the agent wrote runs its `exec`
//!   lines if the user continues that rebase.
//! - **linked worktree** (`.git` is a file): always read-only — the shared
//!   commondir and this worktree's own gitdir are visible, other worktrees'
//!   gitdirs are hidden, and the main worktree's files never enter the view.
//! - **nested** `.git` (submodules, vendored repos): always read-only.
//! - **no `.git`**: an empty read-only placeholder dir is mounted, so `git init`
//!   inside can't plant a repo (and its `core.fsmonitor`) for the host's git;
//!   removed after the run (git ignores an empty `.git` dir).
//!
//! A new `.git` in a subdirectory can't be prevented by mounts; [`snapshot`] +
//! [`changed`] let `moochy run` print a notice when any git metadata the host
//! would trust changed during the run (A191).

use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Git paths of one worktree, resolved on the host (canonical).
#[derive(Debug, Default)]
pub struct GitView {
    /// Paths (dirs or files) to make read-only inside.
    pub read_only: Vec<PathBuf>,
    /// Set for a linked worktree / submodule checkout.
    pub linked: Option<Linked>,
    /// The empty `.git` dir created because the worktree had none; the caller
    /// removes it after the run.
    pub placeholder: Option<PathBuf>,
    /// The `commondir` of `.` created for `git_writable`; the caller removes it after the run.
    pub commondir_dot: Option<PathBuf>,
}

/// Names under `$GIT_DIR` that make the host's git run code, read config or redirect (G20):
/// read-only even with `git_writable`. Directories first, then files.
pub const GIT_TRUSTED: &[&str] = &["hooks", "info", "modules", "worktrees", "branches", "remotes", "config", "config.worktree", "commondir"];
const GIT_TRUSTED_DIRS: usize = 6;

/// Content of a `commondir` that points git at its own dir.
pub const COMMONDIR_DOT: &str = ".\n";

/// The gitdir layout of a worktree whose `.git` is a file.
#[derive(Debug)]
pub struct Linked {
    /// This worktree's own gitdir (`<common>/worktrees/<name>` or a submodule's).
    pub gitdir: PathBuf,
    /// The shared repository dir (objects, refs, config, hooks), if any.
    pub commondir: Option<PathBuf>,
    /// `<common>/worktrees`: hidden, except `gitdir` when it lives there.
    pub worktrees_dir: Option<PathBuf>,
}

/// Small control files (`.git`, `commondir`) are read with this cap.
const CTL_MAX: u64 = 4096;

fn read_small(p: &Path) -> Option<String> {
    let mut s = String::new();
    std::fs::File::open(p).ok()?.take(CTL_MAX).read_to_string(&mut s).ok()?;
    Some(s)
}

/// A directory that really is a git dir (so a forged `gitdir: ~/.ssh` can never
/// pull an arbitrary directory into the view).
fn looks_like_gitdir(p: &Path) -> bool {
    p.join("HEAD").is_file()
}

/// Resolve the git view of `worktree` (canonical): [`top_view`] plus every
/// nested `.git` (from [`crate::mask::scan`]) read-only.
pub fn view(worktree: &Path, git_writable: bool, dotgits: &[PathBuf]) -> Result<GitView, crate::Error> {
    let top = worktree.join(".git");
    let mut v = top_view(worktree, git_writable)?;
    v.read_only.extend(dotgits.iter().filter(|p| **p != top).cloned());
    if std::fs::symlink_metadata(&top).is_err() {
        std::fs::create_dir(&top).map_err(|err| crate::Error::Setup { what: "create .git placeholder", err })?;
        v.read_only.push(top.clone());
        v.placeholder = Some(top);
    }
    Ok(v)
}

/// The top-level `.git`. Missing or malformed git metadata yields an empty
/// view (the worktree simply has no usable git).
fn top_view(worktree: &Path, git_writable: bool) -> Result<GitView, crate::Error> {
    let dotgit = worktree.join(".git");
    let Ok(meta) = std::fs::symlink_metadata(&dotgit) else { return Ok(GitView::default()) };
    if meta.is_dir() {
        if !git_writable {
            return Ok(GitView { read_only: vec![dotgit], ..GitView::default() });
        }
        let commondir_dot = create_trusted(&dotgit)?;
        let read_only = GIT_TRUSTED.iter().map(|n| dotgit.join(n)).collect();
        return Ok(GitView { read_only, commondir_dot, ..GitView::default() });
    }
    Ok(linked_view(worktree, &dotgit, &meta))
}

/// Create every missing [`GIT_TRUSTED`] path (so a read-only bind can cover it); returns the
/// `commondir` created. Fails closed.
fn create_trusted(dotgit: &Path) -> Result<Option<PathBuf>, crate::Error> {
    use std::io::Write as _;
    let err = |err| crate::Error::Setup { what: "create the read-only git paths", err };
    let exists = |r: std::io::Result<()>| match r {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        r => r.map(|()| true).map_err(err),
    };
    for (i, name) in GIT_TRUSTED.iter().enumerate() {
        let p = dotgit.join(name);
        let made = if i < GIT_TRUSTED_DIRS {
            exists(std::fs::create_dir(&p))?
        } else {
            let text = if *name == "commondir" { COMMONDIR_DOT } else { "" };
            exists(std::fs::OpenOptions::new().write(true).create_new(true).open(&p).and_then(|mut f| f.write_all(text.as_bytes())))?
        };
        if made && *name == "commondir" {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

fn linked_view(worktree: &Path, dotgit: &Path, meta: &std::fs::Metadata) -> GitView {
    let dotgit = dotgit.to_path_buf();
    if !meta.is_file() {
        return GitView::default();
    }
    // `.git` file: "gitdir: <path>" (relative to the worktree).
    let Some(text) = read_small(&dotgit) else { return GitView::default() };
    let Some(rel) = text.lines().next().and_then(|l| l.strip_prefix("gitdir:")) else {
        return GitView::default();
    };
    let Ok(gitdir) = worktree.join(rel.trim()).canonicalize() else { return GitView::default() };
    if !looks_like_gitdir(&gitdir) {
        return GitView { read_only: vec![dotgit], ..GitView::default() };
    }
    let commondir = read_small(&gitdir.join("commondir"))
        .and_then(|c| gitdir.join(c.trim()).canonicalize().ok())
        .filter(|c| looks_like_gitdir(c) && c.join("objects").is_dir());
    let worktrees_dir = commondir
        .as_ref()
        .map(|c| c.join("worktrees"))
        .filter(|w| w.is_dir());
    GitView {
        // The `.git` file itself: rewriting it would redirect the host's git.
        read_only: vec![dotgit],
        linked: Some(Linked { gitdir, commondir, worktrees_dir }),
        ..GitView::default()
    }
}

/// The config files git reads for one `.git` entry (a dir, or a `gitdir:` file): `config` and
/// `config.worktree`, plus the shared repository's `config` behind a `commondir`.
#[must_use]
pub fn config_files(dotgit: &Path) -> Vec<PathBuf> {
    let dir = if dotgit.is_dir() {
        Some(dotgit.to_path_buf())
    } else {
        read_small(dotgit)
            .and_then(|t| Some(t.lines().next()?.strip_prefix("gitdir:")?.trim().to_owned()))
            .and_then(|rel| dotgit.parent()?.join(rel).canonicalize().ok())
    };
    let Some(dir) = dir.filter(|d| looks_like_gitdir(d)) else { return Vec::new() };
    let common = read_small(&dir.join("commondir")).and_then(|c| dir.join(c.trim()).canonicalize().ok()).filter(|c| looks_like_gitdir(c));
    [dir.join("config"), dir.join("config.worktree")].into_iter().chain(common.map(|c| c.join("config"))).filter(|p| p.is_file()).collect()
}

/// A git config that can carry a credential (F21): a URL with a user part
/// (`https://x-access-token:…@host`), an `extraheader` (actions/checkout's
/// `AUTHORIZATION: basic …`), or a `credential` section or key. ASCII case-insensitive.
#[must_use]
pub fn holds_credentials(cfg: &[u8]) -> bool {
    let low = cfg.to_ascii_lowercase();
    let has = |n: &[u8]| low.windows(n.len()).any(|w| w == n);
    if has(b"extraheader") || has(b"[credential") || has(b"credential.") {
        return true;
    }
    // `scheme://user[:pass]@host`: an `@` before the end of the authority.
    low.windows(3).enumerate().filter(|(_, w)| *w == b"://").any(|(i, _)| {
        low.get(i.saturating_add(3)..)
            .unwrap_or_default()
            .iter()
            .take_while(|c| !matches!(c, b'/' | b'"' | b'\'' | b' ' | b'\t' | b'\r' | b'\n'))
            .any(|c| *c == b'@')
    })
}

/// What the host's git would trust, per `.git`: its kind, and for a dir the
/// files that make git run code or redirect (`config`, `config.worktree`,
/// `commondir`) plus the `hooks/` listing. Sorted by path.
pub type Snapshot = std::collections::BTreeMap<PathBuf, Vec<u8>>;

const SNAP_MAX: u64 = 64 * 1024;

fn read_capped(p: &Path) -> Vec<u8> {
    let mut v = Vec::new();
    if let Ok(f) = std::fs::File::open(p) {
        let _ = f.take(SNAP_MAX).read_to_end(&mut v);
    }
    v
}

#[must_use]
pub fn snapshot(dotgits: &[PathBuf]) -> Snapshot {
    use std::os::unix::fs::MetadataExt as _;
    let mut s = Snapshot::new();
    for g in dotgits {
        let Ok(meta) = std::fs::symlink_metadata(g) else { continue };
        if !meta.is_dir() {
            s.insert(g.clone(), read_capped(g));
            continue;
        }
        s.insert(g.clone(), b"dir".to_vec());
        for f in ["config", "config.worktree", "commondir"] {
            let p = g.join(f);
            if p.exists() {
                s.insert(p.clone(), read_capped(&p));
            }
        }
        let mut hooks: Vec<(std::ffi::OsString, u64, i64, i64)> = std::fs::read_dir(g.join("hooks"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.metadata().ok().map(|m| (e.file_name(), m.size(), m.mtime(), m.mtime_nsec())))
            .collect();
        hooks.sort();
        s.insert(g.join("hooks"), format!("{hooks:?}").into_bytes());
    }
    s
}

/// The first path whose git metadata differs between two snapshots.
#[must_use]
pub fn changed(before: &Snapshot, after: &Snapshot) -> Option<PathBuf> {
    before
        .keys()
        .chain(after.keys())
        .filter(|k| before.get(*k) != after.get(*k))
        .min()
        .cloned()
}

/// New or changed executables in git-ignored paths listed in the notice, at most.
const EXEC_SHOWN: usize = 5;

/// Print the A191 notice (one line) when git metadata changed during the run, and one when
/// executables appeared in git-ignored paths since `since` (jail review #4).
/// Paths are agent-chosen: printed escaped (`{:?}`), never raw.
#[allow(clippy::unnecessary_debug_formatting)] // Debug = escaped: the path is agent-chosen
pub fn notice_if_changed(worktree: &Path, before: &Snapshot, since: std::time::SystemTime) {
    match crate::mask::new_executables(worktree, since) {
        Ok(v) if v.is_empty() => {}
        Ok(v) => {
            let shown: Vec<_> = v.iter().take(EXEC_SHOWN).map(|p| p.strip_prefix(worktree).unwrap_or(p)).collect();
            let more = if v.len() > EXEC_SHOWN { ", …" } else { "" };
            eprintln!(
                "moochy: notice: {} new or changed executable file(s) in git-ignored paths ({shown:?}{more}); git status does not show them: review them before running anything from {worktree:?}",
                v.len()
            );
        }
        Err(e) => eprintln!("moochy: notice: could not check git-ignored paths for new executables ({e}); review {worktree:?} before running anything from it"),
    }
    let after = crate::mask::dotgits(worktree).map(|d| snapshot(&d));
    let what = match &after {
        Ok(after) => changed(before, after),
        Err(_) => Some(worktree.to_path_buf()),
    };
    if let Some(p) = what {
        let rel = p.strip_prefix(worktree).unwrap_or(&p);
        eprintln!(
            "moochy: notice: git metadata changed during the run ({rel:?}); review it before running git in {worktree:?} (hooks/config there run on the host)"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn forged_gitdir_pointing_at_a_plain_dir_is_not_exposed() {
        let root = std::env::temp_dir().join(format!("moochy-gitview-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("wt")).unwrap();
        std::fs::create_dir_all(root.join("secret")).unwrap();
        std::fs::write(root.join("wt/.git"), "gitdir: ../secret\n").unwrap();
        let v = top_view(&root.join("wt").canonicalize().unwrap(), false).unwrap();
        assert!(v.linked.is_none(), "{v:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn credential_bearing_configs() {
        for cfg in [
            "[remote \"origin\"]\n\turl = https://x-access-token:ghs_abc@github.com/o/r\n",
            "[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic eC1hY2Nlc3M=\n",
            "[remote \"o\"]\n\turl = https://gitlab-ci-token:glcbt-x@gitlab.com/g/p.git\n",
            "[credential]\n\thelper = store\n",
        ] {
            assert!(holds_credentials(cfg.as_bytes()), "{cfg}");
        }
        for cfg in ["[core]\n\tbare = false\n", "[remote \"o\"]\n\turl = git@github.com:o/r.git\n", "[remote \"o\"]\n\turl = https://github.com/o/r@v1\n"] {
            assert!(!holds_credentials(cfg.as_bytes()), "{cfg}");
        }
    }

    #[test]
    fn snapshot_sees_new_nested_repo_and_hook_changes() {
        let root = std::env::temp_dir().join(format!("moochy-gitsnap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::write(root.join(".git/config"), "[core]\n").unwrap();
        let before = snapshot(&crate::mask::dotgits(&root).unwrap());
        assert_eq!(changed(&before, &snapshot(&crate::mask::dotgits(&root).unwrap())), None);
        std::fs::create_dir_all(root.join("sub/.git")).unwrap();
        let after = snapshot(&crate::mask::dotgits(&root).unwrap());
        assert_eq!(changed(&before, &after), Some(root.join("sub/.git")));
        std::fs::remove_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join(".git/hooks/pre-commit"), "x").unwrap();
        let after = snapshot(&crate::mask::dotgits(&root).unwrap());
        assert_eq!(changed(&before, &after), Some(root.join(".git/hooks")));
        let _ = std::fs::remove_dir_all(&root);
    }
}
