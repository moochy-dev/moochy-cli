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
//! - **`git_writable`**: `.git` writable except `hooks/`, `config`, `modules/`.
//!   Residual: `commondir` (see DESIGN.md).
//! - **linked worktree** (`.git` is a file): always read-only — the shared
//!   commondir and this worktree's own gitdir are visible, other worktrees'
//!   gitdirs are hidden, and the main worktree's files never enter the view.

use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Git paths of one worktree, resolved on the host (canonical).
#[derive(Debug, Default)]
pub struct GitView {
    /// Paths (dirs or files) to make read-only inside.
    pub read_only: Vec<PathBuf>,
    /// Set for a linked worktree / submodule checkout.
    pub linked: Option<Linked>,
}

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

/// Resolve the git view of `worktree` (canonical). Missing or malformed git
/// metadata yields an empty view (the worktree simply has no usable git).
pub fn view(worktree: &Path, git_writable: bool) -> GitView {
    let dotgit = worktree.join(".git");
    let Ok(meta) = std::fs::symlink_metadata(&dotgit) else { return GitView::default() };
    if meta.is_dir() {
        let read_only = if git_writable {
            let hooks = dotgit.join("hooks");
            let _ = std::fs::create_dir(&hooks); // as git itself would; then read-only
            [hooks, dotgit.join("config"), dotgit.join("modules")]
                .into_iter()
                .filter(|p| p.exists())
                .collect()
        } else {
            vec![dotgit]
        };
        return GitView { read_only, linked: None };
    }
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
        return GitView { read_only: vec![dotgit], linked: None };
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
        let v = view(&root.join("wt").canonicalize().unwrap(), false);
        assert!(v.linked.is_none(), "{v:?}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
