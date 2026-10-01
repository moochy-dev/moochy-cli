//! Secret-file masking list (CONTRACT §15.4): the secret-shaped and git-ignored
//! files hidden from the agent inside `moochy run`. Exposed so `moochy doctor`
//! can show exactly what is masked.

use std::path::{Path, PathBuf};

use crate::Error;

/// Secret-shaped name patterns hidden anywhere in the worktree. Matched against
/// each file/dir's base name (globs: `*` only). Kept in sync with CONTRACT §15.4
/// and node/src/scrub.rs's intent.
pub const SECRET_PATTERNS: &[&str] = &[
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_*",
    ".npmrc",
    ".netrc",
    ".pypirc",
    "credentials",
    "credentials.*",
    "credentials*",
    // Cloud CLI config directories.
    ".aws",
    ".gcloud",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".ssh",
    ".docker",
];

/// Bound on how many entries we walk/mask, so a hostile worktree cannot make
/// setup unbounded.
const WALK_LIMIT: usize = 50_000;
const MASK_LIMIT: usize = 4_096;

/// Collect absolute paths under `worktree` to overmount: secret-shaped names
/// (any depth) plus git-ignored files (best-effort via `git`, run here in the
/// parent before the sandbox exists).
pub fn collect(worktree: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    walk(worktree, &mut out, &mut seen)?;
    git_ignored(worktree, &mut out);
    out.sort();
    out.dedup();
    out.truncate(MASK_LIMIT);
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, seen: &mut usize) -> Result<(), Error> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()), // unreadable dir: skip, not fatal
    };
    for entry in rd.flatten() {
        if *seen >= WALK_LIMIT || out.len() >= MASK_LIMIT {
            return Ok(());
        }
        *seen = seen.saturating_add(1);
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" {
            continue;
        }
        let path = entry.path();
        if matches_secret(&name) {
            out.push(path.clone());
            continue; // whole subtree masked; no need to descend
        }
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            walk(&path, out, seen)?;
        }
    }
    Ok(())
}

/// Case-sensitive glob match supporting a single leading/trailing `*`.
fn matches_secret(name: &str) -> bool {
    SECRET_PATTERNS.iter().any(|pat| glob1(pat, name))
}

fn glob1(pat: &str, name: &str) -> bool {
    match (pat.strip_prefix('*'), pat.strip_suffix('*')) {
        (Some(suf), _) if !pat.ends_with('*') => name.ends_with(suf),
        (_, Some(pre)) if !pat.starts_with('*') => name.starts_with(pre),
        _ if pat.contains('*') => {
            // pattern like "a*b": split on the single star.
            if let Some((a, b)) = pat.split_once('*') {
                name.len() >= a.len().saturating_add(b.len())
                    && name.starts_with(a)
                    && name.ends_with(b)
            } else {
                pat == name
            }
        }
        _ => pat == name,
    }
}

/// Best-effort git-ignored files. Runs `git` in the parent (the sandbox does not
/// exist yet). Silently does nothing if git or the repo is absent.
fn git_ignored(worktree: &Path, out: &mut Vec<PathBuf>) {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["ls-files", "--others", "--ignored", "--exclude-standard", "-z"])
        .output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return;
    }
    for rel in output.stdout.split(|&b| b == 0) {
        if rel.is_empty() || out.len() >= MASK_LIMIT {
            continue;
        }
        use std::os::unix::ffi::OsStrExt as _;
        let p = worktree.join(std::ffi::OsStr::from_bytes(rel));
        out.push(p);
    }
}
