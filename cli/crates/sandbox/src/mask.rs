//! Secret-file masking list (CONTRACT §15.4): the secret-shaped and git-ignored
//! files hidden from the agent inside `moochy run`. Exposed so `moochy doctor`
//! can show exactly what is masked.
//!
//! Fails closed: a worktree too large to scan completely, or with more secrets
//! than the mask budget, refuses the run instead of leaving the rest readable.

use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use crate::Error;

/// Secret-shaped name patterns hidden anywhere in the worktree, matched
/// case-insensitively against each entry's base name (`*` globs).
/// A pattern with a `/` matches the trailing components of the path instead
/// (`.config/gcloud`). Kept in sync with CONTRACT §15.4 and node/src/scrub.rs.
pub const SECRET_PATTERNS: &[&str] = &[
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".npmrc",
    ".netrc",
    ".pypirc",
    ".pgpass",
    ".git-credentials",
    ".vault-token",
    "*.tfstate",
    "*.tfstate.*",
    "service-account*.json",
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

/// Git-ignored directories that are dependency or build trees, not secrets:
/// left visible (tools need them). Secret-shaped names inside them are still
/// masked by the walk. Every other git-ignored file or directory is masked.
const BUILD_DIRS: &[&str] = &[
    "node_modules", "target", "build", "dist", "out", ".venv", "venv", "__pycache__", ".gradle",
    "vendor", ".next", ".nuxt", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage",
    "bin", "obj", ".build", "zig-out", ".zig-cache", "_build", "deps",
];

/// Bounds so a hostile worktree cannot make setup unbounded; exceeding either
/// refuses the run (fail closed).
// ponytail: one full readdir walk per run (~1 s per million entries); a cache
// keyed on dir mtimes if huge monorepos make that felt.
const WALK_LIMIT: usize = 1_000_000;
const MASK_LIMIT: usize = 16_384;

/// What one scan of the worktree found.
#[derive(Debug, Default)]
pub struct Scan {
    /// Absolute paths to overmount (secret-shaped + git-ignored).
    pub masks: Vec<PathBuf>,
    /// Every `.git` entry (dir or file) at any depth, the top-level one included.
    pub dotgits: Vec<PathBuf>,
}

/// Collect absolute paths under `worktree` to overmount: secret-shaped names
/// (any depth) plus git-ignored files (via `git`, run here in the parent
/// before the sandbox exists).
pub fn collect(worktree: &Path) -> Result<Vec<PathBuf>, Error> {
    scan(worktree).map(|s| s.masks)
}

/// [`collect`] plus every `.git` in the tree.
pub fn scan(worktree: &Path) -> Result<Scan, Error> {
    let mut s = walk_tree(worktree, true)?;
    git_ignored(worktree, &mut s.masks)?;
    s.masks.sort();
    s.masks.dedup();
    Ok(s)
}

/// Only the `.git` entries (no masks, no `git`): for the post-run check.
pub fn dotgits(worktree: &Path) -> Result<Vec<PathBuf>, Error> {
    walk_tree(worktree, false).map(|s| s.dotgits)
}

fn too_big(what: &'static str) -> Error {
    Error::Setup { what, err: std::io::Error::other("worktree too large to scan for secrets (fail closed)") }
}

fn walk_tree(root: &Path, masks: bool) -> Result<Scan, Error> {
    let mut s = Scan::default();
    let mut seen = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue }; // unreadable: also unreadable inside
        for entry in rd.flatten() {
            seen = seen.saturating_add(1);
            if seen > WALK_LIMIT {
                return Err(too_big("mask walk limit"));
            }
            let name = entry.file_name();
            let path = entry.path();
            if name.as_bytes().eq_ignore_ascii_case(b".git") {
                s.dotgits.push(path);
                continue; // its contents are handled by git::view
            }
            if masks && matches_secret(root, &path) {
                if s.masks.len() >= MASK_LIMIT {
                    return Err(too_big("mask limit"));
                }
                s.masks.push(path);
                continue; // whole subtree masked; no need to descend
            }
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(path);
            }
        }
    }
    Ok(s)
}

/// Does this entry match a secret pattern (case-insensitive)?
pub fn matches_secret(root: &Path, path: &Path) -> bool {
    let Some(name) = path.file_name() else { return false };
    let name = name.to_string_lossy().to_ascii_lowercase();
    SECRET_PATTERNS.iter().any(|pat| {
        if pat.contains('/') {
            path.strip_prefix(root).is_ok_and(|rel| lower(rel).ends_with(Path::new(pat)))
        } else {
            glob1(pat, &name)
        }
    })
}

fn lower(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_ascii_lowercase())
}

/// `*`-only glob (any number of stars), byte-wise; the classic linear
/// backtrack-to-last-star match.
pub(crate) fn glob1(pat: &str, name: &str) -> bool {
    let (p, n) = (pat.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None; // (star index in p, n index it covers up to)
    while ni < n.len() {
        match p.get(pi) {
            Some(b'*') => {
                star = Some((pi, ni));
                pi = pi.saturating_add(1);
            }
            Some(c) if n.get(ni) == Some(c) => {
                pi = pi.saturating_add(1);
                ni = ni.saturating_add(1);
            }
            _ => match star {
                Some((sp, sn)) => {
                    pi = sp.saturating_add(1);
                    ni = sn.saturating_add(1);
                    star = Some((sp, ni));
                }
                None => return false,
            },
        }
    }
    p.get(pi..).unwrap_or(&[]).iter().all(|c| *c == b'*')
}

/// Git-ignored entries. Runs `git` in the parent (the sandbox does not exist
/// yet) with every config knob that could make it execute something forced
/// off: the repo's config may already be hostile (A191). No git or no repo:
/// nothing to add. A git that fails on a worktree that has its own repo:
/// refuse (fail closed).
fn git_ignored(worktree: &Path, out: &mut Vec<PathBuf>) -> Result<(), Error> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false"])
        .args(["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    let Ok(output) = output else { return Ok(()) }; // no git binary
    if !output.status.success() {
        let dotgit = worktree.join(".git");
        if !(dotgit.is_file() || dotgit.join("HEAD").exists()) {
            return Ok(()); // not a repo (or an empty placeholder left by a killed run)
        }
        return Err(Error::Setup {
            what: "git ls-files (git-ignored masks)",
            err: std::io::Error::other(format!("git exited with {}", output.status)),
        });
    }
    for rel in output.stdout.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let (rel, is_dir) = match rel.strip_suffix(b"/") {
            Some(r) => (r, true),
            None => (rel, false),
        };
        let p = worktree.join(std::ffi::OsStr::from_bytes(rel));
        if is_dir && p.file_name().is_some_and(|n| BUILD_DIRS.iter().any(|b| n.as_bytes() == b.as_bytes())) {
            continue;
        }
        if out.len() >= MASK_LIMIT {
            return Err(too_big("mask limit"));
        }
        out.push(p);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_names_case_insensitive_and_path_patterns() {
        let r = Path::new("/w");
        for hit in [".env", ".ENV", ".env.local", "Server.PEM", "a.p12", "id_ed25519", "id_rsa.pub", ".git-credentials",
                    "prod.tfstate", "x.tfstate.backup", "service-account-prod.json", "credentials", "Credentials.json", ".pgpass"] {
            assert!(matches_secret(r, &r.join("sub").join(hit)), "{hit} not masked");
        }
        assert!(matches_secret(r, Path::new("/w/.config/gcloud")));
        assert!(matches_secret(r, Path::new("/w/a/.CONFIG/gcloud")));
        for miss in ["README.md", "id_generator.rs", "main.rs", "gcloud", "keys.rs", "pem"] {
            assert!(!matches_secret(r, &r.join(miss)), "{miss} masked");
        }
    }
}
