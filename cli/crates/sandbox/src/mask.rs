//! Secret-file masking list (CONTRACT §15.4): the secret-shaped and git-ignored
//! files hidden from the agent inside `moochy run`. Exposed so `moochy doctor`
//! can show exactly what is masked.
//!
//! Fails closed: a worktree too large to scan completely, or with more secrets
//! than the mask budget, refuses the run instead of leaving the rest readable.

use std::collections::HashSet;
use std::io::Read as _;
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
/// Git configs are read whole up to this size; a larger (or unreadable) one is masked.
const CONFIG_MAX: u64 = 1 << 20;

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
    scan_with(worktree, &HashSet::new())
}

/// [`scan`], plus every entry whose inode an earlier run masked, from `record` (F09): masks
/// computed again each run follow the agent-writable `.gitignore`, and a rename moves a file
/// to a path nothing matches; the inode stays. Then `record` holds this run's masked inodes.
/// A record that cannot be written refuses the run (fail closed).
pub fn scan_kept(worktree: &Path, record: Option<&Path>) -> Result<Scan, Error> {
    use std::os::unix::fs::MetadataExt as _;
    let Some(record) = record else { return scan(worktree) };
    let kept: HashSet<u64> = std::fs::read_to_string(record).unwrap_or_default().lines().filter_map(|l| l.parse().ok()).collect();
    let s = scan_with(worktree, &kept)?;
    let text: Vec<String> = s.masks.iter().filter_map(|m| std::fs::symlink_metadata(m).ok()).map(|m| m.ino().to_string()).collect();
    let text = text.join("\n");
    let tmp = record.with_extension("tmp");
    record
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&tmp, text))
        .and_then(|()| std::fs::rename(&tmp, record))
        .map_err(|err| Error::Setup { what: "write the mask record", err })?;
    Ok(s)
}

fn scan_with(worktree: &Path, kept: &HashSet<u64>) -> Result<Scan, Error> {
    let mut s = walk_tree(worktree, true, kept)?;
    git_ignored(worktree, &mut s.masks)?;
    // F21: a git config holding a credential (token in a remote URL, CI extraheader) is masked
    // like any secret file; also one too large to check.
    for c in s.dotgits.iter().flat_map(|g| crate::git::config_files(g)) {
        let mut v = Vec::new();
        let big = std::fs::File::open(&c).and_then(|f| f.take(CONFIG_MAX + 1).read_to_end(&mut v)).map_or(true, |n| n as u64 > CONFIG_MAX);
        if big || crate::git::holds_credentials(&v) {
            s.masks.push(c);
        }
    }
    s.masks.sort();
    s.masks.dedup();
    Ok(s)
}

/// Only the `.git` entries (no masks, no `git`): for the post-run check.
pub fn dotgits(worktree: &Path) -> Result<Vec<PathBuf>, Error> {
    walk_tree(worktree, false, &HashSet::new()).map(|s| s.dotgits)
}

/// The directories strictly between `worktree` and `mask`, deepest first. Renaming one of them
/// moves the masked path; where a mask is a path rule (macOS Seatbelt), these must not be
/// renamed (F03). Empty for a mask outside the worktree.
pub fn ancestors_below<'a>(worktree: &'a Path, mask: &'a Path) -> impl Iterator<Item = &'a Path> {
    mask.ancestors().skip(1).take_while(move |a| a.starts_with(worktree) && *a != worktree)
}

fn too_big(what: &'static str) -> Error {
    Error::Setup { what, err: std::io::Error::other("worktree too large to scan for secrets (fail closed)") }
}

fn walk_tree(root: &Path, masks: bool, kept: &HashSet<u64>) -> Result<Scan, Error> {
    use std::os::unix::fs::DirEntryExt as _;
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
            if masks && (kept.contains(&entry.ino()) || matches_secret(root, &path)) {
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
/// off: the repo's config may already be hostile (A191). No repo: nothing to
/// add. A git that is missing or fails on a worktree that has its own repo:
/// refuse (fail closed, F22).
fn git_ignored(worktree: &Path, out: &mut Vec<PathBuf>) -> Result<(), Error> {
    ls_ignored("git", worktree, out)
}

fn ls_ignored(git: &str, worktree: &Path, out: &mut Vec<PathBuf>) -> Result<(), Error> {
    let output = std::process::Command::new(git)
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
    let output = match output {
        Ok(o) if o.status.success() => o,
        failed => {
            let dotgit = worktree.join(".git");
            if !(dotgit.is_file() || dotgit.join("HEAD").exists()) {
                return Ok(()); // not a repo (or an empty placeholder left by a killed run)
            }
            let err = match failed {
                Ok(o) => std::io::Error::other(format!("git exited with {}", o.status)),
                Err(e) => e, // no git binary
            };
            return Err(Error::Setup { what: "git ls-files (git-ignored masks)", err });
        }
    };
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
    #[test]
    fn ancestors_of_a_nested_mask() {
        let wt = Path::new("/w");
        let got: Vec<_> = ancestors_below(wt, Path::new("/w/apps/api/.env")).collect();
        assert_eq!(got, [Path::new("/w/apps/api"), Path::new("/w/apps")], "F03: every dir a rename could move it with");
        assert_eq!(ancestors_below(wt, Path::new("/w/.env")).count(), 0, "top level: only the worktree root, which stays");
        assert_eq!(ancestors_below(wt, Path::new("/elsewhere/config")).count(), 0);
    }

    #[test]
    fn git_config_with_a_token_is_masked() {
        let wt = std::env::temp_dir().join(format!("moochy-mask-gitcfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&wt);
        std::fs::create_dir_all(&wt).unwrap();
        let ok = std::process::Command::new("git").arg("-C").arg(&wt).args(["init", "-q"]).status().is_ok_and(|s| s.success());
        if !ok {
            return; // no git here: nothing to check
        }
        let cfg = wt.join(".git/config");
        assert!(!scan(&wt).unwrap().masks.contains(&cfg), "a plain config stays visible");
        let mut text = std::fs::read_to_string(&cfg).unwrap();
        text.push_str("[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX3g=\n");
        std::fs::write(&cfg, text).unwrap();
        assert!(scan(&wt).unwrap().masks.contains(&cfg), "F21: a config holding a CI token is masked");
        std::fs::remove_dir_all(&wt).unwrap();
    }

    #[test]
    fn a_masked_file_stays_masked_after_gitignore_edits_and_renames() {
        let root = std::env::temp_dir().join(format!("moochy-mask-kept-{}", std::process::id()));
        let (wt, record) = (root.join("wt"), root.join("state/masks/wt"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(wt.join("config")).unwrap();
        if !std::process::Command::new("git").arg("-C").arg(&wt).args(["init", "-q"]).status().is_ok_and(|s| s.success()) {
            return; // no git here: nothing to check
        }
        std::fs::write(wt.join(".gitignore"), "config/local_settings.py\n").unwrap();
        std::fs::write(wt.join("config/local_settings.py"), "SECRET = 1\n").unwrap();
        std::fs::write(wt.join("config/settings.py"), "DEBUG = 0\n").unwrap();
        let first = scan_kept(&wt, Some(&record)).unwrap();
        assert!(first.masks.contains(&wt.join("config/local_settings.py")));
        // Run 1's agent: ignore rule gone, directory renamed.
        std::fs::write(wt.join(".gitignore"), "").unwrap();
        std::fs::rename(wt.join("config"), wt.join("conf2")).unwrap();
        assert!(scan(&wt).unwrap().masks.is_empty(), "without a record the file is visible");
        let masks = scan_kept(&wt, Some(&record)).unwrap().masks;
        assert!(masks.contains(&wt.join("conf2/local_settings.py")), "F09: {masks:?}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn missing_git_refuses_a_repo() {
        let wt = std::env::temp_dir().join(format!("moochy-mask-nogit-{}", std::process::id()));
        std::fs::create_dir_all(wt.join(".git")).unwrap();
        let no_git = "/nonexistent/moochy-test/git";
        assert!(ls_ignored(no_git, &wt, &mut Vec::new()).is_ok(), "no repo: nothing to mask");
        std::fs::write(wt.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        assert!(matches!(ls_ignored(no_git, &wt, &mut Vec::new()), Err(Error::Setup { .. })), "F22: a repo without git refuses the run");
        std::fs::remove_dir_all(&wt).unwrap();
    }
}
