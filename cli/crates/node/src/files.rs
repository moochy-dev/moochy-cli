//! `moochy_delegate` `files` (06 §13, T15, CONTRACT §15.2).
//!
//! The background process never reads repository files nor spawns `git`: paths are read by the
//! client side — the stdio shim (`moochy mcp`, inside the agent's own sandbox) with [`read`] —
//! and reach the node as `file_contents`, which [`inline`] checks again by name. Streamable HTTP
//! clients send `file_contents` themselves.
//!
//! [`read`] rules: allowed root = git top-level (recorded for the token, or the shim's cwd) ∩ the client's MCP
//! roots (when it sent any). Each path: no `..`, no symlink anywhere below the root, realpath
//! containment, regular file only, `.git/**` and secret-shaped names denied even when tracked,
//! git-ignored files refused, UTF-8 text only, total ≤ 2 MiB, secret scrubber applied.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

pub const MAX_TOTAL: u64 = 2 << 20;
pub const MAX_FILES: usize = 200;

/// Workspace scope for one MCP session.
#[derive(Clone, Debug, Default)]
pub struct Scope {
    /// Canonical git top-level.
    pub root: Option<PathBuf>,
    /// Canonical client roots; `None` = the client sent none (then the root alone applies).
    pub client_roots: Option<Vec<PathBuf>>,
}

pub struct FileText {
    pub rel: String,
    pub text: String,
}

fn denied_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with(".env")
        || matches!(n.as_str(), ".npmrc" | ".netrc" | ".pypirc" | ".git-credentials" | ".pgpass" | "credentials" | ".htpasswd")
        || n.starts_with("id_")
        || [".pem", ".key", ".kdbx", ".p12", ".pfx", ".keystore", ".jks"].iter().any(|s| n.ends_with(s))
}

/// Percent-decode a `file://` URI into a path.
pub fn file_uri(uri: &str) -> Option<PathBuf> {
    let p = uri.strip_prefix("file://")?;
    let p = p.strip_prefix("localhost").unwrap_or(p);
    let b = p.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let h = std::str::from_utf8(b.get(i.saturating_add(1)..i.saturating_add(3))?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i = i.saturating_add(3);
        } else {
            out.push(c);
            i = i.saturating_add(1);
        }
    }
    let s = String::from_utf8(out).ok()?;
    s.starts_with('/').then(|| PathBuf::from(s))
}

/// Name rules for an inline file: relative, plain components, no `.git`, no secret-shaped name.
fn check_inline_path(p: &str) -> Result<(), String> {
    if p.is_empty() || p.len() > 4096 || p.contains('\0') || p.starts_with('/') {
        return Err("invalid path (relative to the repository root)".into());
    }
    // Split by hand: `Path::components` silently drops interior `.` and empty segments.
    for name in p.split('/') {
        if matches!(name, "" | "." | "..") || name.contains('\\') {
            return Err("`..`/`.`/empty components are not allowed".into());
        }
        if name == ".git" {
            return Err(".git is never readable".into());
        }
        if denied_name(name) {
            return Err("secret-shaped file name".into());
        }
    }
    Ok(())
}

/// `file_contents` = `[{"path", "text"}]`: names checked, ≤ [`MAX_FILES`], ≤ 2 MiB, scrubbed.
/// All or nothing (fail closed).
pub fn inline(items: &[serde_json::Value]) -> Result<Vec<FileText>, String> {
    if items.len() > MAX_FILES {
        return Err(format!("at most {MAX_FILES} files per call"));
    }
    let mut total: u64 = 0;
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let (Some(path), Some(text)) = (it.get("path").and_then(serde_json::Value::as_str), it.get("text").and_then(serde_json::Value::as_str)) else {
            return Err("`file_contents` items are {\"path\", \"text\"}".into());
        };
        check_inline_path(path).map_err(|e| format!("{path}: {e}"))?;
        total = total.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX));
        if total > MAX_TOTAL {
            return Err(format!("files exceed the {} MiB total cap", MAX_TOTAL >> 20));
        }
        let text = crate::scrub::scrub(text.as_bytes()).and_then(|b| String::from_utf8(b).ok()).unwrap_or_else(|| text.to_owned());
        out.push(FileText { rel: path.to_owned(), text });
    }
    Ok(out)
}

/// Git top-level of `dir` (canonical), if `dir` is inside a work tree.
pub fn git_root(dir: &Path) -> Option<PathBuf> {
    let out = crate::util::command("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    std::fs::canonicalize(s.trim_end_matches('\n')).ok()
}

/// Relative paths (to `root`) that git ignores.
fn git_ignored(root: &Path, rels: &[String]) -> Result<Vec<String>, String> {
    use std::io::Write as _;
    let mut child = crate::util::command("git")
        .arg("-C")
        .arg(root)
        .args(["check-ignore", "-z", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("git: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        for r in rels {
            si.write_all(r.as_bytes()).map_err(|e| format!("git: {e}"))?;
            si.write_all(&[0]).map_err(|e| format!("git: {e}"))?;
        }
    }
    let out = child.wait_with_output().map_err(|e| format!("git: {e}"))?;
    // Exit 0 = some ignored, 1 = none ignored, anything else = error (fail closed).
    match out.status.code() {
        Some(0 | 1) => Ok(out.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect()),
        _ => Err("git check-ignore failed".into()),
    }
}

/// Resolve and check one path; returns (canonical path, path relative to root).
fn check(scope_root: &Path, client_roots: Option<&[PathBuf]>, p: &str) -> Result<(PathBuf, String), String> {
    if p.is_empty() || p.len() > 4096 || p.contains('\0') {
        return Err("invalid path".into());
    }
    let given = Path::new(p);
    let joined = if given.is_absolute() { given.to_path_buf() } else { scope_root.join(given) };
    let rel = joined.strip_prefix(scope_root).map_err(|_| "outside the workspace root".to_owned())?;
    let mut cur = scope_root.to_path_buf();
    for c in rel.components() {
        let Component::Normal(name) = c else { return Err("`..`/`.` components are not allowed".into()) };
        let name_s = name.to_str().ok_or("non-UTF-8 path")?;
        if name_s == ".git" {
            return Err(".git is never readable".into());
        }
        if denied_name(name_s) {
            return Err("secret-shaped file name".into());
        }
        cur.push(name);
        let md = std::fs::symlink_metadata(&cur).map_err(|_| "not found".to_owned())?;
        if md.file_type().is_symlink() {
            return Err("symlinks are refused".into());
        }
    }
    let real = std::fs::canonicalize(&cur).map_err(|_| "not found".to_owned())?;
    if !real.starts_with(scope_root) {
        return Err("outside the workspace root".into());
    }
    if client_roots.is_some_and(|rs| !rs.iter().any(|r| real.starts_with(r))) {
        return Err("outside the client's MCP roots".into());
    }
    let rel = real.strip_prefix(scope_root).map_err(|_| "outside the workspace root".to_owned())?;
    Ok((real.clone(), rel.to_str().ok_or("non-UTF-8 path")?.to_owned()))
}

/// Open `rel` (plain components, already checked) beneath `root`: every component with
/// `O_NOFOLLOW` relative to the previous directory fd, the last one `O_NONBLOCK`; the opened fd
/// must be a regular file.
fn open_beneath(root: &Path, rel: &str) -> Result<std::fs::File, String> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = open(root, dir_flags, Mode::empty()).map_err(|_| "cannot open the workspace root".to_owned())?;
    let mut parts = rel.split('/').peekable();
    while let Some(name) = parts.next() {
        if matches!(name, "" | "." | "..") {
            return Err("invalid path".into());
        }
        if parts.peek().is_some() {
            dir = openat(&dir, name, dir_flags, Mode::empty()).map_err(|_| "a path component changed or is a symlink".to_owned())?;
            continue;
        }
        let fd = openat(&dir, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|_| "cannot open (symlink or changed)".to_owned())?;
        let st = fstat(&fd).map_err(|_| "cannot stat".to_owned())?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err("not a regular file".into());
        }
        return Ok(std::fs::File::from(fd));
    }
    Err("invalid path".into())
}

/// Read all requested files or refuse the whole call with the first reason (fail closed).
pub fn read(scope: &Scope, paths: &[String]) -> Result<Vec<FileText>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    if paths.len() > MAX_FILES {
        return Err(format!("at most {MAX_FILES} files per call"));
    }
    let root = scope.root.as_deref().ok_or("no workspace root: run `moochy env --repo owner/name` (or `moochy mcp`) inside the repository")?;
    let mut checked = Vec::with_capacity(paths.len());
    for p in paths {
        checked.push(check(root, scope.client_roots.as_deref(), p).map_err(|e| format!("{p}: {e}"))?);
    }
    let rels: Vec<String> = checked.iter().map(|(_, r)| r.clone()).collect();
    if let Some(ig) = git_ignored(root, &rels)?.first() {
        return Err(format!("{ig}: git-ignored files are refused"));
    }
    let mut total: u64 = 0;
    let mut out = Vec::with_capacity(checked.len());
    for (_real, rel) in checked {
        // Read from an fd opened beneath the root with no symlink anywhere (A171: a component
        // swapped after `check` cannot redirect the read), non-blocking (A172: a FIFO cannot
        // hang the shim), and fstat-checked as a regular file.
        let f = open_beneath(root, &rel).map_err(|e| format!("{rel}: {e}"))?;
        let left = MAX_TOTAL.saturating_sub(total);
        let mut buf = Vec::new();
        f.take(left.saturating_add(1)).read_to_end(&mut buf).map_err(|_| format!("{rel}: read error"))?;
        total = total.saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
        if total > MAX_TOTAL {
            return Err(format!("files exceed the {} MiB total cap", MAX_TOTAL >> 20));
        }
        let buf = crate::scrub::scrub(&buf).unwrap_or(buf);
        let text = String::from_utf8(buf).map_err(|_| format!("{rel}: not UTF-8 text"))?;
        out.push(FileText { rel, text });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn file_uris() {
        assert_eq!(file_uri("file:///home/a%20b/x"), Some(PathBuf::from("/home/a b/x")));
        assert_eq!(file_uri("file://localhost/x"), Some(PathBuf::from("/x")));
        assert_eq!(file_uri("https://x"), None);
        assert_eq!(file_uri("file://%zz"), None);
    }

    #[test]
    fn rules() {
        let base = std::env::temp_dir().join(format!("moochy-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("repo/src")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        let repo = base.join("repo");
        assert!(Command::new("git").arg("-C").arg(&repo).args(["init", "-q"]).status().unwrap().success());
        std::fs::write(repo.join("src/a.rs"), "fn a() {} // key AKIAABCDEFGHIJKLMNOP").unwrap();
        std::fs::write(repo.join(".env"), "X=1").unwrap();
        std::fs::write(repo.join(".gitignore"), "build/\n").unwrap();
        std::fs::create_dir_all(repo.join("build")).unwrap();
        std::fs::write(repo.join("build/out.txt"), "x").unwrap();
        std::fs::write(base.join("outside/s.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(base.join("outside/s.txt"), repo.join("src/link")).unwrap();
        let root = git_root(&repo.join("src")).unwrap();
        let scope = Scope { root: Some(root.clone()), client_roots: None };

        let ok = read(&scope, &["src/a.rs".into()]).unwrap();
        assert_eq!(ok[0].rel, "src/a.rs");
        assert!(ok[0].text.contains("[REDACTED:aws_key]"));
        let abs = root.join("src/a.rs").to_string_lossy().into_owned();
        assert!(read(&scope, &[abs]).is_ok());
        for bad in ["../outside/s.txt", "src/link", ".env", ".git/config", "build/out.txt", "src/../src/a.rs", "/etc/passwd", "src"] {
            assert!(read(&scope, &[bad.to_owned()]).is_err(), "{bad} must be refused");
        }
        let narrow = Scope { root: Some(root.clone()), client_roots: Some(vec![root.join("build")]) };
        let empty = Scope { root: Some(root.clone()), client_roots: Some(vec![]) };
        assert!(read(&empty, &["src/a.rs".into()]).is_err(), "empty roots allow nothing");
        assert!(read(&narrow, &["src/a.rs".into()]).is_err(), "outside client roots");
        assert!(read(&Scope::default(), &["src/a.rs".into()]).is_err(), "no root");
        let inl = |p: &str| inline(&[serde_json::json!({"path": p, "text": "k AKIAABCDEFGHIJKLMNOP"})]);
        assert!(inl("src/a.rs").unwrap()[0].text.contains("[REDACTED:aws_key]"));
        for bad in [".env", "src/.git/config", "../x", "/etc/passwd", "a/./b", "id_rsa", ""] {
            assert!(inl(bad).is_err(), "inline {bad} must be refused");
        }
        assert!(inline(&[serde_json::json!({"path": "a", "text": "x".repeat(3 << 20)})]).is_err(), "size cap");
        let _ = std::fs::remove_dir_all(&base);
    }
}
