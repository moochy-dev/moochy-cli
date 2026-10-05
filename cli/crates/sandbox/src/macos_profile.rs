//! The Seatbelt (SBPL) profiles of the macOS side, as pure string builders: compiled on macOS,
//! and under `cfg(test)` everywhere so their rules are unit-tested on Linux too.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::{DonorPolicy, Error, Spec, mask};

/// Seatbelt matches resolved paths (`/var` is `/private/var`, `/tmp` is
/// `/private/tmp`): every path in a profile goes through here first.
fn real(p: &Path) -> String {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf()).to_string_lossy().into_owned()
}

/// Every sysctl but the process table (G08): `kern.proc*` (`kern.proc.*`, `kern.procargs2`) hands
/// out other same-user processes' argv and environment. The deny comes last, so it wins.
const SYSCTL: &str = "(allow sysctl-read)\n(deny sysctl-read (sysctl-name-prefix \"kern.proc\"))\n";

/// Setuid/setgid helpers (G38). macOS has no `no_new_privs`: a cached sudo ticket or a NOPASSWD
/// rule would run code as root inside the profile, and `write`/`wall` reach other terminals.
const SETUID_DENY: &str = "(deny process-exec* (literal \"/usr/bin/sudo\") (literal \"/usr/bin/su\") (literal \"/usr/bin/login\") \
    (literal \"/usr/bin/newgrp\") (literal \"/usr/bin/crontab\") (literal \"/usr/bin/at\") (literal \"/usr/bin/atq\") (literal \"/usr/bin/atrm\") \
    (literal \"/usr/bin/batch\") (literal \"/usr/bin/write\") (literal \"/usr/bin/wall\") (literal \"/usr/libexec/authopen\") \
    (literal \"/usr/libexec/security_authtrampoline\"))\n";

/// `name` as a case-insensitive SBPL regex: APFS is case-insensitive by default, and a created
/// name reaches the profile in the caller's spelling (G09).
fn ci(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '.' => "\\.".to_owned(),
            c if c.is_ascii_alphabetic() => format!("[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase()),
            c => c.to_string(),
        })
        .collect()
}

/// Deny-by-default maintainer profile: read system paths, read-write the worktree + scratch,
/// deny the masked secret files explicitly, network only to the gateway loopback port, no exec
/// of the setuid helpers in [`SETUID_DENY`] (exec of other system binaries is allowed: tools run,
/// and children keep this profile), no mach services. `ttys`: the run's own terminal(s), the
/// only ones it may use (G23).
pub fn maintainer_profile(
    spec: &Spec,
    worktree: &Path,
    masks: &[PathBuf],
    scratch: &Path,
    proxy_port: Option<u16>,
    ttys: &[PathBuf],
) -> Result<String, Error> {
    let wt = sbpl_quote(&worktree.to_string_lossy());
    let wt_re = regex_escape(&worktree.to_string_lossy())
        .ok_or(Error::Unsupported("worktree path has characters the macOS profile cannot express"))?;
    let mut p = String::new();
    // Rules are matched last-wins: `deny default` first, allows after, the
    // secret masks last so they beat the worktree allow.
    p.push_str("(version 1)\n(deny default)\n");
    // Diagnostics off; we never want the sandbox to prompt.
    p.push_str("(deny file-write* file-read* (with no-report))\n");
    // An agent runs tools: it may fork and exec, and signal its own processes only.
    p.push_str("(allow process-fork)\n");
    p.push_str("(allow signal (target same-sandbox))\n");
    p.push_str(SYSCTL);
    p.push_str("(allow file-read-metadata)\n");
    // System paths (and dyld): read + exec.
    p.push_str("(allow process-exec* file-read* (regex #\"^/(usr|bin|sbin|opt|System|Library|Applications)/\"))\n");
    // F23: not the package managers' own data and config (Homebrew, MacPorts): user-owned
    // local databases and service configs live there. Their CA bundles stay readable.
    p.push_str(HOMEBREW_DATA_DENY);
    p.push_str("(allow file-read* (regex #\"^/(private/etc|private/var/db|etc)/\") (literal \"/\") (literal \"/private\"))\n");
    // Basic devices and the run's own terminal (interactive agents), not every pty of the user.
    p.push_str("(allow file-read* file-write* file-ioctl (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/tty\") (literal \"/dev/dtracehelper\")");
    for t in ttys {
        let _ = write!(p, " (literal {})", sbpl_quote(&t.to_string_lossy()));
    }
    p.push_str(")\n");
    p.push_str("(allow file-read* (literal \"/dev/random\") (literal \"/dev/urandom\"))\n");
    // getpwuid() etc.; every other mach service (keychain, pasteboard, launchd
    // services, Apple Events) stays denied.
    p.push_str("(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n");
    // Tool directories the caller allows (read + exec), worktree read-write, scratch.
    for ro in &spec.ro_paths {
        let _ = writeln!(p, "(allow process-exec* file-read* (subpath {}))", sbpl_quote(&real(ro)));
    }
    let _ = writeln!(p, "(allow process-exec* file-read* file-write* (subpath {wt}))");
    let _ = writeln!(p, "(allow file-read* file-write* (subpath {}))", sbpl_quote(&real(scratch)));
    for p2 in &spec.rw_paths {
        let _ = writeln!(p, "(allow file-read* file-write* (subpath {}))", sbpl_quote(&real(p2)));
    }
    // Network: the gateway only (loopback port and/or its Unix socket).
    for port in spec.gateway_loopback_port.into_iter().chain(proxy_port) {
        let _ = writeln!(p, "(allow network-outbound (remote ip \"localhost:{port}\"))");
    }
    if let Some(sock) = &spec.gateway_socket {
        let q = sbpl_quote(&real(sock));
        let _ = writeln!(p, "(allow network-outbound (remote unix-socket (path-literal {q})))");
        let _ = writeln!(p, "(allow file-read* file-write* (literal {q}))");
        // G33: connect only; never unlink, replace or re-own the node's door.
        let _ = writeln!(p, "(deny file-write-unlink file-write-create file-write-mode file-write-owner file-write-flags (literal {q}))");
    }
    p.push_str(SETUID_DENY);
    // Mask secret-shaped / git-ignored files last: they beat every allow above. A deny is a
    // path, fixed at start: renaming a directory above a mask would move the secret out from
    // under it (F03), so no directory between the worktree and a mask may be renamed or removed.
    let mut ancestors = std::collections::BTreeSet::new();
    for m in masks {
        let _ = writeln!(p, "(deny file-read* file-write* process-exec* (subpath {}))", sbpl_quote(&m.to_string_lossy()));
        ancestors.extend(mask::ancestors_below(worktree, m));
    }
    for a in ancestors {
        let _ = writeln!(p, "(deny file-write-unlink (literal {}))", sbpl_quote(&a.to_string_lossy()));
    }
    // Git metadata the host's git later trusts (A191): no write to any `.git`
    // at any depth — which also blocks creating one (`git init`, a nested repo).
    // `git_writable` reopens the top-level one except the paths that make the
    // host run code or redirect, in any letter case (G09), and any top-level name with a
    // character outside printable ASCII, which APFS may fold onto one of them (`hoo\u{212a}s`).
    let git_re = ci(".git");
    if spec.git_writable {
        let trusted: Vec<String> = crate::git::GIT_TRUSTED.iter().map(|n| ci(n)).collect();
        let _ = writeln!(p, "(deny file-write* (regex #\"^{wt_re}/.+/{git_re}(/|$)\"))");
        let _ = writeln!(p, "(deny file-write* (regex #\"^{wt_re}/{git_re}/({})(/|$)\"))", trusted.join("|"));
        let _ = writeln!(p, "(deny file-write* (regex #\"^{wt_re}/{git_re}/[^/]*[^ -~]\"))");
    } else {
        let _ = writeln!(p, "(deny file-write* (regex #\"^{wt_re}/(.+/)?{git_re}(/|$)\"))");
    }
    Ok(p)
}

const HOMEBREW_DATA_DENY: &str = "(deny file-read* file-write* process-exec* (regex #\"^/(opt/homebrew|opt/local|usr/local)/(var|etc)(/|$)\"))\n\
    (allow file-read* (regex #\"^/(opt/homebrew|opt/local|usr/local)/etc/(openssl[^/]*|ca-certificates)/\"))\n\
    (deny file-read* (regex #\"^/(opt/homebrew|opt/local|usr/local)/etc/openssl[^/]*/private(/|$)\"))\n";

/// A path as a literal inside an SBPL `#"…"` regex; `None` for characters we
/// can't express safely there (quote, backslash, control).
fn regex_escape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len().saturating_mul(2));
    for c in s.chars() {
        if c == '"' || c == '\\' || c.is_control() {
            return None;
        }
        if ".^$*+?()[]{}|".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    Some(out)
}

/// Donor self-lockdown profile (§15.2a): deny process-exec/process-fork, limit
/// files to the state dir (rw) + CA roots (ro), network outbound to 443 + relay
/// (+ loopback gateway bind).
pub fn donor_profile(policy: &DonorPolicy) -> String {
    let state = sbpl_quote(&real(&policy.state_dir));
    let mut p = String::new();
    p.push_str("(version 1)\n(deny default)\n");
    p.push_str("(deny process-exec*)\n(deny process-fork)\n");
    let _ = writeln!(p, "(allow file-read* file-write* (subpath {state}))");
    for ro in &policy.ro_paths {
        let _ = writeln!(p, "(allow file-read* (subpath {}))", sbpl_quote(&real(ro)));
    }
    p.push_str("(allow file-read* (regex #\"^/(usr/lib|System/Library)/\"))\n");
    // Name resolution for provider hosts: getaddrinfo goes through libinfo and
    // mDNSResponder (mach service + its Unix socket) and reads /etc/hosts.
    p.push_str("(allow mach-lookup (global-name \"com.apple.dnssd.service\") (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n");
    p.push_str("(allow network-outbound (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))\n");
    p.push_str("(allow file-read-metadata)\n");
    p.push_str("(allow file-read* (literal \"/private/etc/hosts\") (literal \"/private/etc/resolv.conf\") (literal \"/private/var/run/resolv.conf\") (literal \"/Library/Preferences/com.apple.networkd.plist\"))\n");
    p.push_str(SYSCTL);
    let _ = writeln!(p, 
        "(allow network-outbound (remote tcp \"*:443\") (remote tcp \"*:{}\"))",
        policy.relay_port
    );
    // Dev/e2e only: fake providers on loopback ports (empty in production).
    for port in &policy.connect_ports {
        let _ = writeln!(p, "(allow network-outbound (remote tcp \"*:{port}\"))");
    }
    if let Some(gw) = policy.gateway_port {
        let _ = writeln!(p, 
            "(allow network-inbound (local tcp \"localhost:{gw}\"))"
        );
    }
    p
}

/// SBPL string literal with escaping of `"` and `\`.
fn sbpl_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    #[test]
    fn package_manager_data_is_not_a_system_path() {
        let wt = std::env::temp_dir();
        let p = super::maintainer_profile(&crate::Spec::new(wt.clone()), &wt, &[], &wt, None, &[]).unwrap();
        let (sys, deny) = (p.find("(usr|bin|sbin|opt|").unwrap(), p.find(super::HOMEBREW_DATA_DENY).unwrap());
        assert!(deny > sys, "F23: the deny follows (beats) the system-path allow");
        let private = p.find("openssl[^/]*/private(/|$)").unwrap();
        assert!(private > p.find("ca-certificates)/").unwrap(), "G40: the CA re-allow does not reopen openssl's private/");
    }

    fn profile(git_writable: bool, ttys: &[&str]) -> String {
        let wt = std::path::PathBuf::from("/w");
        let mut spec = crate::Spec::new(wt.clone());
        spec.git_writable = git_writable;
        spec.gateway_socket = Some("/s/gateway.sock".into());
        let ttys: Vec<std::path::PathBuf> = ttys.iter().map(Into::into).collect();
        super::maintainer_profile(&spec, &wt, &[], &wt, None, &ttys).unwrap()
    }

    /// The last rule naming `needle` (Seatbelt: last match wins).
    fn last(p: &str, needle: &str) -> usize {
        p.rfind(needle).unwrap_or_else(|| panic!("{needle} missing:\n{p}"))
    }

    #[test]
    fn g08_no_process_table_sysctls() {
        for p in [profile(false, &[]), super::donor_profile(&crate::DonorPolicy::new("/s".into(), 8443))] {
            assert!(last(&p, "(deny sysctl-read (sysctl-name-prefix \"kern.proc\"))") > last(&p, "(allow sysctl-read)"), "{p}");
        }
    }

    #[test]
    fn g09_git_writable_trusted_names_any_case() {
        let p = profile(true, &[]);
        let rule = p.lines().find(|l| l.contains("[cC][oO][mM][mM][oO][nN][dD][iI][rR]")).unwrap_or_else(|| panic!("{p}"));
        for n in ["[hH][oO][oO][kK][sS]", "[cC][oO][nN][fF][iI][gG]\\.[wW][oO][rR][kK][tT][rR][eE][eE]", "[mM][oO][dD][uU][lL][eE][sS]", "[iI][nN][fF][oO]", "[wW][oO][rR][kK][tT][rR][eE][eE][sS]"] {
            assert!(rule.contains(n), "{n}: {rule}");
        }
        assert!(p.contains("/\\.[gG][iI][tT]/[^/]*[^ -~]"), "non-ASCII names at .git's top level: {p}");
    }

    #[test]
    fn g23_only_the_runs_own_terminal() {
        let p = profile(false, &["/dev/ttys004"]);
        assert!(!p.contains("ttys[0-9]"), "no pty regex: {p}");
        assert!(p.contains("(literal \"/dev/ttys004\")"), "{p}");
        assert!(!profile(false, &[]).contains("/dev/ttys"), "no tty: no pty rule");
    }

    #[test]
    fn g33_gateway_socket_cannot_be_unlinked_or_replaced() {
        let p = profile(false, &[]);
        let deny = last(&p, "(deny file-write-unlink file-write-create file-write-mode file-write-owner file-write-flags (literal \"/s/gateway.sock\"))");
        assert!(deny > last(&p, "(allow file-read* file-write* (literal \"/s/gateway.sock\"))"), "{p}");
    }

    #[test]
    fn g38_setuid_helpers_denied_after_every_exec_allow() {
        let p = profile(false, &[]);
        let deny = last(&p, "(literal \"/usr/bin/sudo\")");
        assert!(deny > last(&p, "(allow process-exec*"), "{p}");
        assert!(p[..deny].rfind("(deny process-exec*").is_some(), "{p}");
    }
}
