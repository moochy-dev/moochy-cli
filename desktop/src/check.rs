//! Argument checks for every app command (plan 14 §2.2): nothing reaches a child process or the
//! system browser before it passes here. Pure functions, unit-tested below.

use moochy_node::config::{canonical_org, canonical_slug};

/// The providers `moochy keys add` takes from the window (a local GPU stays a CLI step).
pub const PROVIDERS: [&str; 5] = ["anthropic", "openai", "openrouter", "deepseek", "xai"];

pub fn provider(p: &str) -> Result<&'static str, String> {
    PROVIDERS.iter().copied().find(|x| *x == p).ok_or_else(|| "Pick a provider from the list.".to_owned())
}

/// The providers a key's prefix can belong to; empty when the prefix says nothing.
pub fn key_providers(key: &str) -> &'static [&'static str] {
    if key.starts_with("sk-ant-") {
        &["anthropic"]
    } else if key.starts_with("sk-or-") {
        &["openrouter"]
    } else if key.starts_with("xai-") {
        &["xai"]
    } else if key.starts_with("sk-") {
        &["openai", "deepseek"]
    } else {
        &[]
    }
}

/// A plausible API key for `provider`: printable ASCII, no spaces, a sane length, and a prefix
/// that does not name another provider.
pub fn key(provider: &str, key: &str) -> Result<(), String> {
    if !(16..=512).contains(&key.len()) || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("This does not look like an API key. Paste the whole key, without spaces.".into());
    }
    let fits = key_providers(key);
    if !fits.is_empty() && !fits.contains(&provider) {
        return Err(format!("This looks like a key for {}, not {}.", name(fits.first().copied().unwrap_or("")), name(provider)));
    }
    Ok(())
}

/// The provider's name as people write it.
pub fn name(p: &str) -> &str {
    match p {
        "anthropic" => "Anthropic",
        "openai" => "OpenAI",
        "openrouter" => "OpenRouter",
        "deepseek" => "DeepSeek",
        "xai" => "xAI",
        other => other,
    }
}

/// Whole dollars, $1 to $100,000.
pub fn dollars(d: u32) -> Result<u32, String> {
    if (1..=100_000).contains(&d) { Ok(d) } else { Err("Enter a whole number of dollars, from 1 to 100,000.".into()) }
}

/// What `donate` receives: (`--repo` | `--org` | `--person`, canonical value). A project may be
/// pasted as a GitHub or GitLab URL.
pub fn target(kind: &str, t: &str) -> Result<(&'static str, String), String> {
    let t = t.trim();
    match kind {
        "repo" => project(t).map(|s| ("--repo", s)).ok_or_else(|| "Enter a project as owner/name, gitlab/group/name, or paste its GitHub or GitLab link.".into()),
        "org" => canonical_org(t).map(|s| ("--org", s)).ok_or_else(|| "Enter an organisation as github/ORG or gitlab/GROUP.".into()),
        "person" => canonical_org(t).filter(|c| c.matches('/').count() == 1).map(|s| ("--person", s)).ok_or_else(|| "Enter a person as github/LOGIN or gitlab/USERNAME.".into()),
        _ => Err("unknown donation kind".into()),
    }
}

/// `owner/name`, `gitlab/…`, or a link to the project (`https://github.com/o/n/tree/main?x`).
pub fn project(t: &str) -> Option<String> {
    let t = t.split(['?', '#']).next().unwrap_or_default().trim_end_matches('/');
    let bare = t.strip_prefix("https://").or_else(|| t.strip_prefix("http://")).unwrap_or(t);
    let bare = bare.strip_prefix("www.").unwrap_or(bare);
    if let Some(path) = bare.strip_prefix("github.com/") {
        // Only owner/name: a link into the tree or an issue names the same project.
        let mut segs = path.splitn(3, '/');
        let (o, n) = (segs.next()?, segs.next()?);
        return canonical_slug(&format!("{o}/{}", n.strip_suffix(".git").unwrap_or(n)));
    }
    if let Some(path) = bare.strip_prefix("gitlab.com/") {
        // GitLab puts pages after `/-/`.
        let path = path.split("/-/").next().unwrap_or_default();
        return canonical_slug(&format!("gitlab/{}", path.strip_suffix(".git").unwrap_or(path)));
    }
    if t.starts_with("git@") || t.contains("://") {
        let p = moochy_node::button::parse_remote(t).ok()?;
        return canonical_slug(&if p.provider == "gitlab" { format!("gitlab/{}", p.path) } else { p.path });
    }
    canonical_slug(t)
}

/// A donation or request id as the relay prints it (`p_01J…`).
pub fn id(s: &str) -> Result<(), String> {
    let ok = (1..=80).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric());
    if ok { Ok(()) } else { Err("not a donation id".into()) }
}

pub fn client(c: &str) -> Result<(), String> {
    if moochy_node::connect::CLIENTS.contains(&c) { Ok(()) } else { Err("unknown tool".into()) }
}

/// `https://host[:port]`, or `http://` for a dev relay on this machine; no path, no user part.
fn is_origin(o: &str) -> bool {
    let (rest, local_only) = match (o.strip_prefix("https://"), o.strip_prefix("http://")) {
        (Some(r), _) => (r, false),
        (_, Some(r)) => (r, true),
        _ => return false,
    };
    let host = rest.rsplit_once(':').map_or(rest, |(h, port)| if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) { h } else { "" });
    !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') && (!local_only || host == "localhost" || host == "127.0.0.1")
}

/// Fixed pages the window links to outside moochy.dev, matched exactly: each provider's spend
/// limit page (the safety step, as `moochy safety` names them) and the client's source.
const FIXED: [&str; 6] = [
    "https://console.anthropic.com/settings/limits",
    "https://platform.openai.com/settings/organization/limits",
    "https://openrouter.ai/settings/keys",
    "https://platform.deepseek.com/usage",
    "https://console.x.ai",
    "https://github.com/moochy-dev/moochy-cli",
];

/// Links open in the system browser only on `https://moochy.dev/…`, the snapshot's web origin, and
/// the [`FIXED`] pages. A `/g/…` path must be exactly a gift link.
pub fn web_url(url: &str, web: &str) -> Result<(), String> {
    let clean = url.len() <= 2048 && url.chars().all(|c| c.is_ascii_graphic() && c != '\\');
    let path = url.strip_prefix("https://moochy.dev").or_else(|| url.strip_prefix(web).filter(|_| is_origin(web))).filter(|r| r.starts_with('/'));
    let page = path.is_some_and(|p| p.strip_prefix("/g/").is_none_or(gift_token));
    if clean && (page || FIXED.contains(&url)) { Ok(()) } else { Err("This link is not on moochy.dev, so the app does not open it.".into()) }
}

/// The 22 base64url characters of a gift link (CONTRACT §25.2).
fn gift_token(t: &str) -> bool {
    t.len() == 22 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Exactly `https://moochy.dev/g/<token>`, or the same on the snapshot's web origin (a dev relay).
pub fn gift_url(url: &str, web: &str) -> bool {
    url.strip_prefix("https://moochy.dev/g/").or_else(|| url.strip_prefix(web).filter(|_| is_origin(web))?.strip_prefix("/g/")).is_some_and(gift_token)
}

/// A donate page as `moochy button --qr` names it: `https://moochy.dev/p/<slug>[/-]/donate`.
pub fn donate_url(url: &str) -> Option<&str> {
    let slug = url.strip_prefix("https://moochy.dev/p/")?.strip_suffix("/donate")?;
    let ok = slug.len() <= 300 && !slug.contains("..") && !slug.contains("//") && !slug.starts_with(['/', '-', '.']) && slug.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b));
    ok.then_some(slug)
}

/// A gift is $1 to $1,000 (plan 15 §3.1).
pub fn gift_dollars(d: u32) -> Result<u32, String> {
    if (1..=1000).contains(&d) { Ok(d) } else { Err("A gift is a whole number of dollars, from 1 to 1,000.".into()) }
}

/// A gift note: trimmed, at most 140 characters, no control or direction-changing characters.
pub fn note(n: &str) -> Result<String, String> {
    let n = n.trim();
    let bad = |c: char| c.is_control() || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}');
    if n.chars().count() > 140 || n.chars().any(bad) { Err("A note is one line of at most 140 characters.".into()) } else { Ok(n.to_owned()) }
}

/// A gift link lives 1 to 90 days (30 by default).
pub fn days(d: u32) -> Result<u32, String> {
    if (1..=90).contains(&d) { Ok(d) } else { Err("A gift link lasts 1 to 90 days.".into()) }
}

/// `gf_` and a ULID (26 Crockford base32 characters).
pub fn gift_id(s: &str) -> Result<(), String> {
    let ulid = s.strip_prefix("gf_").filter(|u| u.len() == 26 && u.bytes().all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b))));
    if ulid.is_some() { Ok(()) } else { Err("not a gift id".into()) }
}

/// The QR code of `url` as SVG (ECC M, quiet zone, dark on light), drawn here (plan 15 D5).
pub fn qr_svg(url: &str) -> Result<String, String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::with_error_correction_level(url.as_bytes(), qrcode::EcLevel::M).map_err(|e| format!("QR code: {e}"))?;
    Ok(code.render::<svg::Color<'_>>().min_dimensions(256, 256).dark_color(svg::Color("#0f1b3d")).light_color(svg::Color("#ffffff")).build())
}

/// One line of `moochy doctor`: `ok  ` / `note` / `FAIL`, the check, the detail.
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct DoctorLine {
    pub level: &'static str,
    pub what: String,
    pub detail: String,
}

pub fn doctor(out: &str) -> Vec<DoctorLine> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut w = l.trim().splitn(2, ' ');
            let tag = w.next().unwrap_or_default();
            let rest = w.next().unwrap_or_default().trim_start();
            let level = match tag {
                "ok" => "ok",
                "FAIL" => "fail",
                _ => "warn",
            };
            let (what, detail) = rest.split_once(' ').unwrap_or((rest, ""));
            if matches!(tag, "ok" | "FAIL" | "note" | "warn") {
                DoctorLine { level, what: what.to_owned(), detail: detail.trim().to_owned() }
            } else {
                DoctorLine { level: "warn", what: String::new(), detail: l.trim().to_owned() }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_prefixes() {
        assert_eq!(key_providers("sk-ant-api03-abc"), ["anthropic"]);
        assert_eq!(key_providers("sk-or-v1-abc"), ["openrouter"]);
        assert_eq!(key_providers("xai-abc"), ["xai"]);
        assert_eq!(key_providers("sk-proj-abc"), ["openai", "deepseek"]);
        assert_eq!(key_providers("AIza123"), [] as [&str; 0]);
        assert!(key("anthropic", "sk-ant-api03-0123456789abcdef").is_ok());
        assert!(key("openai", "sk-ant-api03-0123456789abcdef").unwrap_err().contains("Anthropic"));
        assert!(key("deepseek", "sk-0123456789abcdef0123").is_ok());
        assert!(key("xai", "sk-or-v1-0123456789abcdef").is_err());
        assert!(key("openai", "sk-0123 456789abcdef").is_err(), "spaces");
        assert!(key("openai", "sk-short").is_err());
        assert!(key("openai", "sk-0123456789abcdef\u{1b}[2J").is_err(), "control bytes");
        assert!(provider("local").is_err() && provider("--yes").is_err() && provider("xai").is_ok());
    }

    #[test]
    fn amounts() {
        assert!(dollars(0).is_err() && dollars(100_001).is_err());
        assert_eq!(dollars(1), Ok(1));
        assert_eq!(dollars(100_000), Ok(100_000));
    }

    #[test]
    fn targets() {
        let r = |t: &str| target("repo", t).map(|x| x.1);
        assert_eq!(r("tokio-rs/axum").unwrap(), "tokio-rs/axum");
        assert_eq!(r(" github/tokio-rs/axum ").unwrap(), "tokio-rs/axum");
        assert_eq!(r("https://github.com/tokio-rs/axum").unwrap(), "tokio-rs/axum");
        assert_eq!(r("https://github.com/tokio-rs/axum/tree/main/src?x=1#l").unwrap(), "tokio-rs/axum");
        assert_eq!(r("github.com/tokio-rs/axum.git").unwrap(), "tokio-rs/axum");
        assert_eq!(r("git@github.com:tokio-rs/axum.git").unwrap(), "tokio-rs/axum");
        assert_eq!(r("https://gitlab.com/inkscape/inkscape/-/issues").unwrap(), "gitlab/inkscape/inkscape");
        assert_eq!(r("gitlab/a/b/c").unwrap(), "gitlab/a/b/c");
        for bad in ["--yes", "a", "a/b/c", "https://bitbucket.org/a/b", "a/-b", "acme/api\u{1b}[2J", "", "../x"] {
            assert!(r(bad).is_err(), "{bad:?}");
        }
        assert_eq!(target("org", "github/acme").unwrap(), ("--org", "github/acme".into()));
        assert!(target("org", "acme").is_err());
        assert_eq!(target("person", "github/alice").unwrap(), ("--person", "github/alice".into()));
        assert!(target("person", "gitlab/a/b").is_err());
        assert!(target("box", "x/y").is_err());
        assert!(id("p_01JABC").is_ok() && id("-x").is_err() && id("").is_err() && id("a b").is_err());
        assert!(client("claude-code").is_ok() && client("sh").is_err());
    }

    #[test]
    fn links() {
        let web = "https://moochy.dev";
        assert!(web_url("https://moochy.dev/device?code=ABCD-1234", web).is_ok());
        assert!(web_url("https://moochy.dev/decide/p_01", "").is_ok());
        for bad in ["https://moochy.dev", "https://moochy.dev.evil.com/x", "https://moochy.dev@evil.com/", "http://moochy.dev/x", "javascript:alert(1)", "file:///etc/passwd", "https://moochy.dev/a b", "https://moochy.dev/\\evil"] {
            assert!(web_url(bad, web).is_err(), "{bad}");
        }
        assert!(web_url("http://127.0.0.1:8080/decide/x", "http://127.0.0.1:8080").is_ok(), "dev relay");
        assert!(web_url("http://evil.com/x", "http://evil.com").is_err(), "plain http only on this machine");
        assert!(web_url("https://evil.com/x", "https://evil.com/path").is_err(), "an origin has no path");
        assert!(web_url("https://console.x.ai", web).is_ok());
        assert!(web_url("https://console.x.ai/../evil", web).is_err() && web_url("https://github.com/moochy-dev/moochy-cli/x", web).is_err(), "fixed pages match exactly");
    }

    #[test]
    fn gifts() {
        let t = "AbCdEfGhIjKlMnOpQrSt_-";
        let web = "https://moochy.dev";
        assert!(gift_url(&format!("https://moochy.dev/g/{t}"), web));
        assert!(gift_url(&format!("http://127.0.0.1:8080/g/{t}"), "http://127.0.0.1:8080"), "dev relay");
        for bad in [format!("https://moochy.dev/g/{t}x"), format!("https://moochy.dev/g/{t}/"), format!("https://moochy.dev/g/{t}?a"), format!("http://moochy.dev/g/{t}"), format!("https://evil.com/g/{t}"), "https://moochy.dev/g/AbCdEfGhIjKlMnOpQrSt_=".into()] {
            assert!(!gift_url(&bad, web), "{bad}");
        }
        // open_web: `/g/` only in the exact shape; other pages as before.
        assert!(web_url(&format!("https://moochy.dev/g/{t}"), web).is_ok());
        assert!(web_url("https://moochy.dev/g/short", web).is_err() && web_url(&format!("https://moochy.dev/g/{t}/x"), web).is_err());
        assert!(web_url(&format!("http://127.0.0.1:8080/g/{t}"), "http://127.0.0.1:8080").is_ok() && web_url("http://127.0.0.1:8080/g/x", "http://127.0.0.1:8080").is_err());
        assert!(web_url("https://moochy.dev/credits", web).is_ok());

        assert_eq!(donate_url("https://moochy.dev/p/github/tokio-rs/axum/donate"), Some("github/tokio-rs/axum"));
        assert_eq!(donate_url("https://moochy.dev/p/gitlab/inkscape/inkscape/-/donate"), Some("gitlab/inkscape/inkscape/-"));
        for bad in ["https://moochy.dev/p/../x/donate", "https://moochy.dev/p//x/donate", "https://evil.com/p/a/b/donate", "https://moochy.dev/p/a/b/donate?x", "https://moochy.dev/p/a b/donate"] {
            assert!(donate_url(bad).is_none(), "{bad}");
        }

        assert!(gift_dollars(0).is_err() && gift_dollars(1001).is_err() && gift_dollars(1).is_ok() && gift_dollars(1000).is_ok());
        assert!(days(0).is_err() && days(91).is_err() && days(30).is_ok());
        assert_eq!(note("  for the axum team  ").unwrap(), "for the axum team");
        assert!(note(&"é".repeat(140)).is_ok() && note(&"é".repeat(141)).is_err(), "characters, not bytes");
        for bad in ["two\nlines", "tab\there", "\u{1b}[2J", "rtl\u{202E}txt", "zw\u{200B}j"] {
            assert!(note(bad).is_err(), "{bad:?}");
        }
        assert!(gift_id("gf_01JB8ZK3M4N5P6Q7R8S9T0VWXY").is_ok());
        for bad in ["gf_01JB8ZK3M4N5P6Q7R8S9T0VWX", "gf_01JB8ZK3M4N5P6Q7R8S9T0VWXI", "gf_01jb8zk3m4n5p6q7r8s9t0vwxy", "p_01JB8ZK3M4N5P6Q7R8S9T0VWXY", "--replace", ""] {
            assert!(gift_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn qr() {
        let a = qr_svg("https://moochy.dev/g/AbCdEfGhIjKlMnOpQrSt_-").unwrap();
        assert!(a.contains("<svg") && a.contains("crispEdges") && a.ends_with("</svg>"));
        assert_eq!(a, qr_svg("https://moochy.dev/g/AbCdEfGhIjKlMnOpQrSt_-").unwrap(), "deterministic");
        assert_ne!(a, qr_svg("https://moochy.dev/g/AbCdEfGhIjKlMnOpQrSt_x").unwrap());
    }

    #[test]
    fn doctor_lines() {
        let v = doctor("ok   keystore  opens (keychain), device keys present\nFAIL clock     off by 40 s\n\nsomething else\n");
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], DoctorLine { level: "ok", what: "keystore".into(), detail: "opens (keychain), device keys present".into() });
        assert_eq!(v[1].level, "fail");
        assert_eq!(v[2].detail, "something else");
    }
}
