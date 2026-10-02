//! `moochy button` (CONTRACT §9, docs/guides/donate-button.md steps 1–3): the README "Donate
//! tokens" snippet for this repository, offline. The output is exactly the guide's snippets (a
//! unit test compares them with the guide).
//!
//! URLs: GitHub projects use the short two-segment form (`/p/OWNER/NAME/button.svg`, valid
//! forever as GitHub, CONTRACT §9); GitLab projects use the provider-qualified form with actions
//! after GitLab's `/-/` separator (`/p/gitlab/GROUP[/SUBGROUP…]/NAME/-/button.svg`, `/-/donate`,
//! A229), since the two-segment form means GitHub.

use crate::util::{Result, usage};

const ORIGIN: &str = "https://moochy.dev";
const DEFAULT_LABEL: &str = "Donate tokens";

#[derive(Debug, PartialEq, Eq)]
pub struct Project {
    pub provider: &'static str,
    /// `owner/name`, or `group/subgroup/…/name` on GitLab.
    pub path: String,
}

#[derive(Debug, Default)]
pub struct Options {
    pub label: Option<String>,
    pub style: Option<String>,
    pub theme: Option<String>,
    pub size: Option<String>,
    pub format: Option<String>,
}

fn valid_segment(s: &str) -> bool {
    (1..=100).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) && s.bytes().next().is_some_and(|c| c.is_ascii_alphanumeric())
}

/// The guide's remote parsing (step 1): `https://…`, `ssh://…`, `git@host:owner/name(.git)`.
/// The remote URL itself is never printed (it can carry a token).
pub fn parse_remote(url: &str) -> Result<Project> {
    let s = url.trim();
    let s = s.find("://").filter(|&i| s.get(..i).is_some_and(|sch| !sch.is_empty() && sch.bytes().all(|c| c.is_ascii_lowercase() || c == b'+'))).map_or(s, |i| s.get(i.saturating_add(3)..).unwrap_or_default());
    let s = match s.find(['@', '/']) {
        Some(i) if s.as_bytes().get(i) == Some(&b'@') => s.get(i.saturating_add(1)..).unwrap_or_default(),
        _ => s,
    };
    let host_end = s.find([':', '/']).unwrap_or(s.len());
    let host = s.get(..host_end).unwrap_or_default().to_ascii_lowercase();
    let mut rest = s.get(host_end..).unwrap_or_default();
    // `host:port/` (ssh://) or `host:` (scp-like) or `host/`.
    if let Some(r) = rest.strip_prefix(':') {
        rest = match r.split_once('/') {
            Some((port, after)) if !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) => after,
            _ => r,
        };
    } else {
        rest = rest.strip_prefix('/').unwrap_or(rest);
    }
    let path = rest.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let provider = match host.as_str() {
        "github.com" => "github",
        "gitlab.com" => "gitlab",
        _ => return Err(usage("only public repositories on github.com and gitlab.com can receive donations")),
    };
    project(provider, path)
}

/// A project from a `--repo` slug (`owner/name`, `github/owner/name`, `gitlab/group[/…]/name`).
pub fn from_slug(slug: &str) -> Result<Project> {
    let c = crate::config::canonical_slug(slug).ok_or_else(|| usage("--repo is owner/name, github/owner/name or gitlab/group[/subgroup]/name"))?;
    match c.strip_prefix("gitlab/") {
        Some(path) => project("gitlab", path),
        None => project("github", &c),
    }
}

/// Check an `owner/name` (GitHub) or `group[/subgroup…]/name` (GitLab) path.
pub fn project(provider: &'static str, path: &str) -> Result<Project> {
    let segs: Vec<&str> = path.split('/').collect();
    let ok_len = if provider == "github" { segs.len() == 2 } else { (2..=20).contains(&segs.len()) };
    if !ok_len || !segs.iter().all(|s| valid_segment(s)) {
        return Err(usage(format!("{provider}: the project must be {} (letters, digits, . _ -)", if provider == "github" { "owner/name" } else { "group[/subgroup]/name" })));
    }
    Ok(Project { provider, path: path.to_owned() })
}

fn valid_label(l: &str) -> bool {
    (1..=32).contains(&l.chars().count()) && l.chars().all(|c| c.is_ascii_alphanumeric() || " .,:;!?'’&+-()/#@".contains(c))
}

/// Form-encoding of a label (`Fuel this project` → `Fuel+this+project`).
fn encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b' ' => o.push('+'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => o.push(char::from(b)),
            _ => {
                let _ = write!(o, "%{b:02X}");
            }
        }
    }
    o
}

/// The snippet. `Options` values are checked against the guide's `button.svg` reference.
pub fn snippet(p: &Project, o: &Options) -> Result<String> {
    let pick = |v: &Option<String>, allowed: &[&str], name: &str| -> Result<Option<String>> {
        match v.as_deref() {
            None => Ok(None),
            Some(x) if allowed.contains(&x) => Ok(Some(x.to_owned())),
            Some(_) => Err(usage(format!("--{name} is one of: {}", allowed.join(", ")))),
        }
    };
    let style = pick(&o.style, &["mascot", "text", "compact"], "style")?;
    let theme = pick(&o.theme, &["light", "dark", "auto"], "theme")?;
    let size = pick(&o.size, &["s", "m", "l"], "size")?;
    if o.label.as_deref().is_some_and(|l| !valid_label(l)) {
        return Err(usage("--label: 1 to 32 characters (letters, digits, spaces, . , : ; ! ? ' ’ & + - ( ) / # @)"));
    }
    let label = o.label.clone().unwrap_or_else(|| DEFAULT_LABEL.to_owned());
    // The studio leaves out defaults and writes the rest in alphabetical order.
    let query = |theme_override: Option<&str>| -> String {
        let mut q: Vec<String> = Vec::new();
        if label != DEFAULT_LABEL {
            q.push(format!("label={}", encode(&label)));
        }
        if let Some(s) = size.as_deref().filter(|s| *s != "m") {
            q.push(format!("size={s}"));
        }
        if let Some(s) = style.as_deref().filter(|s| *s != "mascot") {
            q.push(format!("style={s}"));
        }
        if let Some(t) = theme_override.or(theme.as_deref()).filter(|t| *t != "light") {
            q.push(format!("theme={t}"));
        }
        if q.is_empty() { String::new() } else { format!("?{}", q.join("&")) }
    };
    // GitHub: the legacy short form (README buttons in the wild); GitLab: the canonical form, with
    // actions after `/-/` so nested group paths stay unambiguous (A229).
    let (base, act) = match p.provider {
        "github" => (format!("{ORIGIN}/p/{}", p.path), "/"),
        _ => (format!("{ORIGIN}/p/{}/{}", p.provider, p.path), "/-/"),
    };
    let (img, donate) = (format!("{base}{act}button.svg{}", query(None)), format!("{base}{act}donate"));
    let height = match size.as_deref() {
        Some("s") => 28,
        Some("l") => 44,
        _ => 36,
    };
    Ok(match o.format.as_deref().unwrap_or("markdown") {
        "markdown" => format!("[![{label}]({img})]({donate})"),
        // No explicit theme: the snippet that follows the reader's light or dark theme.
        "html" if theme.is_none() => format!(
            "<a href=\"{donate}\">\n  <picture>\n    <source media=\"(prefers-color-scheme: dark)\" srcset=\"{}\">\n    <img alt=\"{label}\" height=\"{height}\" src=\"{img}\">\n  </picture>\n</a>",
            format_args!("{base}{act}button.svg{}", query(Some("dark")))
        ),
        "html" => format!("<a href=\"{donate}\"><img alt=\"{label}\" height=\"{height}\" src=\"{img}\"></a>"),
        "rst" => format!(".. image:: {img}\n   :target: {donate}\n   :alt: {label}"),
        _ => return Err(usage("--format is one of: markdown, html, rst")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUIDE: &str = include_str!("../../../../docs/guides/donate-button.md");

    /// Fenced blocks of the guide's step 3, by language.
    fn guide_blocks(lang: &str) -> Vec<String> {
        let (_, step3) = GUIDE.split_once("### 3. Pick the snippet").unwrap();
        let (step3, _) = step3.split_once("### 4.").unwrap();
        step3.split(&format!("```{lang}\n")).skip(1).map(|b| b.split_once("\n```").unwrap().0.to_owned()).collect()
    }

    /// Step 2's example answer for a field (`button_url`, `donate_url`).
    fn guide_url(field: &str) -> String {
        let (_, step2) = GUIDE.split_once("### 2.").unwrap();
        let (_, json) = step2.split_once("```json\n").unwrap();
        let v: serde_json::Value = serde_json::from_str(json.split_once("\n```").unwrap().0).unwrap();
        v[field].as_str().unwrap().to_owned()
    }

    #[test]
    fn output_is_the_guide() {
        // Step 2's example project, in the GitHub short form the guide says `moochy button` prints.
        let (button, donate) = (guide_url("button_url"), guide_url("donate_url"));
        let short = |u: &str| u.replacen("/p/github/", "/p/", 1);
        assert!(GUIDE.contains(&short(&button).replacen("https://moochy.dev", "", 1)), "the guide documents the short form");
        let fill = |b: &str| b.replace("BUTTON_URL", &short(&button)).replace("DONATE_URL", &short(&donate));
        let p = Project { provider: "github", path: "tinyhttp/arrow".into() };
        let o = |format: &str, theme: Option<&str>| Options { format: Some(format.into()), theme: theme.map(str::to_owned), ..Options::default() };
        assert_eq!(snippet(&p, &o("markdown", None)).unwrap(), fill(&guide_blocks("markdown")[0]));
        let html = guide_blocks("html");
        assert_eq!(snippet(&p, &o("html", None)).unwrap(), fill(&html[0]), "theme-following HTML");
        assert_eq!(snippet(&p, &o("html", Some("light"))).unwrap(), fill(&html[1]), "one-theme HTML");
        assert_eq!(snippet(&p, &o("rst", None)).unwrap(), fill(&guide_blocks("rst")[0]));
        // The GitLab subgroup example, verbatim (actions after `/-/`, A229).
        let gl = Project { provider: "gitlab", path: "group/subgroup/project".into() };
        assert_eq!(snippet(&gl, &o("markdown", None)).unwrap(), guide_blocks("markdown")[1]);
    }

    #[test]
    fn remotes_and_options() {
        for (url, prov, path) in [
            ("https://github.com/tinyhttp/arrow.git", "github", "tinyhttp/arrow"),
            ("https://github.com/tinyhttp/arrow", "github", "tinyhttp/arrow"),
            ("git@github.com:tinyhttp/arrow.git", "github", "tinyhttp/arrow"),
            ("ssh://git@github.com/tinyhttp/arrow.git", "github", "tinyhttp/arrow"),
            ("https://user:tok@github.com/tinyhttp/arrow/", "github", "tinyhttp/arrow"),
            ("ssh://git@gitlab.com:22/group/sub/project.git", "gitlab", "group/sub/project"),
            ("git@gitlab.com:group/project.git", "gitlab", "group/project"),
        ] {
            assert_eq!(parse_remote(url).unwrap(), Project { provider: prov, path: path.into() }, "{url}");
        }
        for bad in ["https://bitbucket.org/a/b", "https://github.com/a/b/c", "https://github.com/-a/b", "git@github.com:a"] {
            assert!(parse_remote(bad).is_err(), "{bad}");
        }
        let p = Project { provider: "gitlab", path: "g/s/p".into() };
        let o = Options { label: Some("Fuel this project".into()), style: Some("compact".into()), size: Some("l".into()), ..Options::default() };
        assert_eq!(
            snippet(&p, &o).unwrap(),
            "[![Fuel this project](https://moochy.dev/p/gitlab/g/s/p/-/button.svg?label=Fuel+this+project&size=l&style=compact)](https://moochy.dev/p/gitlab/g/s/p/-/donate)"
        );
        assert!(snippet(&p, &Options { style: Some("neon".into()), ..Options::default() }).is_err());
        assert_eq!(from_slug("gitlab/g/s/p").unwrap(), p);
        assert_eq!(from_slug("github/acme/widget").unwrap(), Project { provider: "github", path: "acme/widget".into() });
        assert_eq!(from_slug("github/docs").unwrap(), Project { provider: "github", path: "github/docs".into() });
        assert!(snippet(&p, &Options { label: Some("<script>".into()), ..Options::default() }).is_err());
    }
}
