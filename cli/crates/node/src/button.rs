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
    /// `--chart` only (CONTRACT §21.2).
    pub metric: Option<String>,
    pub series: Option<String>,
    pub kind: Option<String>,
    pub period: Option<String>,
    pub goal: bool,
    pub total: bool,
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

fn valid_label(l: &str, max: usize) -> bool {
    (1..=max).contains(&l.chars().count()) && l.chars().all(|c| c.is_ascii_alphanumeric() || " .,:;!?'’&+-()/#@".contains(c))
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

fn pick(v: Option<&str>, allowed: &[&str], name: &str) -> Result<Option<String>> {
    match v {
        None => Ok(None),
        Some(x) if allowed.contains(&x) => Ok(Some(x.to_owned())),
        Some(_) => Err(usage(format!("--{name} is one of: {}", allowed.join(", ")))),
    }
}

/// `https://moochy.dev/p/…` (project page) and the separator before actions (`/` or `/-/`).
fn project_base(p: &Project) -> (String, &'static str) {
    // GitHub: the legacy short form (README buttons in the wild); GitLab: the canonical form, with
    // actions after `/-/` so nested group paths stay unambiguous (A229).
    match p.provider {
        "github" => (format!("{ORIGIN}/p/{}", p.path), "/"),
        _ => (format!("{ORIGIN}/p/{}/{}", p.provider, p.path), "/-/"),
    }
}

/// The canonical page of a project, organisation or person, relative to the site (CONTRACT §9,
/// §19.6, §22.1, §24.6): `p/github/OWNER/NAME`, `p/gitlab/…`, `org/PROVIDER/…`, `people/PROVIDER/LOGIN`.
pub fn page(to: crate::donations::To, target: &str) -> Result<String> {
    use crate::donations::To;
    match to {
        To::Repo => {
            let c = crate::config::canonical_slug(target).ok_or_else(|| usage("not a project: owner/name, github/owner/name or gitlab/group[/subgroup]/name"))?;
            Ok(if c.starts_with("gitlab/") { format!("p/{c}") } else { format!("p/github/{c}") })
        }
        To::Org => crate::config::canonical_org(target).map(|o| format!("org/{o}")).ok_or_else(|| usage("--org is github/ORG or gitlab/GROUP[/SUBGROUP…]")),
        To::Person => crate::config::canonical_org(target).filter(|o| o.matches('/').count() == 1).map(|o| format!("people/{o}")).ok_or_else(|| usage("--person is github/LOGIN or gitlab/USERNAME")),
    }
}

/// An organisation's or person's page and action separator (no short form, `/-/` on GitLab).
pub fn group_base(to: crate::donations::To, path: &str) -> Result<(String, &'static str)> {
    let page = page(to, path)?;
    let act = if path.starts_with("gitlab/") { "/-/" } else { "/" };
    Ok((format!("{ORIGIN}/{page}"), act))
}

const CHART_ALT: &str = "Tokens donated and used on Moochy";

/// An HTML attribute value, escaped exactly like the studio's Go `html.EscapeString`.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('\'', "&#39;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&#34;")
}

/// The showcase chart snippet (CONTRACT §21.3) for a project or organisation page `base` (its
/// actions after `act`). Same format and URLs as the web studio: defaults left out, the rest in
/// alphabetical order.
pub fn chart(base: &str, act: &str, o: &Options) -> Result<String> {
    let metric = pick(o.metric.as_deref(), &["tokens", "dollars"], "metric")?;
    let series = pick(o.series.as_deref(), &["both", "donated", "used"], "series")?;
    let kind = pick(o.kind.as_deref(), &["area", "bars", "line", "sparkline"], "kind")?;
    let period = pick(o.period.as_deref(), &["7d", "30d", "90d", "12m"], "period")?;
    let theme = pick(o.theme.as_deref(), &["light", "dark", "auto"], "theme")?;
    let size = pick(o.size.as_deref(), &["s", "m", "l"], "size")?;
    // The studio trims the label before using it.
    let label = o.label.as_deref().map(str::trim);
    if label.is_some_and(|l| !valid_label(l, 40)) {
        return Err(usage("--label: 1 to 40 characters (letters, digits, spaces, . , : ; ! ? ' ’ & + - ( ) / # @)"));
    }
    if o.style.is_some() {
        return Err(usage("--style is for the button, not --chart"));
    }
    let query = |theme_override: Option<&str>, card: bool| -> String {
        let mut q: Vec<String> = Vec::new();
        let mut opt = |k: &str, v: Option<&str>, default: &str| {
            if let Some(v) = v.filter(|v| *v != default) {
                q.push(format!("{k}={v}"));
            }
        };
        opt("goal", o.goal.then_some("1"), "");
        opt("kind", kind.as_deref(), "area");
        opt("label", label.map(encode).as_deref(), "");
        opt("metric", metric.as_deref(), "tokens");
        opt("period", period.as_deref(), "30d");
        opt("series", series.as_deref(), "both");
        opt("size", size.as_deref(), "m");
        // The card follows the reader's scheme unless told, so Light is written out there (as the studio).
        let t = theme_override.or(theme.as_deref());
        opt("theme", if card { t.or(Some("light")) } else { t }, if card { "" } else { "light" });
        opt("total", o.total.then_some("1"), "");
        if q.is_empty() { String::new() } else { format!("?{}", q.join("&")) }
    };
    let img = format!("{base}{act}chart.svg{}", query(None, false));
    let text = label.unwrap_or(CHART_ALT);
    let alt = html_escape(text);
    // In HTML attributes the query's `&` is written `&amp;`, as the studio does.
    let attr = |q: String| html_escape(&q);
    Ok(match o.format.as_deref().unwrap_or("markdown") {
        // Markdown alt text: `[` and `]` are not in the label charset.
        "markdown" => format!("[![{text}]({img})]({base})"),
        // Only `auto` follows the reader's theme with `<picture>` (light image, dark source);
        // the default (light) and an explicit theme are one image, as in the studio.
        "html" if theme.as_deref() == Some("auto") => format!(
            "<a href=\"{base}\">\n  <picture>\n    <source media=\"(prefers-color-scheme: dark)\" srcset=\"{base}{act}chart.svg{}\">\n    <img alt=\"{alt}\" src=\"{base}{act}chart.svg{}\">\n  </picture>\n</a>",
            attr(query(Some("dark"), false)),
            attr(query(Some("light"), false))
        ),
        "html" => format!("<a href=\"{base}\"><img alt=\"{alt}\" src=\"{base}{act}chart.svg{}\"></a>", attr(query(None, false))),
        "rst" => format!(".. image:: {img}\n   :target: {base}\n   :alt: {text}"),
        "iframe" => {
            // The studio's pixel boxes (sparklines are a strip).
            let spark = kind.as_deref() == Some("sparkline");
            let (w, h) = match size.as_deref() {
                Some("s") => (320, if spark { 40 } else { 160 }),
                Some("l") => (640, if spark { 80 } else { 320 }),
                _ => (480, if spark { 60 } else { 240 }),
            };
            format!("<iframe src=\"{base}{act}card{}\" title=\"{alt}\" width=\"{w}\" height=\"{h}\" style=\"border:0\" loading=\"lazy\"></iframe>", attr(query(None, true)))
        }
        _ => return Err(usage("--format is one of: markdown, html, rst, iframe")),
    })
}

/// A project's chart snippet: always the canonical `/p/PROVIDER/…` form (§9), as the studio.
pub fn project_chart(p: &Project, o: &Options) -> Result<String> {
    let act = if p.provider == "github" { "/" } else { "/-/" };
    chart(&format!("{ORIGIN}/p/{}/{}", p.provider, p.path), act, o)
}

/// The snippet. `Options` values are checked against the guide's `button.svg` reference.
pub fn snippet(p: &Project, o: &Options) -> Result<String> {
    if o.metric.is_some() || o.series.is_some() || o.kind.is_some() || o.period.is_some() || o.goal || o.total {
        return Err(usage("--metric, --series, --kind, --period, --goal and --total go with --chart"));
    }
    let style = pick(o.style.as_deref(), &["mascot", "text", "compact"], "style")?;
    let theme = pick(o.theme.as_deref(), &["light", "dark", "auto"], "theme")?;
    let size = pick(o.size.as_deref(), &["s", "m", "l"], "size")?;
    if o.label.as_deref().is_some_and(|l| !valid_label(l, 32)) {
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
    let (base, act) = project_base(p);
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

    #[test]
    fn chart_snippets() {
        let gh = Project { provider: "github", path: "tinyhttp/arrow".into() };
        let o = |f: &str| Options { format: Some(f.into()), ..Options::default() };
        // Canonical URLs (§9: `/p/github/…`), defaults left out.
        assert_eq!(
            project_chart(&gh, &Options::default()).unwrap(),
            "[![Tokens donated and used on Moochy](https://moochy.dev/p/github/tinyhttp/arrow/chart.svg)](https://moochy.dev/p/github/tinyhttp/arrow)"
        );
        // The studio's default HTML is one light image; only `auto` is a <picture> (E123).
        assert_eq!(
            project_chart(&gh, &o("html")).unwrap(),
            "<a href=\"https://moochy.dev/p/github/tinyhttp/arrow\"><img alt=\"Tokens donated and used on Moochy\" src=\"https://moochy.dev/p/github/tinyhttp/arrow/chart.svg\"></a>"
        );
        let auto = Options { theme: Some("auto".into()), kind: Some("bars".into()), label: Some(" Our tokens ".into()), total: true, ..o("html") };
        assert_eq!(
            project_chart(&gh, &auto).unwrap(),
            "<a href=\"https://moochy.dev/p/github/tinyhttp/arrow\">\n  <picture>\n    <source media=\"(prefers-color-scheme: dark)\" srcset=\"https://moochy.dev/p/github/tinyhttp/arrow/chart.svg?kind=bars&amp;label=Our+tokens&amp;theme=dark&amp;total=1\">\n    <img alt=\"Our tokens\" src=\"https://moochy.dev/p/github/tinyhttp/arrow/chart.svg?kind=bars&amp;label=Our+tokens&amp;total=1\">\n  </picture>\n</a>",
            "the studio's E123 auto case: label trimmed, & as &amp; in attributes"
        );
        assert_eq!(project_chart(&gh, &Options { format: Some("markdown".into()), ..auto }).unwrap(), "[![Our tokens](https://moochy.dev/p/github/tinyhttp/arrow/chart.svg?kind=bars&label=Our+tokens&theme=auto&total=1)](https://moochy.dev/p/github/tinyhttp/arrow)");
        // Every option, alphabetical; GitLab actions after `/-/`.
        let gl = Project { provider: "gitlab", path: "group/sub/project".into() };
        let all = Options {
            label: Some("Our tokens & use".into()),
            theme: Some("dark".into()),
            size: Some("l".into()),
            metric: Some("dollars".into()),
            series: Some("used".into()),
            kind: Some("bars".into()),
            period: Some("12m".into()),
            goal: true,
            total: true,
            ..Options::default()
        };
        let q = "?goal=1&kind=bars&label=Our+tokens+%26+use&metric=dollars&period=12m&series=used&size=l&theme=dark&total=1";
        let page = "https://moochy.dev/p/gitlab/group/sub/project";
        assert_eq!(project_chart(&gl, &all).unwrap(), format!("[![Our tokens & use]({page}/-/chart.svg{q})]({page})"));
        assert_eq!(project_chart(&gl, &Options { format: Some("html".into()), ..all }).unwrap(), format!("<a href=\"{page}\"><img alt=\"Our tokens &amp; use\" src=\"{page}/-/chart.svg{}\"></a>", q.replace('&', "&amp;")));
        assert_eq!(project_chart(&gl, &o("rst")).unwrap(), format!(".. image:: {page}/-/chart.svg\n   :target: {page}\n   :alt: Tokens donated and used on Moochy"));
        // Organisations: no short form; the card's pixel box (sparkline = a strip).
        let (b, a) = group_base(crate::donations::To::Org, "gitlab/group/sub").unwrap();
        let spark = Options { kind: Some("sparkline".into()), size: Some("s".into()), ..o("iframe") };
        assert_eq!(
            chart(&b, a, &spark).unwrap(),
            "<iframe src=\"https://moochy.dev/org/gitlab/group/sub/-/card?kind=sparkline&amp;size=s&amp;theme=light\" title=\"Tokens donated and used on Moochy\" width=\"320\" height=\"40\" style=\"border:0\" loading=\"lazy\"></iframe>"
        );
        let (b, a) = group_base(crate::donations::To::Org, "github/acme").unwrap();
        assert_eq!(chart(&b, a, &Options { period: Some("7d".into()), ..Options::default() }).unwrap(), "[![Tokens donated and used on Moochy](https://moochy.dev/org/github/acme/chart.svg?period=7d)](https://moochy.dev/org/github/acme)");
        assert!(group_base(crate::donations::To::Org, "acme").is_err());
        // People (§24.6): `/people/…`, one segment, `/-/` on GitLab.
        let (b, a) = group_base(crate::donations::To::Person, "gitlab/alice").unwrap();
        assert_eq!(chart(&b, a, &Options::default()).unwrap(), "[![Tokens donated and used on Moochy](https://moochy.dev/people/gitlab/alice/-/chart.svg)](https://moochy.dev/people/gitlab/alice)");
        assert!(group_base(crate::donations::To::Person, "github/a/b").is_err() && group_base(crate::donations::To::Person, "alice").is_err());
        // §22.1 share pages.
        assert_eq!(super::page(crate::donations::To::Repo, "acme/api").unwrap(), "p/github/acme/api");
        assert_eq!(super::page(crate::donations::To::Repo, "gitlab/g/s/p").unwrap(), "p/gitlab/g/s/p");
        assert_eq!(super::page(crate::donations::To::Org, "gitlab/g/s").unwrap(), "org/gitlab/g/s");
        // Refused: unknown values, a too long or hostile label, button-only and chart-only options.
        for bad in [
            Options { kind: Some("pie".into()), ..Options::default() },
            Options { period: Some("1y".into()), ..Options::default() },
            Options { label: Some("x".repeat(41)), ..Options::default() },
            Options { label: Some("<img onerror=x>".into()), ..Options::default() },
            Options { style: Some("text".into()), ..Options::default() },
            o("svg"),
        ] {
            assert!(project_chart(&gh, &bad).is_err(), "{bad:?}");
        }
        assert!(snippet(&gh, &Options { total: true, ..Options::default() }).is_err());
    }
}
