//! Secret scrubber (06 §13): high-confidence secret shapes → `[REDACTED:type]`, before sealing
//! request bodies and MCP files. Works on raw bytes; replaced runs never contain `"` or `\`, so a
//! valid JSON document stays valid. Best effort by nature: novel formats pass (T20 residual).

const TOKEN_PREFIXES: &[(&[u8], usize, &str)] = &[
    (b"sk-ant-", 20, "anthropic_key"),
    (b"sk-or-v1-", 20, "openrouter_key"),
    (b"sk-proj-", 20, "openai_key"),
    (b"sk-", 32, "api_key"),
    (b"ghp_", 30, "github_token"),
    (b"gho_", 30, "github_token"),
    (b"ghs_", 30, "github_token"),
    (b"ghu_", 30, "github_token"),
    (b"ghr_", 30, "github_token"),
    (b"github_pat_", 30, "github_token"),
    (b"glpat-", 20, "gitlab_token"),
    (b"xoxb-", 10, "slack_token"),
    (b"xoxp-", 10, "slack_token"),
    (b"xoxa-", 10, "slack_token"),
    (b"xapp-", 10, "slack_token"),
    (b"AIza", 35, "google_key"),
    (b"AKIA", 16, "aws_key"),
    (b"ASIA", 16, "aws_key"),
];

const ENV_WORDS: &[&[u8]] = &[b"SECRET", b"TOKEN", b"PASSWORD", b"PASSWD", b"API_KEY", b"APIKEY", b"PRIVATE_KEY", b"ACCESS_KEY", b"CREDENTIAL"];

fn tok(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

fn run_len(b: &[u8], from: usize, f: impl Fn(u8) -> bool) -> usize {
    b.get(from..).map_or(0, |s| s.iter().take_while(|c| f(**c)).count())
}

fn starts(b: &[u8], i: usize, p: &[u8]) -> bool {
    b.get(i..).is_some_and(|s| s.starts_with(p))
}

fn find(b: &[u8], from: usize, p: &[u8]) -> Option<usize> {
    let s = b.get(from..)?;
    s.windows(p.len()).position(|w| w == p).map(|x| x.saturating_add(from))
}

/// Match a secret starting at `i`: `(end, kind)`. `i` must be at a word boundary.
fn match_at(b: &[u8], i: usize) -> Option<(usize, &'static str)> {
    let c = at(b, i);
    if c == b'-' && starts(b, i, b"-----BEGIN ") {
        let hdr_end = find(b, i.saturating_add(11), b"-----")?;
        let hdr = b.get(i..hdr_end)?;
        if hdr.len() < 120 && hdr.windows(11).any(|w| w == b"PRIVATE KEY") {
            let end = find(b, hdr_end.saturating_add(5), b"-----END ")?;
            let close = find(b, end.saturating_add(9), b"-----")?;
            return Some((close.saturating_add(5), "private_key"));
        }
        return None;
    }
    if c == b'e' && starts(b, i, b"eyJ") {
        // JWT: three base64url segments, the first two JSON objects.
        let a = run_len(b, i, |c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
        let p1 = i.saturating_add(a);
        if a >= 10 && at(b, p1) == b'.' && starts(b, p1.saturating_add(1), b"eyJ") {
            let p2 = p1.saturating_add(1);
            let bl = run_len(b, p2, |c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
            let p3 = p2.saturating_add(bl);
            if bl >= 10 && at(b, p3) == b'.' {
                let s = run_len(b, p3.saturating_add(1), |c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
                if s >= 16 {
                    return Some((p3.saturating_add(1).saturating_add(s), "jwt"));
                }
            }
        }
        return None;
    }
    for (p, min, kind) in TOKEN_PREFIXES {
        if starts(b, i, p) {
            let body = i.saturating_add(p.len());
            let n = if p.starts_with(b"AKIA") || p.starts_with(b"ASIA") {
                run_len(b, body, |c| c.is_ascii_uppercase() || c.is_ascii_digit())
            } else {
                run_len(b, body, tok)
            };
            if n >= *min {
                return Some((body.saturating_add(n), kind));
            }
        }
    }
    None
}

/// `NAME=value` where NAME looks like a secret variable: returns the value span.
fn env_value(b: &[u8], eq: usize) -> Option<(usize, usize)> {
    let mut s = eq;
    while s > 0 && at(b, s.saturating_sub(1)) == b' ' {
        s = s.saturating_sub(1);
    }
    let name_end = s;
    while s > 0 && (at(b, s.saturating_sub(1)).is_ascii_uppercase() || at(b, s.saturating_sub(1)).is_ascii_digit() || at(b, s.saturating_sub(1)) == b'_') {
        s = s.saturating_sub(1);
    }
    let name = b.get(s..name_end)?;
    if name.is_empty() || !ENV_WORDS.iter().any(|w| name.windows(w.len()).any(|x| x == *w)) {
        return None;
    }
    let before = if s == 0 { b'\n' } else { at(b, s.saturating_sub(1)) };
    let escaped_nl = before == b'n' && s >= 2 && at(b, s.saturating_sub(2)) == b'\\';
    if !(matches!(before, b'\n' | b' ' | b'\t' | b'"') || escaped_nl) {
        return None;
    }
    let mut v = eq.saturating_add(1).saturating_add(run_len(b, eq.saturating_add(1), |c| c == b' '));
    if starts(b, v, b"\\\"") {
        v = v.saturating_add(2);
    } else if at(b, v) == b'\'' {
        v = v.saturating_add(1);
    }
    let n = run_len(b, v, |c| c.is_ascii_graphic() && !matches!(c, b'"' | b'\\' | b'\'' | b'$' | b'<'));
    (n >= 8).then(|| (v, v.saturating_add(n)))
}

/// Scrub; `None` when nothing matched (no copy).
pub fn scrub(b: &[u8]) -> Option<Vec<u8>> {
    let mut out: Option<Vec<u8>> = None;
    let mut last = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = at(b, i);
        // A JSON escape (`\n`, `\t`, `\r`) right before also counts as a word boundary.
        let prev = at(b, i.saturating_sub(1));
        let escaped = i >= 2 && at(b, i.saturating_sub(2)) == b'\\' && matches!(prev, b'n' | b't' | b'r');
        let boundary = i == 0 || !tok(prev) || escaped;
        let hit = if c == b'=' {
            env_value(b, i).map(|(s, e)| (s, e, "env_secret"))
        } else if boundary && matches!(c, b'-' | b'e' | b's' | b'g' | b'x' | b'A') {
            match_at(b, i).map(|(e, k)| (i, e, k))
        } else {
            None
        };
        if let Some((s, e, kind)) = hit {
            let o = out.get_or_insert_with(|| Vec::with_capacity(b.len()));
            o.extend_from_slice(b.get(last..s).unwrap_or_default());
            o.extend_from_slice(format!("[REDACTED:{kind}]").as_bytes());
            last = e;
            i = e;
        } else {
            i = i.saturating_add(1);
        }
    }
    let mut o = out?;
    o.extend_from_slice(b.get(last..).unwrap_or_default());
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::scrub;

    fn s(x: &str) -> String {
        String::from_utf8(scrub(x.as_bytes()).unwrap_or_else(|| x.as_bytes().to_vec())).unwrap()
    }

    #[test]
    fn redacts_known_shapes() {
        assert_eq!(s("key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123 end"), "key [REDACTED:anthropic_key] end");
        assert_eq!(s("AKIAABCDEFGHIJKLMNOP"), "[REDACTED:aws_key]");
        assert_eq!(s("x ghp_0123456789abcdefghijklmnopqrstuvwxyz"), "x [REDACTED:github_token]");
        assert_eq!(s("DB_PASSWORD=hunter2hunter2\nOK=1"), "DB_PASSWORD=[REDACTED:env_secret]\nOK=1");
        assert_eq!(s("export API_KEY = 'abcdefgh123'"), "export API_KEY = '[REDACTED:env_secret]'");
        assert_eq!(s("PATH=/usr/bin:/bin"), "PATH=/usr/bin:/bin");
        assert_eq!(s("TOKEN=$OTHER_VAR"), "TOKEN=$OTHER_VAR");
        assert_eq!(s("task-ant-x"), "task-ant-x", "needs a word boundary");
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_eq!(s(jwt), "[REDACTED:jwt]");
    }

    #[test]
    fn keeps_json_valid() {
        let body = serde_json::json!({"messages":[{"role":"user","content":
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\nAWS_SECRET_ACCESS_KEY=abcdEFGH1234/xyz\nsk-proj-abcdefghijklmnopqrstuvwxyz"}]})
        .to_string();
        let out = scrub(body.as_bytes()).unwrap();
        let v = crate::json::parse(&out).unwrap();
        let text = v["messages"][0]["content"].as_str().unwrap();
        assert_eq!(text, "[REDACTED:private_key]\nAWS_SECRET_ACCESS_KEY=[REDACTED:env_secret]\n[REDACTED:openai_key]");
        assert!(scrub(b"{\"a\":\"plain text\"}").is_none());
    }
}
