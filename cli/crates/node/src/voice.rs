//! docs/brand/VOICE.md guard: user-facing text never says "pledge", uses no banned hype words,
//! exclamation marks or emoji. Covers `--help`, every `connect` snippet, and every human
//! string literal (one containing a space) outside test code.

const BANNED: &[&str] = &[
    "pledge", "seamless", "unlock", "empower", "supercharge", "revolutioniz", "effortless", "leverage", "cutting-edge", "ai-powered",
    "next-gen", "magic", "game-changer", "donate compute", "donate ai compute", "pooled compute",
];

fn problems(where_: &str, text: &str, out: &mut Vec<String>) {
    let low = text.to_lowercase();
    for w in BANNED {
        if low.contains(w) {
            out.push(format!("{where_}: banned {w:?} in {text:?}"));
        }
    }
    if text.chars().any(|c| matches!(u32::from(c), 0x1F000..=0x1FAFF | 0x2600..=0x27BF)) {
        out.push(format!("{where_}: emoji in {text:?}"));
    }
}

/// Human prose ends a sentence with `!` (code like `!=` or `!x` does not count).
fn exclaims(text: &str) -> bool {
    text.match_indices('!').any(|(i, _)| i > 0 && text[..i].ends_with(|c: char| c.is_alphabetic()) && text[i + 1..].chars().next().is_none_or(|c| c.is_whitespace() || c == '"'))
}

/// String literals of a Rust source (plain `"..."` only; raw strings are covered by the snippet check).
fn literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines().map(str::trim_start).filter(|l| !l.starts_with("//")) {
        let mut chars = line.chars().peekable();
        let (mut cur, mut inside, mut prev) = (String::new(), false, ' ');
        while let Some(c) = chars.next() {
            if inside {
                match c {
                    '\\' => {
                        let _ = chars.next();
                        cur.push(' ');
                    }
                    '"' => {
                        out.push(std::mem::take(&mut cur));
                        inside = false;
                    }
                    _ => cur.push(c),
                }
            } else if c == '/' && chars.peek() == Some(&'/') {
                break;
            } else if c == '"' && prev != '\'' && prev != '#' && prev != 'r' {
                inside = true;
            }
            prev = c;
        }
    }
    out
}

#[test]
fn user_facing_text_follows_voice() {
    let mut bad = Vec::new();
    problems("--help", crate::cli::HELP, &mut bad);
    if exclaims(crate::cli::HELP) {
        bad.push("--help: exclamation mark".into());
    }
    for c in crate::connect::CLIENTS {
        let s = crate::connect::snippet(c, "http://127.0.0.1:4100", "acme/widget", "anthropic/claude-sonnet-5", "xai/grok-4").unwrap_or_default();
        problems(&format!("connect {c}"), &s, &mut bad);
        if exclaims(&s) {
            bad.push(format!("connect {c}: exclamation mark"));
        }
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "rs")).collect();
    files.sort();
    for f in files.iter().filter(|f| !f.ends_with("voice.rs")) {
        let src = std::fs::read_to_string(f).unwrap();
        let body = src.split("#[cfg(test)]").next().unwrap_or("");
        let name = f.file_name().unwrap().to_string_lossy();
        for lit in literals(body).iter().filter(|l| l.contains(' ')) {
            problems(&name, lit, &mut bad);
            if exclaims(lit) {
                bad.push(format!("{name}: exclamation mark in {lit:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "VOICE.md violations:\n{}", bad.join("\n"));
}

#[test]
fn guard_catches_violations() {
    let mut bad = Vec::new();
    problems("t", "Create a pledge to unlock magic", &mut bad);
    assert_eq!(bad.len(), 3);
    assert!(exclaims("Thanks for donating!"));
    assert!(!exclaims("if a != b { !x }"));
    assert_eq!(literals(r#"let a = "x \"y\" z"; // "no""#), vec!["x  y  z".to_owned()]);
}
