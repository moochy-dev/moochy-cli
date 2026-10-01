//! Moochy usernames (CONTRACT §11), identical in Go and Rust via `spec/vectors/usernames.json`.
//!
//! Pipeline: refuse anything non-ASCII (no homoglyphs, zero-width or bidi tricks) → ASCII
//! lowercase → format `^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$` without `--` → reserved words.
//! ASCII look-alikes (`rnoochy`, `m00chy`, `ange-s`/`anges`) are caught by comparing
//! [`skeleton`]s: reserved words, taken handles and tombstones all match on the skeleton
//! (`users.username_skeleton`, UNIQUE). [`verdict`] fixes the order of all checks so both
//! implementations report the same reason.

use std::borrow::Cow;
use std::fmt::Write as _;

/// CONTRACT §11 reserved handles: first path segments of web/API routes, then staff/system words.
/// Defined once in `spec/vectors/usernames.json` (`reserved`, CONTRACT R7); `tests/vectors.rs`
/// fails if this copy and the file ever differ.
pub const RESERVED: &[&str] = &[
    "api", "dev", "p", "r", "u", "log", "logout", "events", "open", "connect", "explore", "station", "console",
    "device", "devices", "claim", "leaderboard", "auth", "admin", "static", "mcp", "v1", "moochy", "root", "support",
    "security", "staff", "official", "system", "null", "undefined", "anonymous", "relay", "node", "bot",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// Non-ASCII, wrong length, bad characters, leading/trailing/double hyphen.
    Invalid,
    Reserved,
    /// Held by a current user (case-insensitive).
    Taken,
    /// Used before by someone (renamed away); never reassigned.
    Tombstoned,
}

impl Verdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Invalid => "invalid",
            Self::Reserved => "reserved",
            Self::Taken => "taken",
            Self::Tombstoned => "tombstoned",
        }
    }
}

/// Canonical (stored) form of a requested handle, or why it can never be one.
pub fn canonical(input: &str) -> Result<String, Verdict> {
    if !input.is_ascii() {
        return Err(Verdict::Invalid);
    }
    let h = input.to_ascii_lowercase();
    let b = h.as_bytes();
    let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = (3..=32).contains(&b.len())
        && b.first().is_some_and(alnum)
        && b.last().is_some_and(alnum)
        && b.iter().all(|c| alnum(c) || *c == b'-')
        && !h.contains("--");
    if !ok {
        return Err(Verdict::Invalid);
    }
    let sk = skeleton(&h);
    if RESERVED.iter().any(|r| skeleton(r) == sk) {
        return Err(Verdict::Reserved);
    }
    Ok(h)
}

/// Look-alike key (CONTRACT §11): ASCII-lowercase, then `rn`→`m`, `vv`→`w`, `0`→`o`, `1`→`l`,
/// then `-` removed — each rule applied left to right over the whole string, in that order
/// (`rrn`→`rm`, `vvv`→`wv`, `r-n`→`rn`). Identical to Go `oauth.Skeleton`.
#[must_use]
pub fn skeleton(handle: &str) -> String {
    handle.to_ascii_lowercase().replace("rn", "m").replace("vv", "w").replace('0', "o").replace('1', "l").replace('-', "")
}

/// Full decision: invalid → reserved → taken → tombstoned → ok. The lookups receive the
/// SKELETON of the canonical form and must answer "does a current / retired handle have this
/// skeleton?" (`users.username_skeleton`, `username_tombstones` skeletons).
pub fn verdict(input: &str, taken: impl Fn(&str) -> bool, tombstoned: impl Fn(&str) -> bool) -> Verdict {
    match canonical(input).map(|h| skeleton(&h)) {
        Err(v) => v,
        Ok(sk) if taken(&sk) => Verdict::Taken,
        Ok(sk) if tombstoned(&sk) => Verdict::Tombstoned,
        Ok(_) => Verdict::Ok,
    }
}

/// Escape characters that can hijack a terminal or reorder text (C0/C1 controls, bidi controls,
/// zero-width and other invisible format characters) as `\u{XXXX}`. Use on every
/// server-provided string before printing (CONTRACT §11).
#[must_use]
pub fn display_safe(s: &str) -> Cow<'_, str> {
    let bad = |c: char| {
        c.is_control()
            || matches!(c, '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
    };
    if !s.contains(bad) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len().saturating_add(16));
    for c in s.chars() {
        if bad(c) {
            let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        for ok in ["abc", "alice", "a-b", "a1-b2-c3", "0xff", &"a".repeat(32)] {
            assert_eq!(canonical(ok).as_deref(), Ok(ok), "{ok}");
        }
        assert_eq!(canonical("Alice").as_deref(), Ok("alice"));
        for bad in ["ab", "-ab", "ab-", "a--b", "a_b", "a.b", "a b", " abc", "аlice", "al\u{200B}ice", "", &"a".repeat(33)] {
            assert_eq!(canonical(bad), Err(Verdict::Invalid), "{bad:?}");
        }
        assert_eq!(canonical("ADMIN"), Err(Verdict::Reserved));
        assert_eq!((canonical("logout"), canonical("Events")), (Err(Verdict::Reserved), Err(Verdict::Reserved)));
        let v = |s| verdict(s, |k| k == skeleton("alice"), |k| k == skeleton("old-name"));
        assert_eq!((v("ALICE"), v("Old-Name"), v("bob")), (Verdict::Taken, Verdict::Tombstoned, Verdict::Ok));
        assert_eq!((v("a1ice"), v("oldname"), v("o1d-name")), (Verdict::Taken, Verdict::Tombstoned, Verdict::Tombstoned));
        for (i, o) in [("rnoochy", "moochy"), ("m00chy", "moochy"), ("RNOOCHY", "moochy"), ("ange-s", "anges"), ("ali1ce", "alilce"), ("vvalt", "walt"), ("rnrn", "mm"), ("rrn", "rm"), ("rnn", "mn"), ("vvv", "wv"), ("r-n", "rn"), ("v-v", "vv"), ("r0n", "ron"), ("1o1", "lol")] {
            assert_eq!(skeleton(i), o, "{i}");
        }
        for r in ["rnoochy", "adrnin", "r00t", "a-p-i", "v-1", "dev-ice"] {
            assert_eq!(canonical(r), Err(Verdict::Reserved), "{r}");
        }
        assert_eq!(canonical("dev1ce").as_deref(), Ok("dev1ce"));
        assert_eq!(display_safe("ok"), "ok");
        assert_eq!(display_safe("a\x1b[2Jb\u{202E}c"), "a\\u{001B}[2Jb\\u{202E}c");
    }
}
