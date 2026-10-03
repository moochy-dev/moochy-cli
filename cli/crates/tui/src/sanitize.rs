//! Terminal-safe text (CONTRACT §20.4, E121, A274): every server- or peer-provided string is
//! cleaned before it reaches the terminal, so a handle, description or model name cannot carry
//! escape sequences (cursor moves, title changes, OSC 52 clipboard writes, hyperlinks) or text
//! tricks (bidi overrides, invisible format characters, tag characters, Zalgo stacks).

/// Longest text kept, in characters; longer text ends with `…`.
pub const MAX_CHARS: usize = 2048;
/// Combining marks kept after one base character (more is a Zalgo stack, not a language).
const MAX_MARKS: usize = 2;

/// Cleans `s` for display:
/// - every control character (C0, DEL, C1, U+2028/2029) becomes U+FFFD, so an escape sequence
///   can never start: ESC, CSI (U+009B), OSC (U+009D)… are gone and what followed them is plain,
///   inert text (`�]52;c;…` shows that a peer tried, which is worth seeing);
/// - format characters (Unicode Cf: bidi overrides and isolates, zero-width, soft hyphen,
///   tags…) and Hangul fillers are dropped, as are variation selectors after the first and
///   combining marks after the second on one base;
/// - the result is at most [`MAX_CHARS`] characters.
#[must_use]
pub fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_CHARS));
    let (mut n, mut marks, mut vs) = (0usize, 0usize, 0usize);
    for c in s.chars() {
        if n >= MAX_CHARS {
            out.pop();
            out.push('…');
            break;
        }
        let kept = match c {
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => Some('\u{FFFD}'),
            c if is_format(c) || is_filler(c) => None,
            c if is_variation_selector(c) => {
                vs = vs.saturating_add(1);
                (vs == 1).then_some(c)
            }
            c if is_combining(c) => {
                marks = marks.saturating_add(1);
                (marks <= MAX_MARKS).then_some(c)
            }
            c => {
                marks = 0;
                vs = 0;
                Some(c)
            }
        };
        if let Some(k) = kept {
            out.push(k);
            n = n.saturating_add(1);
        }
    }
    out
}

/// Hangul fillers: blank-looking letters that pad or forge names.
fn is_filler(c: char) -> bool {
    matches!(c, '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}')
}

/// Unicode general category Cf (format), plus the invisible operators.
fn is_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}' | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

fn is_variation_selector(c: char) -> bool {
    matches!(c, '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}' | '\u{180B}'..='\u{180D}')
}

fn is_combining(c: char) -> bool {
    matches!(c, '\u{0300}'..='\u{036F}' | '\u{0483}'..='\u{0489}' | '\u{1AB0}'..='\u{1AFF}' | '\u{1DC0}'..='\u{1DFF}' | '\u{20D0}'..='\u{20FF}' | '\u{FE20}'..='\u{FE2F}')
}

#[cfg(test)]
mod tests {
    use super::{MAX_CHARS, clean};

    #[test]
    fn escapes_are_inert() {
        assert_eq!(clean("a\u{1b}[2Jb"), "a\u{FFFD}[2Jb");
        assert_eq!(clean("x\u{1b}]52;c;Zm9v\u{7}y"), "x\u{FFFD}]52;c;Zm9v\u{FFFD}y");
        assert_eq!(clean("c1\u{9b}31m"), "c1\u{FFFD}31m");
        assert_eq!(clean("osc\u{9d}0;t\u{9c}"), "osc\u{FFFD}0;t\u{FFFD}");
        assert_eq!(clean("tab\there\nnl"), "tab\u{FFFD}here\u{FFFD}nl");
        assert_eq!(clean("ls\u{2028}ps\u{2029}"), "ls\u{FFFD}ps\u{FFFD}");
        assert_eq!(clean("plain @alice"), "plain @alice");
        // No escape can survive: every ESC/C1 is gone.
        assert!(!clean("\u{1b}\u{9b}\u{9d}\u{90}").chars().any(char::is_control));
    }

    #[test]
    fn text_tricks_are_dropped() {
        assert_eq!(clean("ab\u{202E}cd\u{2066}e"), "abcde");
        assert_eq!(clean("in\u{200B}vis\u{00AD}ible\u{2060}"), "invisible");
        assert_eq!(clean("tag\u{E0041}\u{E0042}s"), "tags");
        assert_eq!(clean("a\u{3164}b\u{115F}c"), "abc");
        assert_eq!(clean("e\u{0301}\u{0301}\u{0301}\u{0301}x"), "e\u{0301}\u{0301}x");
        assert_eq!(clean("\u{2764}\u{FE0F}\u{FE0F}\u{FE0F}"), "\u{2764}\u{FE0F}");
        assert_eq!(clean("café naïve 日本"), "café naïve 日本");
        let long = clean(&"x".repeat(MAX_CHARS * 2));
        assert_eq!(long.chars().count(), MAX_CHARS);
        assert!(long.ends_with('…'));
    }
}
