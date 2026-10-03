//! Terminal-safe text (CONTRACT §20.4, E121, A274): every server- or peer-provided string is
//! cleaned before it reaches the terminal, so a handle, description or model name cannot carry
//! escape sequences (cursor moves, title changes, OSC 52 clipboard writes, hyperlinks) or text
//! tricks (bidi overrides, invisible format characters, tag characters, Zalgo stacks).

/// Longest text kept, in characters; longer text ends with `…`.
pub const MAX_CHARS: usize = 2048;
/// Combining marks kept after one base character (more is a Zalgo stack, not a language).
const MAX_MARKS: usize = 2;

/// Cleans `s` for display:
/// - a whole escape sequence (CSI, OSC, DCS/SOS/PM/APC, their C1 forms, or ESC + one char)
///   becomes one U+FFFD, so nothing of its payload is left to read as text;
/// - any other control character (C0, DEL, C1, U+2028/2029) becomes U+FFFD;
/// - format characters (Unicode Cf: bidi overrides and isolates, zero-width, soft hyphen,
///   tags…) are dropped, as are variation selectors after the first and combining marks after
///   the second on one base;
/// - the result is at most [`MAX_CHARS`] characters.
#[must_use]
pub fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_CHARS));
    let mut it = s.chars().peekable();
    let (mut n, mut marks, mut vs) = (0usize, 0usize, 0usize);
    while let Some(c) = it.next() {
        if n >= MAX_CHARS {
            out.pop();
            out.push('…');
            break;
        }
        let kept = match c {
            '\u{1b}' => {
                match it.next() {
                    Some('[') => skip_csi(&mut it),
                    Some(']' | 'P' | 'X' | '^' | '_') => skip_string(&mut it),
                    _ => {}
                }
                Some('\u{FFFD}')
            }
            '\u{9b}' => {
                skip_csi(&mut it);
                Some('\u{FFFD}')
            }
            '\u{9d}' | '\u{90}' | '\u{98}' | '\u{9e}' | '\u{9f}' => {
                skip_string(&mut it);
                Some('\u{FFFD}')
            }
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => Some('\u{FFFD}'),
            c if is_format(c) => None,
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

/// CSI: parameters and intermediates up to the final byte (0x40–0x7E).
fn skip_csi(it: &mut std::iter::Peekable<std::str::Chars>) {
    for c in it.by_ref() {
        if ('\u{40}'..='\u{7e}').contains(&c) {
            break;
        }
    }
}

/// OSC/DCS/SOS/PM/APC: up to BEL, ST (ESC \) or the C1 ST.
fn skip_string(it: &mut std::iter::Peekable<std::str::Chars>) {
    while let Some(c) = it.next() {
        match c {
            '\u{7}' | '\u{9c}' => break,
            '\u{1b}' => {
                if it.peek() == Some(&'\\') {
                    it.next();
                }
                break;
            }
            _ => {}
        }
    }
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
        assert_eq!(clean("a\u{1b}[2Jb"), "a\u{FFFD}b");
        assert_eq!(clean("x\u{1b}]52;c;Zm9v\u{7}y"), "x\u{FFFD}y");
        assert_eq!(clean("x\u{1b}]8;;https://evil\u{1b}\\link"), "x\u{FFFD}link");
        assert_eq!(clean("c1\u{9b}31mz"), "c1\u{FFFD}z");
        assert_eq!(clean("dcs\u{1b}Pq#0\u{1b}\\end"), "dcs\u{FFFD}end");
        assert_eq!(clean("esc\u{1b}c!"), "esc\u{FFFD}!");
        assert_eq!(clean("unterminated\u{1b}]0;title"), "unterminated\u{FFFD}");
        assert_eq!(clean("tab\there\nnl"), "tab\u{FFFD}here\u{FFFD}nl");
        assert_eq!(clean("ls\u{2028}ps\u{2029}"), "ls\u{FFFD}ps\u{FFFD}");
        assert_eq!(clean("plain @alice"), "plain @alice");
    }

    #[test]
    fn text_tricks_are_dropped() {
        assert_eq!(clean("ab\u{202E}cd\u{2066}e"), "abcde");
        assert_eq!(clean("in\u{200B}vis\u{00AD}ible\u{2060}"), "invisible");
        assert_eq!(clean("tag\u{E0041}\u{E0042}s"), "tags");
        assert_eq!(clean("e\u{0301}\u{0301}\u{0301}\u{0301}x"), "e\u{0301}\u{0301}x");
        assert_eq!(clean("\u{2764}\u{FE0F}\u{FE0F}\u{FE0F}"), "\u{2764}\u{FE0F}");
        assert_eq!(clean("café naïve 日本"), "café naïve 日本");
        let long = clean(&"x".repeat(MAX_CHARS * 2));
        assert_eq!(long.chars().count(), MAX_CHARS);
        assert!(long.ends_with('…'));
    }
}
