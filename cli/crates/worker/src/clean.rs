//! Terminal-safe text (CONTRACT §15.4, attack A165/A46): strip everything a terminal would
//! interpret instead of print, from any donor text a human or an agent will display.
//!
//! Removed: ESC sequences (CSI `ESC [ … final`, OSC `ESC ] … BEL|ST` incl. OSC 8 links and
//! OSC 52 clipboard writes, DCS/SOS/PM/APC `ESC P|X|^|_ … ST`, any other `ESC x`), C1
//! controls U+0080–U+009F (8-bit CSI/OSC with their parameters), C0 controls except `\n` and
//! `\t` (a lone `\r` is dropped, `\r\n` becomes `\n`), DEL, and bidi controls (LRE, RLE, PDF,
//! LRO, RLO, LRI, RLI, FSI, PDI, LRM, RLM, ALM: Trojan-Source reordering). Everything else is
//! kept byte for byte; clean input is returned borrowed (no allocation).

use std::borrow::Cow;

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

fn needs_cleaning(c: char) -> bool {
    match c {
        '\n' | '\t' => false,
        '\u{0}'..='\u{1F}' | '\u{7F}'..='\u{9F}' => true,
        _ => is_bidi(c),
    }
}

/// Strip terminal control sequences and bidi overrides (see module docs).
pub fn clean_text(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_cleaning) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\u{1B}' => match it.next() {
                // CSI: parameters/intermediates until a final byte 0x40–0x7E.
                Some('[') => {
                    for d in it.by_ref() {
                        if ('\u{40}'..='\u{7E}').contains(&d) {
                            break;
                        }
                    }
                }
                // OSC and string controls: until BEL, ST (ESC \) or C1 ST.
                Some(']' | 'P' | 'X' | '^' | '_') => skip_string(&mut it),
                // Any other two-byte escape (or a trailing ESC).
                _ => {}
            },
            '\u{9B}' => {
                for d in it.by_ref() {
                    if ('\u{40}'..='\u{7E}').contains(&d) {
                        break;
                    }
                }
            }
            '\u{9D}' | '\u{90}' | '\u{98}' | '\u{9E}' | '\u{9F}' => skip_string(&mut it),
            '\r' => {
                if it.peek() == Some(&'\n') {
                    // `\r\n` → `\n` (the `\n` is pushed next iteration)
                }
            }
            c if needs_cleaning(c) => {}
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

fn skip_string(it: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(d) = it.next() {
        match d {
            '\u{7}' | '\u{9C}' => return,
            '\u{1B}' => {
                if it.peek() == Some(&'\\') {
                    it.next();
                }
                return;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_controls() {
        let cases = [
            ("plain text\nline 2\tok", "plain text\nline 2\tok"),
            ("a\x1b[31mred\x1b[0m b", "ared b"),
            ("x\x1b]52;c;ZWNobyBoaQ==\x07y", "xy"),
            ("x\x1b]8;;https://evil.example\x1b\\link\x1b]8;;\x1b\\y", "xlinky"),
            ("a\u{9b}31mb", "ab"),
            ("a\u{9d}0;title\u{9c}b", "ab"),
            ("\u{202e}evil\u{202c} \u{2066}x\u{2069}", "evil x"),
            ("a\rb\r\nc", "ab\nc"),
            ("bell\x07 del\x7f nul\0", "bell del nul"),
            ("\x1bPdcs payload\x1b\\after", "after"),
            ("trailing esc \x1b", "trailing esc "),
            ("unterminated \x1b]52;c;AAAA", "unterminated "),
            ("emoji 👩‍💻 and accents é", "emoji 👩‍💻 and accents é"),
        ];
        for (i, want) in cases {
            assert_eq!(clean_text(i), want, "{i:?}");
        }
        assert!(matches!(clean_text("nothing to do"), Cow::Borrowed(_)));
    }
}
