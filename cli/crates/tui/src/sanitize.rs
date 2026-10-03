//! Terminal-safe text (CONTRACT §20.4, E118): every server- or peer-provided string is cleaned
//! before it reaches the terminal, so a handle, description or model name cannot carry CSI/OSC/C1
//! escape sequences (cursor moves, title changes, OSC 52 clipboard writes, hyperlinks).

/// Replaces every control character (C0 except none, DEL, C1) with U+FFFD and drops bidi
/// overrides and zero-width characters that could disguise text.
#[must_use]
pub fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'))
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::clean;

    #[test]
    fn escapes_are_inert() {
        assert_eq!(clean("a\u{1b}[2Jb"), "a\u{FFFD}[2Jb");
        assert_eq!(clean("x\u{1b}]52;c;Zm9v\u{7}y"), "x\u{FFFD}]52;c;Zm9v\u{FFFD}y");
        assert_eq!(clean("c1\u{9b}31m"), "c1\u{FFFD}31m");
        assert_eq!(clean("ab\u{202E}cd"), "abcd");
        assert_eq!(clean("plain @alice"), "plain @alice");
    }
}
