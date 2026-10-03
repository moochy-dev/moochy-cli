//! Fuzzy matching for `/` filters and the command palette: case-insensitive subsequence, every
//! space-separated word must match; consecutive runs and word starts score higher.

/// `None` when `pattern` does not match `text`; higher is better. An empty pattern matches all.
#[must_use]
pub fn score(pattern: &str, text: &str) -> Option<i64> {
    let mut total: i64 = 0;
    for word in pattern.split_whitespace() {
        total = total.saturating_add(word_score(word, text)?);
    }
    Some(total)
}

fn word_score(word: &str, text: &str) -> Option<i64> {
    let mut pat = word.chars().flat_map(char::to_lowercase).peekable();
    let mut s: i64 = 0;
    let mut prev_matched = false;
    let mut prev: Option<char> = None;
    for c in text.chars() {
        let Some(&p) = pat.peek() else { break };
        let lc = c.to_lowercase().next().unwrap_or(c);
        if lc == p {
            pat.next();
            let start = prev.is_none_or(|q| !q.is_alphanumeric());
            s = s.saturating_add(1).saturating_add(if prev_matched { 3 } else { 0 }).saturating_add(if start { 2 } else { 0 });
            prev_matched = true;
        } else {
            prev_matched = false;
        }
        prev = Some(c);
    }
    if pat.peek().is_some() { None } else { Some(s) }
}

#[cfg(test)]
mod tests {
    use super::score;

    #[test]
    fn matches() {
        assert_eq!(score("", "anything"), Some(0));
        assert!(score("dn", "Donations").is_some());
        assert!(score("xyz", "Donations").is_none());
        assert!(score("go don", "Go to Donations").is_some());
        assert!(score("go zz", "Go to Donations").is_none());
        // Word starts and runs beat scattered letters.
        assert!(score("sv", "Served") < score("se", "Served"));
        assert!(score("pa", "Pause donation") > score("pa", "Open alerts"));
    }
}
