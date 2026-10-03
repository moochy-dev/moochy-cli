//! Shared widgets (CONTRACT §20.3): sortable/filterable tables, detail panes, sparklines, gauges,
//! status glyphs, money and time formatting. Owner: mo-tui; view owners may add here in their own
//! files and tell mo-tui.

/// `$12.34` from µ$, rounded down to the cent.
#[must_use]
pub fn dollars(uusd: u64) -> String {
    let cents = uusd / 10_000;
    format!("${}.{:02}", cents / 100, cents % 100)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dollars_from_uusd() {
        assert_eq!(super::dollars(12_345_678), "$12.34");
        assert_eq!(super::dollars(0), "$0.00");
    }
}
