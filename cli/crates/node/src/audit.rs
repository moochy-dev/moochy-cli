//! `moochy audit --provider` (07 §2): reconcile what this device served for others (the durable
//! journal) with the provider's own usage report.
//!
//! Without a file: per UTC day and model, the tasks served and the cost the donor's receipts
//! billed. With `--from-file usage.csv` (the provider's usage export reduced to
//! `date,model,cost_usd` rows, header optional): per day, journal vs provider and the gap; a day
//! whose provider cost exceeds the journal by more than 1% (and 1 cent) is flagged, since that is
//! spend Moochy did not account for.

use crate::pb::local::JournalEntry;
use crate::util::{Result, fmt_dollars, parse_dollars, usage};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// (day, model) → (tasks, µ$) for tasks served as a worker.
pub fn served(entries: &[JournalEntry]) -> BTreeMap<(String, String), (u64, u64)> {
    let mut m: BTreeMap<(String, String), (u64, u64)> = BTreeMap::new();
    for e in entries.iter().filter(|e| e.role == "worker") {
        let day = crate::journal::utc_day(u64::try_from(e.t_ms).unwrap_or(0));
        let v = m.entry((day, e.model.clone())).or_insert((0, 0));
        v.0 = v.0.saturating_add(1);
        v.1 = v.1.saturating_add(u64::try_from(e.cost_uusd).unwrap_or(0));
    }
    m
}

/// `date,model,cost_usd` rows → day → µ$ (header and blank lines skipped; quoted fields allowed).
pub fn provider_csv(text: &str) -> Result<BTreeMap<String, u64>> {
    let mut m: BTreeMap<String, u64> = BTreeMap::new();
    for (i, line) in text.lines().enumerate().take(1_000_000) {
        let f: Vec<&str> = line.split(',').map(|x| x.trim().trim_matches('"')).collect();
        let (Some(day), Some(cost)) = (f.first(), f.get(2)) else { continue };
        if day.is_empty() || day.eq_ignore_ascii_case("date") {
            continue;
        }
        let day: String = day.chars().take(10).collect();
        if day.len() != 10 || !day.bytes().enumerate().all(|(j, c)| if j == 4 || j == 7 { c == b'-' } else { c.is_ascii_digit() }) {
            return Err(usage(format!("line {}: date must be YYYY-MM-DD", i.saturating_add(1))));
        }
        let uusd = parse_dollars(cost.trim_start_matches('$')).ok_or_else(|| usage(format!("line {}: cost_usd is not an amount", i.saturating_add(1))))?;
        let v = m.entry(day).or_insert(0);
        *v = v.saturating_add(uusd);
    }
    Ok(m)
}

/// The report: rows per day (and per model without a provider file), plus flagged days.
pub fn report(entries: &[JournalEntry], provider: Option<&BTreeMap<String, u64>>) -> Value {
    let s = served(entries);
    let Some(p) = provider else {
        let rows: Vec<Value> = s.iter().map(|((d, m), (n, c))| json!({"day": d, "model": m, "tasks": n, "billed": fmt_dollars(*c)})).collect();
        return json!({"served": rows});
    };
    let mut days: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for ((d, _), (n, c)) in &s {
        let v = days.entry(d.as_str()).or_insert((0, 0));
        v.0 = v.0.saturating_add(*n);
        v.1 = v.1.saturating_add(*c);
    }
    for d in p.keys() {
        days.entry(d.as_str()).or_insert((0, 0));
    }
    let mut flagged = Vec::new();
    let rows: Vec<Value> = days
        .iter()
        .map(|(d, (n, journal))| {
            let prov = p.get(*d).copied().unwrap_or(0);
            let over = prov.saturating_sub(*journal);
            // Unaccounted spend: more than 1% of the journal and more than one cent.
            let flag = over > 10_000 && over.saturating_mul(100) > *journal;
            if flag {
                flagged.push(json!(d));
            }
            json!({"day": d, "tasks": n, "journal": fmt_dollars(*journal), "provider": fmt_dollars(prov), "unaccounted": fmt_dollars(over), "flag": flag})
        })
        .collect();
    json!({"days": rows, "flagged": flagged})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile() {
        let e = |day_ms: u64, model: &str, c: i64, role: &str| JournalEntry { t_ms: i64::try_from(day_ms).unwrap(), role: role.into(), model: model.into(), cost_uusd: c, ..JournalEntry::default() };
        let d1 = 1_790_870_400_000u64; // 2026-10-01
        let d2 = d1 + 86_400_000;
        let j = vec![e(d1, "m", 1_000_000, "worker"), e(d1, "m", 500_000, "worker"), e(d2, "m", 2_000_000, "worker"), e(d2, "m", 9_000_000, "gateway")];
        let r = report(&j, None);
        assert_eq!(r["served"][0]["tasks"], 2, "gateway tasks are not served work");
        let p = provider_csv("date,model,cost_usd\n2026-10-01,m,1.50\n\"2026-10-02\",m,$2.30\n2026-10-03,m,0.004\n").unwrap();
        let r = report(&j, Some(&p));
        assert_eq!(r["flagged"], json!(["2026-10-02"]), "{r}");
        assert_eq!(r["days"][1]["unaccounted"], "$0.30");
        assert!(provider_csv("01/10/2026,m,1\n").is_err());
    }
}
