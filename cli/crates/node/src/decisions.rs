//! `moochy decisions` (CONTRACT §16.6): the donations offered to the projects you own, waiting
//! or decided, with their trail (who decided, when, how, the key-log index).
//!
//! - `moochy decisions [--repo P] [--json]`: pending requests first, then history.
//! - `moochy decisions refuse <id> [--reason TEXT] [--yes]`: decline a pending request (the
//!   reason, ≤ 280 characters, is shown to the donor).
//! - Accepting needs the owner's signature: on the web with a passkey (`/decide/<id>`, printed
//!   here), or `moochy accept <donor> --repo P` with a CLI owner key.
//!
//! Over the running app's Donations passthrough: `ListDonations{as_owner}` and
//! `DonationAction{refuse}`. A relay that cannot list as owner does not echo `as_owner`, and
//! its answer (the user's OWN donations) is refused rather than shown as decisions.

use crate::config::Home;
use crate::pb::link::{DonationActionRequest, ListDonationsRequest, ListDonationsResponse, Donation};
use crate::util::{Result, clean, emit, fmt_dollars, internal, usage};
use prost::Message as _;
use serde_json::json;

const MAX_REASON: usize = 280;

/// Where the owner decides on the web: the site of the default relay, else the relay itself
/// (development relays serve the web on the link's port).
pub(crate) fn web_origin(home: &Home) -> String {
    let cfg = home.load().unwrap_or_default();
    match cfg.relay.as_deref().map(crate::tls::Origin::parse) {
        Some(Ok(o)) if o.url() != crate::config::DEFAULT_RELAY => o.url(),
        _ => "https://moochy.dev".into(),
    }
}

fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn decision_json(d: &Donation, origin: &str) -> serde_json::Value {
    let money = |v: i64| fmt_dollars(u64::try_from(v).unwrap_or(0));
    let mut v = json!({"pledge_id": clean(&d.pledge_id), "repo": clean(&d.repo_slug), "org": clean(&d.org), "person": clean(&d.person), "donor": clean(&d.donor), "status": clean(&d.status),
        "monthly_limit": money(d.budget_uusd), "per_request_limit": money(d.per_task_cap_uusd), "models": d.models.iter().map(|m| clean(m).into_owned()).collect::<Vec<_>>(),
        "created_at_ms": d.created_at_ms,
        "events": d.events.iter().map(|e| json!({"event": clean(&e.event), "via": clean(&e.via), "at_ms": e.at_ms, "reason": clean(&e.reason), "log_index": e.log_index})).collect::<Vec<_>>()});
    if d.status == "pending"
        && let Some(o) = v.as_object_mut()
    {
        o.insert("expires_at_ms".into(), json!(d.expires_at_ms));
        o.insert("decide_url".into(), json!(format!("{origin}/decide/{}", clean(&d.pledge_id))));
    }
    v
}

/// Decisions to show: those of project `slug` (the server filters), or of organisation or person
/// `org` (filtered here: the link has no org filter; GitHub and GitLab share one namespace for
/// users and orgs, so one path never names both).
fn fetch(home: &Home, slug: Option<&str>, org: Option<&str>) -> Result<Vec<Donation>> {
    let q = ListDonationsRequest { as_owner: true, repo_slug: slug.unwrap_or_default().into() };
    let b = crate::donations::call(home, "list", q.encode_to_vec())?;
    let r = ListDonationsResponse::decode(b.as_slice()).map_err(|_| internal("malformed answer"))?;
    if !r.as_owner {
        return Err(usage("the Moochy server cannot list donation decisions yet (update pending): decide on the web, Activity → Decisions"));
    }
    Ok(r.donations.into_iter().filter(|d| org.is_none_or(|o| d.org.eq_ignore_ascii_case(o) || d.person.eq_ignore_ascii_case(o))).collect())
}

/// `moochy decisions [--repo P | --org github/ORG] [--json]`.
pub fn list(home: &Home, slug: Option<&str>, org: Option<&str>, json_out: bool) -> Result<()> {
    let mut v = fetch(home, slug, org)?;
    // Waiting first (oldest first), then the rest (newest first).
    v.sort_by_key(|d| if d.status == "pending" { (0, d.created_at_ms) } else { (1, d.created_at_ms.saturating_neg()) });
    let origin = web_origin(home);
    for d in &v {
        if json_out {
            emit(&decision_json(d, &origin));
            continue;
        }
        let who = if d.donor.is_empty() { "a hidden donor".into() } else { clean(&d.donor) };
        let line = format!("{:<28} {:<9} {who}, up to {} a month ({})", crate::donations::target(d), clean(&d.status), fmt_dollars(u64::try_from(d.budget_uusd).unwrap_or(0)), clean(&d.pledge_id));
        println!("{line}");
        if d.status == "pending" {
            println!("    accept with your passkey: {origin}/decide/{}   refuse: moochy decisions refuse {} [--reason TEXT]", clean(&d.pledge_id), clean(&d.pledge_id));
        }
        for e in &d.events {
            let idx = if e.log_index > 0 { format!(", key log #{}", e.log_index) } else { String::new() };
            let why = if e.reason.is_empty() { String::new() } else { format!(": {}", clean(&e.reason)) };
            println!("    {} {} via {}{idx}{why}", crate::journal::utc_day(u64::try_from(e.at_ms).unwrap_or(0)), clean(&e.event), clean(&e.via));
        }
    }
    if v.is_empty() && !json_out {
        println!("No donation requests for your projects yet.");
    }
    Ok(())
}

/// `moochy decisions refuse <id> [--reason TEXT] [--yes]`.
pub fn refuse(home: &Home, id: &str, reason: Option<&str>, yes: bool) -> Result<()> {
    if !valid_id(id) {
        return Err(usage("decisions refuse <id> (from `moochy decisions`)"));
    }
    let reason = reason.unwrap_or_default().trim();
    if reason.chars().count() > MAX_REASON {
        return Err(usage(format!("--reason is at most {MAX_REASON} characters (the donor sees it)")));
    }
    if !yes {
        use std::io::IsTerminal as _;
        if !std::io::stdin().is_terminal() {
            return Err(usage("pass --yes to refuse non-interactively"));
        }
        eprint!("Refuse donation request {}? The donor is told{}. [y/N] ", clean(id), if reason.is_empty() { "" } else { ", with your reason" });
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            return Err(usage("nothing changed"));
        }
    }
    let q = DonationActionRequest { pledge_id: id.into(), action: "refuse".into(), reason: reason.into(), ..DonationActionRequest::default() };
    let b = crate::donations::call(home, "action", q.encode_to_vec())?;
    let d = Donation::decode(b.as_slice()).map_err(|_| internal("malformed answer"))?;
    if d.status != "declined" {
        return Err(usage(format!("the server did not refuse it (status {}): an old server may not support refusing from the CLI", clean(&d.status))));
    }
    emit(&json!({"event": "donation_refused", "pledge_id": clean(&d.pledge_id), "repo": clean(&d.repo_slug), "org": clean(&d.org)}));
    Ok(())
}

/// `moochy decisions accept <id>`: the owner signature happens on the web (passkey).
pub fn accept_link(home: &Home, id: &str) -> Result<()> {
    if !valid_id(id) {
        return Err(usage("decisions accept <id> (from `moochy decisions`)"));
    }
    let url = format!("{}/decide/{id}", web_origin(home));
    emit(&json!({"event": "decide_on_web", "pledge_id": id, "decide_url": url}));
    eprintln!("Accepting a donor is signed with your passkey: open {url}\n(with a CLI owner key: moochy accept <donor> --repo PROJECT | --org github/ORG)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_rows_carry_the_decide_link() {
        let d = Donation { pledge_id: "pl_01J".into(), repo_slug: "acme/widget".into(), status: "pending".into(), donor: "\u{1b}[31malice".into(), budget_uusd: 20_000_000, ..Donation::default() };
        let v = decision_json(&d, "https://moochy.dev");
        assert_eq!(v["decide_url"], "https://moochy.dev/decide/pl_01J");
        assert!(!v["donor"].as_str().unwrap().contains('\u{1b}'), "donor names are cleaned");
        let done = decision_json(&Donation { status: "active".into(), ..d }, "https://moochy.dev");
        assert!(done.get("decide_url").is_none());
        assert!(valid_id("pl_01J") && !valid_id("../x") && !valid_id(""));
    }
}
