//! Gift links and credits (plan 15 §3, §5): `moochy gift create|list|revoke|claim`, `moochy
//! credits [add]` and `moochy donate --credits`. Over the running app's `LinkCall` passthrough,
//! like `moochy box`. Every server string is cleaned before it reaches the terminal.

use crate::config::Home;
use crate::pb::link::{ClaimGiftRequest, CreateGiftRequest, Credits, DonateRequest, Donation, GetCreditsRequest, Gift, ListGiftsRequest, ListGiftsResponse, RevokeGiftRequest};
use crate::util::{Error, Result, clean, emit, fmt_dollars, internal, usage};
use prost::Message as _;
use serde_json::json;
use tonic::{Code, Status};

pub(crate) const CREDITS_OFF: &str = "Credits are off on this relay.";

/// A gift is $1 to $1,000 (plan 15 §3.1, the `gifts` table's CHECK).
const MIN_GIFT_UUSD: i64 = 1_000_000;
const MAX_GIFT_UUSD: i64 = 1_000_000_000;
const MAX_NOTE: usize = 140;
const MAX_EXPIRES_DAYS: u32 = 90;
/// `moochy credits add`: what the web page takes (plan 15 §5.2).
const MIN_ADD_UUSD: u64 = 5_000_000;
const MAX_ADD_UUSD: u64 = 500_000_000;
/// CONTRACT D19: default per-request limit of a donation.
const DEFAULT_PER_REQUEST_UUSD: i64 = 5_000_000;

/// The relay's refusals, in words (plan 15 §3.3); the rest as every `LinkCall`.
fn refusal(op: &str, credits: bool, s: &Status) -> Error {
    let m = clean(s.message()).into_owned();
    let because = |why: &str| usage(format!("{why} ({m})"));
    match (op, s.code()) {
        (_, Code::Unimplemented) if credits => usage(CREDITS_OFF),
        (_, Code::Unimplemented) => usage("this Moochy server has no gift links yet (update pending)"),
        ("claim_gift", Code::NotFound) => usage("this gift link does not work: it is unknown, already used, expired or revoked"),
        ("revoke_gift", Code::NotFound) => usage("no open gift with this id: `moochy gift list` shows yours"),
        (_, Code::FailedPrecondition) if m.starts_with("self_gift") => because("you cannot claim your own gift, or one from an account linked to yours"),
        (_, Code::FailedPrecondition) if m.starts_with("not_eligible") => {
            because("this target cannot take a gift: a public project you claimed on Moochy, not a fork, not archived, at least 30 days old")
        }
        (_, Code::FailedPrecondition) if m.starts_with("already_donating") => because("the giver already donates to this target: pick another"),
        _ => crate::boxes::status(s),
    }
}

fn call<Q: prost::Message, A: prost::Message + Default>(home: &Home, op: &str, credits: bool, q: &Q) -> Result<A> {
    crate::boxes::call_map(home, op, q, |s| refusal(op, credits, s))
}

fn money(uusd: i64) -> String {
    fmt_dollars(u64::try_from(uusd).unwrap_or(0))
}

fn day(ms: i64) -> String {
    crate::journal::utc_day(u64::try_from(ms).unwrap_or(0))
}

/// `20`, `$20.50` → µ$, between $1 and $1,000.
pub fn amount(v: &str) -> Result<i64> {
    let a = crate::util::parse_amount(v).map_err(|e| usage(format!("gift amount (dollars): {e}")))?;
    let a = i64::try_from(a).map_err(|_| usage("the gift amount is too large"))?;
    if !(MIN_GIFT_UUSD..=MAX_GIFT_UUSD).contains(&a) {
        return Err(usage("a gift is $1 to $1,000"));
    }
    Ok(a)
}

/// The bare token of a gift link: `https://HOST/g/{t}` or `{t}`, `t` = 22 base64url characters.
/// Anything else is refused (never sent to the server).
pub fn token(v: &str) -> Result<&str> {
    let v = v.trim();
    let t = match v.strip_prefix("https://") {
        Some(rest) => match rest.split_once('/') {
            Some((host, path)) if !host.is_empty() && !host.contains(['@', '?', '#']) => path.strip_prefix("g/").unwrap_or(""),
            _ => "",
        },
        None => v,
    };
    if t.len() == 22 && t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        Ok(t)
    } else {
        Err(usage("a gift link is https://moochy.dev/g/… (or its 22-character token)"))
    }
}

fn gift_json(g: &Gift) -> serde_json::Value {
    let mut v = json!({"gift_id": clean(&g.gift_id), "source": clean(&g.source), "amount": money(g.amount_uusd), "amount_uusd": g.amount_uusd, "status": clean(&g.status),
        "note": clean(&g.note), "models": g.models.iter().map(|m| clean(m).into_owned()).collect::<Vec<_>>(), "max_effort": clean(&g.max_effort), "visibility": clean(&g.visibility),
        "created_at_ms": g.created_at_ms, "expires_at_ms": g.expires_at_ms, "claimed_at_ms": g.claimed_at_ms, "claimer": clean(&g.claimer), "target": clean(&g.target),
        "pledge_id": clean(&g.pledge_id), "existing": g.existing});
    if !g.url.is_empty()
        && let Some(o) = v.as_object_mut()
    {
        o.insert("url".into(), json!(clean(&g.url)));
    }
    v
}

/// The link, once: stdout carries it alone so it can be piped; the warning goes to stderr.
fn show_link(g: &Gift, json_out: bool) {
    if json_out {
        emit(&gift_json(g));
    } else if g.url.is_empty() {
        eprintln!("Gift {} exists already: its link cannot be shown again. New link: moochy gift revoke {} --replace", clean(&g.gift_id), clean(&g.gift_id));
    } else {
        println!("{}", clean(&g.url));
        eprintln!("Shown once. Anyone with this link can claim it. ({}, {}, expires {})", money(g.amount_uusd), clean(&g.gift_id), day(g.expires_at_ms));
    }
}

/// `moochy gift create AMOUNT [--credits] [--note T] [--models a,b] [--effort E]
/// [--visibility V] [--expires DAYS]`.
pub fn create(home: &Home, mut q: CreateGiftRequest, json_out: bool) -> Result<()> {
    if q.note.chars().count() > MAX_NOTE {
        return Err(usage(format!("--note is at most {MAX_NOTE} characters")));
    }
    if !matches!(q.visibility.as_str(), "public" | "pseudonymous" | "anonymous") {
        return Err(usage("--visibility is public, pseudonymous or anonymous"));
    }
    if q.expires_days > MAX_EXPIRES_DAYS {
        return Err(usage(format!("--expires is 1 to {MAX_EXPIRES_DAYS} days")));
    }
    q.request_id = crate::util::ulid()?;
    let g: Gift = call(home, "create_gift", q.source == "credits", &q)?;
    show_link(&g, json_out);
    Ok(())
}

/// `moochy gift list [--json]`.
pub fn list(home: &Home, json_out: bool) -> Result<()> {
    let r: ListGiftsResponse = call(home, "list_gifts", false, &ListGiftsRequest {})?;
    for g in &r.gifts {
        if json_out {
            emit(&gift_json(g));
            continue;
        }
        let state = match g.status.as_str() {
            "claimed" => format!("claimed by {} for {}", clean(&g.claimer), if g.target == "personal" { "their own use".into() } else { clean(&g.target) }),
            "open" => format!("open, expires {}", day(g.expires_at_ms)),
            s => clean(s).into_owned(),
        };
        let note = if g.note.is_empty() { String::new() } else { format!("  \"{}\"", clean(&g.note)) };
        println!("{:<30} {:>10} {:<7} {state}{note}", clean(&g.gift_id), money(g.amount_uusd), clean(&g.source));
    }
    if r.gifts.is_empty() && !json_out {
        println!("No gifts yet: moochy gift create 20");
    }
    Ok(())
}

/// `moochy gift revoke <gf_…> [--replace]`: the replacement link is shown once.
pub fn revoke(home: &Home, id: &str, replace: bool, json_out: bool) -> Result<()> {
    if !id.starts_with("gf_") || id.len() > 64 {
        return Err(usage("gift revoke <gf_…> (from `moochy gift list`)"));
    }
    let g: Gift = call(home, "revoke_gift", false, &RevokeGiftRequest { gift_id: id.into(), replace })?;
    if replace {
        show_link(&g, json_out);
    } else {
        emit(&json!({"event": "gift_revoked", "gift_id": clean(&g.gift_id), "status": clean(&g.status)}));
    }
    Ok(())
}

/// `moochy gift claim <link|token> …`: the donation the gift made (pending until accepted).
pub fn claim(home: &Home, link: &str, mut q: ClaimGiftRequest) -> Result<Donation> {
    token(link)?.clone_into(&mut q.token);
    let d: Donation = call(home, "claim_gift", false, &q)?;
    let p = crate::style::err();
    let what = crate::donations::total(&d).unwrap_or_else(|| crate::donations::dollars(d.budget_uusd));
    eprintln!("{} {} for {}{}.", p.bold("Gift claimed:"), what, crate::donations::target(&d), crate::donations::served_by(&d));
    let mut v = crate::donations::donation_json(&d);
    if let Some(o) = v.as_object_mut() {
        o.insert("event".into(), json!("gift_claimed"));
    }
    emit(&v);
    Ok(d)
}

/// `moochy credits [--json]`: balance, purchases with fees, allocations with used and left.
pub fn show(home: &Home, json_out: bool) -> Result<()> {
    let c: Credits = call(home, "get_credits", true, &GetCreditsRequest {})?;
    let cents = |c: i64| money(c.checked_mul(10_000).unwrap_or(0));
    if json_out {
        emit(&json!({"available_uusd": c.available_uusd, "held_uusd": c.held_uusd, "allocated_uusd": c.allocated_uusd, "frozen": c.frozen,
            "purchases": c.purchases.iter().map(|p| json!({"id": clean(&p.id), "amount_cents": p.amount_cents, "stripe_fee_cents": p.stripe_fee_cents, "provider_fee_uusd": p.provider_fee_uusd,
                "credits_uusd": p.credits_uusd, "status": clean(&p.status), "paid_at_ms": p.paid_at_ms, "available_at_ms": p.available_at_ms, "refunded_cents": p.refunded_cents})).collect::<Vec<_>>(),
            "allocations": c.allocations.iter().map(|a| json!({"id": clean(&a.id), "target": clean(&a.target), "amount_uusd": a.amount_uusd, "used_uusd": a.used_uusd,
                "left_uusd": a.amount_uusd.saturating_sub(a.used_uusd).max(0), "gift_id": clean(&a.gift_id), "ends_at_ms": a.ends_at_ms, "ended_at_ms": a.ended_at_ms, "pledge_id": clean(&a.pledge_id)})).collect::<Vec<_>>()}));
        return Ok(());
    }
    println!("Credits: {} available, {} held (72 h), {} allocated", money(c.available_uusd), money(c.held_uusd), money(c.allocated_uusd));
    if c.frozen {
        println!("Your credits are frozen (a card dispute or fraud warning): nothing new can be spent.");
    }
    if !c.purchases.is_empty() {
        println!("Purchases:");
    }
    for p in &c.purchases {
        let refunded = if p.refunded_cents > 0 { format!(", {} refunded", cents(p.refunded_cents)) } else { String::new() };
        println!(
            "  {} {} paid {}, card fee {}, provider fee {} -> {} credits, {}{refunded}",
            clean(&p.id),
            day(p.paid_at_ms),
            cents(p.amount_cents),
            cents(p.stripe_fee_cents),
            money(p.provider_fee_uusd),
            money(p.credits_uusd),
            clean(&p.status)
        );
    }
    if !c.allocations.is_empty() {
        println!("Allocations:");
    }
    for a in &c.allocations {
        let target = if a.target == "personal" { "For my own use".into() } else { clean(&a.target) };
        let end = if a.ended_at_ms > 0 { format!("ended {}", day(a.ended_at_ms)) } else { format!("ends {}", day(a.ends_at_ms)) };
        println!("  {} {target}: {}, used {}, left {}, {end}", clean(&a.id), money(a.amount_uusd), money(a.used_uusd), money(a.amount_uusd.saturating_sub(a.used_uusd).max(0)));
    }
    if c.purchases.is_empty() && c.allocations.is_empty() {
        println!("Add credits on the web: moochy credits add 20");
    }
    Ok(())
}

/// `{web}/credits[?amount=N]`, the only place a card is entered.
pub fn add_url(web: &str, amount: Option<&str>) -> Result<String> {
    let Some(a) = amount else { return Ok(format!("{web}/credits")) };
    let a = crate::util::parse_amount(a).map_err(|e| usage(format!("credits add AMOUNT (dollars): {e}")))?;
    if !(MIN_ADD_UUSD..=MAX_ADD_UUSD).contains(&a) {
        return Err(usage("credits are added $5 to $500 at a time"));
    }
    Ok(format!("{web}/credits?amount={}", fmt_dollars(a).trim_start_matches('$')))
}

/// `moochy credits add [AMOUNT]`: opens the browser at the web page; prints the URL too.
pub fn add(home: &Home, amount: Option<&str>) -> Result<()> {
    let url = add_url(&crate::decisions::web_origin(home), amount)?;
    println!("{url}");
    if !crate::login::browse(&url) {
        eprintln!("Open this page to add credits (cards are only ever entered there).");
    }
    Ok(())
}

/// `moochy donate --credits AMOUNT --repo P | --org ORG | --person PERSON [--yes]`: a one-off total
/// from the credits balance, served by Moochy Credits (plan 15 §5.2).
pub fn donate(home: &Home, slug: &str, to: crate::donations::To, amount: &str, yes: bool) -> Result<()> {
    use crate::donations::To;
    let a = crate::util::parse_amount(amount).map_err(|e| usage(format!("--credits (dollars): {e}")))?;
    let a = i64::try_from(a).ok().filter(|&a| a > 0).ok_or_else(|| usage("--credits is more than $0"))?;
    let what = clean(slug);
    if !yes {
        use std::io::IsTerminal as _;
        if !std::io::stdin().is_terminal() {
            return Err(usage("pass --yes to donate non-interactively"));
        }
        eprint!("Give {} of your credits to {what} (a one-off total, served by Moochy Credits)? [y/N] ", money(a));
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            return Err(usage("nothing changed"));
        }
    }
    let q = DonateRequest {
        request_id: crate::util::ulid()?,
        repo_slug: if to == To::Repo { slug.into() } else { String::new() },
        org: if to == To::Org { slug.into() } else { String::new() },
        person: if to == To::Person { slug.into() } else { String::new() },
        budget_uusd: a,
        per_task_cap_uusd: a.min(DEFAULT_PER_REQUEST_UUSD),
        visibility: "pseudonymous".into(),
        credits: true,
        ..DonateRequest::default()
    };
    let b = crate::donations::call(home, "donate", q.encode_to_vec())?;
    let d = Donation::decode(b.as_slice()).map_err(|_| internal("malformed answer"))?;
    let mut v = crate::donations::donation_json(&d);
    if let Some(o) = v.as_object_mut() {
        o.insert("event".into(), json!("donation"));
    }
    emit(&v);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_and_tokens() {
        let t = "AbCdEfGhIjKlMnOpQrSt_-";
        assert_eq!(token(t).unwrap(), t);
        assert_eq!(token(&format!("https://moochy.dev/g/{t}")).unwrap(), t);
        assert_eq!(token(&format!(" https://relay.test:8443/g/{t}\n")).unwrap(), t);
        for bad in [
            format!("http://moochy.dev/g/{t}"),
            format!("https://moochy.dev/x/{t}"),
            format!("https:///g/{t}"),
            format!("https://moochy.dev/g/{t}?a=1"),
            format!("https://moochy.dev/g/{t}/"),
            format!("https://evil@moochy.dev/g/{t}"),
            "AbCdEfGhIjKlMnOpQrSt_".into(),
            "AbCdEfGhIjKlMnOpQrSt_=".into(),
            String::new(),
        ] {
            assert!(token(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn gift_amounts() {
        assert_eq!(amount("20").unwrap(), 20_000_000);
        assert_eq!(amount("$1").unwrap(), 1_000_000);
        assert_eq!(amount("1000").unwrap(), 1_000_000_000);
        assert!(amount("0.99").is_err() && amount("1000.01").is_err() && amount("-5").is_err() && amount("x").is_err());
    }

    #[test]
    fn credits_page() {
        let w = "https://moochy.dev";
        assert_eq!(add_url(w, None).unwrap(), "https://moochy.dev/credits");
        assert_eq!(add_url(w, Some("20")).unwrap(), "https://moochy.dev/credits?amount=20.00");
        assert_eq!(add_url(w, Some("$12.5")).unwrap(), "https://moochy.dev/credits?amount=12.50");
        assert!(add_url(w, Some("4.99")).is_err() && add_url(w, Some("501")).is_err());
    }

    #[test]
    fn refusals_in_words() {
        let r = |op, credits, code, m| refusal(op, credits, &Status::new(code, m)).msg;
        assert_eq!(r("get_credits", true, Code::Unimplemented, ""), CREDITS_OFF);
        assert!(r("claim_gift", false, Code::NotFound, "gift not found").starts_with("this gift link does not work"));
        assert!(r("claim_gift", false, Code::FailedPrecondition, "self_gift: same account").contains("your own gift"));
        assert!(r("claim_gift", false, Code::FailedPrecondition, "already_donating").contains("pick another"));
        assert!(r("claim_gift", false, Code::FailedPrecondition, "not_eligible: fork").contains("not a fork"));
    }
}
