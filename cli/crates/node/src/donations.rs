//! Donations ("Donate tokens", VOICE.md): `moochy donate` and `moochy donations`.
//!
//! The relay knows the user from the authenticated session, never from a field, so the CLI asks
//! the running app (LocalControl `Donations`), which relays the link.proto message on its own
//! session (`ListDonations` / `Donate` / `DonationAction`) and returns the answer as-is.

use crate::node::Node;
use crate::pb::link::{DonateRequest, Donation, DonationActionRequest, ListDonationsRequest, ListDonationsResponse};
use crate::pb::local::{DonationsRequest, DonationsResponse};
use crate::util::{Result, clean, emit, internal, net, usage};
use prost::Message as _;
use serde_json::json;
use std::time::Duration;
use tonic::Status;

/// Node side: relay one call on the authenticated session.
pub async fn relay(node: &Node, r: DonationsRequest) -> std::result::Result<DonationsResponse, Status> {
    if r.request.len() > 16 << 10 {
        return Err(Status::invalid_argument("request too large"));
    }
    let link = node.link_now(Duration::from_secs(5)).await.ok_or_else(|| Status::unavailable("not connected to the Moochy server"))?;
    let mut c = link.client.clone();
    let bad = |_| Status::invalid_argument("malformed request");
    let call = async {
        Ok(match r.op.as_str() {
            "list" => {
                let q = ListDonationsRequest::decode(r.request.as_slice()).map_err(bad)?;
                c.list_donations(crate::link::with_session(&link, q)).await?.into_inner().encode_to_vec()
            }
            "donate" => {
                let q = DonateRequest::decode(r.request.as_slice()).map_err(bad)?;
                c.donate(crate::link::with_session(&link, q)).await?.into_inner().encode_to_vec()
            }
            "action" => {
                let q = DonationActionRequest::decode(r.request.as_slice()).map_err(bad)?;
                let refused = (q.action == "refuse").then(|| q.pledge_id.clone());
                let out = c.donation_action(crate::link::with_session(&link, q)).await?.into_inner().encode_to_vec();
                // A refused request is decided: withdraw the signature request the relay pushed for
                // it now (`pending`, the TUI's Decisions), not at the relay's next push.
                if let Some(id) = refused.filter(|id| !id.is_empty()) {
                    crate::node::lock(&node.approvals).retain(|a| a.pledge_id != id && a.request_id != id);
                }
                out
            }
            _ => return Err(Status::invalid_argument("unknown donations op")),
        })
    };
    let response = tokio::time::timeout(Duration::from_secs(15), call).await.map_err(|_| Status::deadline_exceeded("the server did not answer"))??;
    Ok(DonationsResponse { response })
}

fn status(s: &Status) -> crate::util::Error {
    let m = clean(s.message()).into_owned();
    match s.code() {
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => net(m),
        tonic::Code::InvalidArgument | tonic::Code::NotFound | tonic::Code::AlreadyExists | tonic::Code::FailedPrecondition | tonic::Code::ResourceExhausted => usage(m),
        _ => internal(m),
    }
}

pub(crate) fn call(home: &crate::config::Home, op: &str, request: Vec<u8>) -> Result<Vec<u8>> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| internal(format!("runtime: {e}")))?;
    rt.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.donations(DonationsRequest { op: op.into(), request }).await.map(|r| r.into_inner().response).map_err(|e| status(&e))
    })
}

/// What a donation targets (CONTRACT §19, §24): exactly one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum To {
    Repo,
    Org,
    Person,
}

/// What a donation funds, for people: the project, `org github/acme` or `person github/alice`.
pub(crate) fn target(d: &Donation) -> String {
    if !d.person.is_empty() {
        format!("person {}", clean(&d.person))
    } else if d.org.is_empty() {
        clean(&d.repo_slug).into_owned()
    } else {
        format!("org {}", clean(&d.org))
    }
}

fn donation_json(d: &Donation) -> serde_json::Value {
    json!({"pledge_id": clean(&d.pledge_id), "repo": clean(&d.repo_slug), "org": clean(&d.org), "person": clean(&d.person), "status": clean(&d.status), "monthly_limit_uusd": d.budget_uusd,
        "weekly_limit_uusd": d.weekly_limit_uusd, "daily_limit_uusd": d.daily_limit_uusd, "per_request_limit_uusd": d.per_task_cap_uusd, "spent_uusd": d.spent_uusd, "reserved_uusd": d.reserved_uusd,
        "models": d.models.iter().map(|m| clean(m).into_owned()).collect::<Vec<_>>(), "visibility": clean(&d.visibility), "schedule": clean(&d.schedule)})
}

/// CONTRACT D19: default per-request limit of a donation.
const DEFAULT_PER_REQUEST_UUSD: i64 = 5_000_000;

fn dollars(uusd: i64) -> String {
    format!("${}.{:02}", uusd / 1_000_000, (uusd % 1_000_000) / 10_000)
}

/// `moochy donations [--json]`: this account's donations.
pub fn list(home: &crate::config::Home, json_out: bool) -> Result<()> {
    let b = call(home, "list", ListDonationsRequest::default().encode_to_vec())?;
    let r = ListDonationsResponse::decode(b.as_slice()).map_err(|_| internal("malformed answer"))?;
    for d in &r.donations {
        if json_out {
            emit(&donation_json(d));
        } else {
            let windows = Limits { monthly: d.budget_uusd, weekly: (d.weekly_limit_uusd > 0).then_some(d.weekly_limit_uusd), daily: (d.daily_limit_uusd > 0).then_some(d.daily_limit_uusd) };
            println!("{:<28} {:<9} {} of {} this month{}  ({})", target(d), clean(&d.status), dollars(d.spent_uusd), dollars(d.budget_uusd), windows.extra(), clean(&d.pledge_id));
        }
    }
    if r.donations.is_empty() && !json_out {
        println!("No donations yet: `moochy donate --repo OWNER/NAME --cap $20` (or --org github/ORG, --person github/LOGIN)");
    }
    Ok(())
}

/// A new donation's limits in µ$ (CONTRACT D19a): monthly required, weekly and daily optional.
#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    pub monthly: i64,
    pub weekly: Option<i64>,
    pub daily: Option<i64>,
}

impl Limits {
    /// Positive amounts, daily ≤ weekly ≤ monthly (the relay checks the same).
    fn check(self) -> Result<()> {
        if self.monthly <= 0 {
            return Err(usage("set a monthly limit: --cap $20 (or --budget-uusd N)"));
        }
        if self.weekly.is_some_and(|w| w <= 0) || self.daily.is_some_and(|d| d <= 0) {
            return Err(usage("a weekly or daily limit is more than $0 (leave it out for none)"));
        }
        if self.weekly.is_some_and(|w| w > self.monthly) {
            return Err(usage("the weekly limit cannot be higher than the monthly limit"));
        }
        if self.daily.is_some_and(|d| d > self.weekly.unwrap_or(self.monthly)) {
            return Err(usage(format!("the daily limit cannot be higher than the {} limit", if self.weekly.is_some() { "weekly" } else { "monthly" })));
        }
        Ok(())
    }

    /// `" ($8.00 a week, $2.00 a day)"`, or nothing.
    fn extra(self) -> String {
        let parts: Vec<String> = [(self.weekly, "week"), (self.daily, "day")].iter().filter_map(|(v, w)| v.map(|v| format!("{} a {w}", dollars(v)))).collect();
        if parts.is_empty() { String::new() } else { format!(", {}", parts.join(", ")) }
    }
}

/// `moochy donate --repo OWNER/NAME | --org github/ORG | --person github/LOGIN --cap $N [--yes]`:
/// start donating up to $N a month. The donation waits for the owner's approval (signed with their
/// owner key). An organisation (CONTRACT §19) funds the repos its owner covers; a person (§24)
/// only their own requests on the repos they cover.
pub fn donate(home: &crate::config::Home, slug: &str, to: To, limits: Limits, yes: bool) -> Result<()> {
    limits.check()?;
    let monthly_uusd = limits.monthly;
    let what = match to {
        To::Repo => clean(slug).into_owned(),
        To::Org => format!("the organisation {}", clean(slug)),
        To::Person => format!("{}'s own requests (sponsoring {})", clean(slug.rsplit('/').next().unwrap_or(slug)), clean(slug)),
    };
    let p = crate::style::err();
    eprintln!(
        "Donating tokens to {} up to {} a month{} {}.",
        p.bold(&what),
        p.hi(&dollars(monthly_uusd)),
        limits.extra(),
        p.dim(&format!("(at most {} per request)", dollars(monthly_uusd.min(DEFAULT_PER_REQUEST_UUSD))))
    );
    if !yes {
        use std::io::IsTerminal as _;
        if !std::io::stdin().is_terminal() {
            return Err(usage("pass --yes to donate non-interactively"));
        }
        eprint!("Donate tokens to {what} up to {} a month{}? [y/N] ", dollars(monthly_uusd), limits.extra());
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            return Err(usage("nothing changed"));
        }
    }
    let q = DonateRequest {
        request_id: crate::util::ulid()?,
        // §19, §24: exactly one of repo_slug, org and person.
        repo_slug: if to == To::Repo { slug.into() } else { String::new() },
        org: if to == To::Org { slug.into() } else { String::new() },
        person: if to == To::Person { slug.into() } else { String::new() },
        budget_uusd: monthly_uusd,
        // D19: one request may use at most $5 by default (or the whole monthly limit when smaller).
        per_task_cap_uusd: monthly_uusd.min(DEFAULT_PER_REQUEST_UUSD),
        models: Vec::new(),
        max_effort: String::new(),
        visibility: "pseudonymous".into(),
        schedule: "always".into(),
        weekly_limit_uusd: limits.weekly.unwrap_or(0),
        daily_limit_uusd: limits.daily.unwrap_or(0),
    };
    let b = call(home, "donate", q.encode_to_vec())?;
    let d = Donation::decode(b.as_slice()).map_err(|_| internal("malformed answer"))?;
    let mut v = donation_json(&d);
    if let Some(o) = v.as_object_mut() {
        o.insert("event".into(), json!("donation"));
    }
    emit(&v);
    Ok(())
}

/// `moochy donations pause|resume|stop <id>`.
pub fn action(home: &crate::config::Home, action: &str, pledge_id: &str) -> Result<()> {
    let action = match action {
        "pause" | "resume" => action,
        "stop" => "reclaim",
        _ => return Err(usage("donations pause|resume|stop <id>")),
    };
    let q = DonationActionRequest { pledge_id: pledge_id.into(), action: action.into(), ..DonationActionRequest::default() };
    let b = call(home, "action", q.encode_to_vec())?;
    let d = Donation::decode(b.as_slice()).map_err(|_| internal("malformed answer"))?;
    emit(&donation_json(&d));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Limits;

    #[test]
    fn limits_order_and_sign() {
        let l = |m, w, d| Limits { monthly: m, weekly: w, daily: d }.check().is_ok();
        assert!(l(20, None, None));
        assert!(l(20, Some(8), Some(2)));
        assert!(l(20, Some(20), Some(20)), "equal is fine");
        assert!(l(20, None, Some(20)) && !l(20, None, Some(21)), "daily vs monthly without weekly");
        assert!(!l(0, None, None), "monthly is required");
        assert!(!l(20, Some(21), None), "weekly > monthly");
        assert!(!l(20, Some(8), Some(9)), "daily > weekly");
        assert!(!l(20, Some(0), None) && !l(20, None, Some(-1)), "positive amounts");
    }
}
