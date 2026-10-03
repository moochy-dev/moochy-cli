//! `NodeSource` (CONTRACT §20.4): the dashboard's data over `node.sock` (LocalControl). It lives in
//! the node crate so `moochy-tui` stays UI-only (no gRPC, no cycle). Blocking calls, each bounded
//! by [`CALL`]; the TUI calls them off its UI thread. Relay-backed parts (donations, decisions,
//! boxes) are left empty when the relay does not answer: only a missing node is an error.

use crate::config::Home;
use crate::pb::link::{
    Donation, DonationActionRequest, ListBoxesRequest, ListBoxesResponse, ListDevicesRequest, ListDevicesResponse, ListDonationsRequest, ListDonationsResponse, ListOwnedRequest, ListOwnedResponse, RevokeBoxRequest,
};
use crate::pb::local::local_control_client::LocalControlClient;
use crate::pb::local::{DonationsRequest, JournalEntry, JournalRequest, LinkCallRequest, PendingRequest, StatusRequest, WatchRequest};
use moochy_tui::model::{self, Snapshot};
use moochy_tui::source::{Action, ActionResult, Source, SourceEvent};
use prost::Message as _;
use std::future::Future;
use std::sync::mpsc::SyncSender;
use std::time::Duration;
use tonic::transport::Channel;

const CALL: Duration = Duration::from_secs(5);
/// Watch events arriving this soon after one are folded into the same refresh.
const COALESCE: Duration = Duration::from_millis(150);
const MAX_SERVED: usize = 200;
const DAYS: usize = 30;
const DAY_MS: u64 = 86_400_000;

type Client = LocalControlClient<Channel>;

pub struct NodeSource {
    home: Home,
    rt: tokio::runtime::Runtime,
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| format!("runtime: {e}"))
}

async fn bounded<T, E: std::fmt::Display>(f: impl Future<Output = Result<tonic::Response<T>, E>>) -> Result<T, String> {
    match tokio::time::timeout(CALL, f).await {
        Ok(Ok(r)) => Ok(r.into_inner()),
        Ok(Err(e)) => Err(crate::util::clean(&e.to_string()).into_owned()),
        Err(_) => Err("the Moochy app did not answer in time".into()),
    }
}

async fn connect(home: &Home) -> Result<Client, String> {
    crate::ctl::connect(&home.socket_path()).await.map_err(|e| e.to_string())
}

fn ms(t: i64) -> u64 {
    u64::try_from(t).unwrap_or(0)
}

fn uusd(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

async fn donations(c: &mut Client, as_owner: bool) -> Vec<Donation> {
    let q = ListDonationsRequest { as_owner, ..ListDonationsRequest::default() };
    let Ok(r) = bounded(c.donations(DonationsRequest { op: "list".into(), request: q.encode_to_vec() })).await else { return Vec::new() };
    ListDonationsResponse::decode(r.response.as_slice()).map(|l| l.donations).unwrap_or_default()
}

/// One relay read through the node's session (`LinkCall`); `None` when the relay or the node
/// does not answer (an older relay without the RPC included).
async fn link_call<Q: prost::Message, A: prost::Message + Default>(c: &mut Client, op: &str, q: Q) -> Option<A> {
    let r = bounded(c.link_call(LinkCallRequest { op: op.into(), request: q.encode_to_vec() })).await.ok()?;
    A::decode(r.response.as_slice()).ok()
}

async fn journal(c: &mut Client) -> Vec<JournalEntry> {
    let Ok(mut s) = bounded(c.journal(JournalRequest { follow: false })).await else { return Vec::new() };
    let mut v = Vec::new();
    // The node keeps a bounded journal (512) and ends the stream: bounded by the same timeout.
    while let Ok(Ok(Some(e))) = tokio::time::timeout(CALL, s.message()).await {
        v.push(e);
    }
    v
}

/// Per-day sums (oldest first) of the last [`DAYS`] days.
fn per_day(entries: &[JournalEntry], role: &str, now: u64) -> Vec<u64> {
    let mut d = vec![0u64; DAYS];
    for e in entries.iter().filter(|e| e.role == role) {
        let age = now.saturating_sub(ms(e.t_ms)).checked_div(DAY_MS).and_then(|a| usize::try_from(a).ok());
        if let Some(slot) = age.and_then(|a| DAYS.checked_sub(a)).and_then(|i| i.checked_sub(1)).and_then(|i| d.get_mut(i)) {
            *slot = slot.saturating_add(uusd(e.cost_uusd));
        }
    }
    d
}

#[allow(clippy::too_many_lines, reason = "one mapping per tab, in tab order")]
async fn fetch(home: &Home, c: &mut Client) -> Result<Snapshot, String> {
    let st = bounded(c.status(StatusRequest {})).await?;
    let pending = bounded(c.pending(PendingRequest {})).await.unwrap_or_default();
    // Relay-backed parts only while the link is up (else each would wait for it), in parallel.
    let (mine, owned, boxes, devices, targets) = if st.link_state == "up" {
        let (mut c1, mut c2, mut c3, mut c4, mut c5) = (c.clone(), c.clone(), c.clone(), c.clone(), c.clone());
        let (m, o, b, d, t) = tokio::join!(
            donations(&mut c1, false),
            donations(&mut c2, true),
            link_call::<_, ListBoxesResponse>(&mut c3, "list_boxes", ListBoxesRequest::default()),
            link_call::<_, ListDevicesResponse>(&mut c4, "list_devices", ListDevicesRequest::default()),
            link_call::<_, ListOwnedResponse>(&mut c5, "list_owned", ListOwnedRequest::default())
        );
        (m, o, b.map(|l| l.boxes).unwrap_or_default(), d.map(|l| l.devices).unwrap_or_default(), t.map(|l| l.owned))
    } else {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), None)
    };
    let entries = journal(c).await;
    let now = crate::util::now_ms();
    let cfg = home.load().ok();
    let mut s = Snapshot {
        me: model::Me {
            handle: String::new(),
            pseudonym: cfg.as_ref().and_then(|c| c.pseudonym.clone()).unwrap_or_default(),
            relay: st.relay.clone(),
            // ponytail: the relay serves the web on its own origin (BaseURL); a separate web base when that changes.
            web: st.relay.clone(),
            connected: st.link_state == "up",
            roles: st.roles.clone(),
            // ponytail: Status has only `locked`; mechanisms and failures once the node reports them.
            lockdown: if st.locked { model::Lockdown::Enforced(String::new()) } else { model::Lockdown::Unknown },
        },
        ..Snapshot::default()
    };
    s.donations = mine
        .iter()
        .map(|d| model::Donation {
            id: d.pledge_id.clone(),
            target: [&d.org, &d.person].into_iter().find(|t| !t.is_empty()).unwrap_or(&d.repo_slug).clone(),
            org: !d.org.is_empty(),
            person: d.person.clone(),
            status: d.status.clone(),
            budget_uusd: uusd(d.budget_uusd),
            per_task_cap_uusd: uusd(d.per_task_cap_uusd),
            spent_uusd: uusd(d.spent_uusd),
            schedule: d.schedule.clone(),
            models: d.models.clone(),
            // ponytail: the link's Donation has no per-project split yet (integrator request).
            per_repo_uusd: d.per_repo.iter().map(|r| (r.repo_slug.clone(), uusd(r.spent_uusd))).collect(),
            ..model::Donation::default()
        })
        .collect();
    // Decisions: the trail of every donation to my projects; projects: grouped from the same list.
    for d in &owned {
        let target = [&d.org, &d.person].into_iter().find(|t| !t.is_empty()).unwrap_or(&d.repo_slug).clone();
        for e in &d.events {
            s.decisions.push(model::Decision { at_ms: ms(e.at_ms), target: target.clone(), donor: d.donor.clone(), event: e.event.clone(), via: e.via.clone(), reason: e.reason.clone() });
        }
        if d.org.is_empty() && d.person.is_empty() {
            if !s.projects.iter().any(|p| p.slug == d.repo_slug) {
                s.projects.push(model::Project { slug: d.repo_slug.clone(), ..model::Project::default() });
            }
            let Some(p) = s.projects.iter_mut().find(|p| p.slug == d.repo_slug) else { continue };
            if d.status == "pending" {
                p.pending = p.pending.saturating_add(1);
            } else {
                p.donors = p.donors.saturating_add(1);
            }
            p.month_uusd = p.month_uusd.saturating_add(uusd(d.spent_uusd));
        }
    }
    s.decisions.sort_by_key(|d| std::cmp::Reverse(d.at_ms));
    // What I own, as the relay counts it (§20): replaces the projects grouped above when answered.
    // ponytail: person profiles (m_) have no tab in the model yet; listed once mo-tui adds one.
    if let Some(targets) = targets {
        s.projects = targets
            .iter()
            .filter(|t| t.id.starts_with("r_"))
            .map(|t| model::Project {
                id: t.id.clone(),
                slug: t.path.clone(),
                donors: u32::try_from(t.donors).unwrap_or(0),
                pending: u32::try_from(t.pending).unwrap_or(0),
                month_uusd: uusd(t.month_uusd),
                goal_uusd: uusd(t.goal_uusd),
                members: Vec::new(),
                funded_by: t.funded_by.clone(),
                paused_since_ms: ms(t.paused_since_ms),
            })
            .collect();
        s.orgs = targets
            .iter()
            .filter(|t| t.id.starts_with("o_"))
            .map(|t| model::Org {
                id: t.id.clone(),
                path: t.path.clone(),
                covered: t.covered.iter().map(|r| model::CoveredRepo { slug: r.repo_slug.clone(), used_uusd: uusd(r.used_uusd), share_cap_uusd: uusd(r.share_cap_uusd) }).collect(),
                donors: u32::try_from(t.donors).unwrap_or(0),
                month_uusd: uusd(t.month_uusd),
                paused_since_ms: ms(t.paused_since_ms),
                ..model::Org::default()
            })
            .collect();
    }
    for c in &pending.claims {
        if let Some(p) = s.projects.iter_mut().find(|p| p.slug == c.path) {
            p.paused_since_ms = ms(c.paused_since_ms);
        }
    }
    // Standing offers (`remove:` …) are actions, not things waiting (as `moochy pending`).
    s.pending = pending
        .requests
        .iter()
        .filter(|q| !crate::cli::STANDING.iter().any(|p| q.request_id.starts_with(p)))
        .map(|q| model::Pending {
            request_id: q.request_id.clone(),
            kind: q.kind.clone(),
            target: if q.org_path.is_empty() { q.repo_slug.clone() } else { q.org_path.clone() },
            subject: if q.subject_username.is_empty() { q.subject.clone() } else { q.subject_username.clone() },
            summary: q.kind.clone(),
            created_at_ms: ms(q.issued_at_ms),
            ..model::Pending::default()
        })
        .chain(owned.iter().filter(|d| d.status == "pending").map(|d| model::Pending {
            request_id: d.pledge_id.clone(),
            kind: "DONATION_REQUEST".into(),
            target: [&d.org, &d.person].into_iter().find(|t| !t.is_empty()).unwrap_or(&d.repo_slug).clone(),
            subject: d.donor.clone(),
            summary: format!("{} µ$/month", d.budget_uusd),
            created_at_ms: ms(d.created_at_ms),
            ..model::Pending::default()
        }))
        .collect();
    // Settings: what `moochy config show` prints (the config file holds no secret), plus the doors.
    if let Some(serde_json::Value::Object(m)) = cfg.as_ref().and_then(|c| serde_json::to_value(c).ok()) {
        s.config = m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, v.as_str().map_or_else(|| v.to_string(), str::to_owned))).collect();
    }
    s.config.push(("gateway_url".into(), st.gateway_url.clone()));
    s.config.push(("mcp_url".into(), st.mcp_url.clone()));
    s.devices = devices
        .iter()
        .map(|d| model::Device { id: d.device_id.clone(), name: d.name.clone(), roles: d.roles.clone(), online: d.online || d.device_id == st.device_id, this_device: d.device_id == st.device_id })
        .collect();
    // An older relay (or none): at least this device.
    if !s.devices.iter().any(|d| d.this_device) {
        s.devices.push(model::Device { id: st.device_id.clone(), name: "this device".into(), roles: st.roles.clone(), online: true, this_device: true });
    }
    s.boxes = boxes
        .iter()
        .filter(|b| !b.revoked)
        .map(|b| model::BoxDevice { id: b.device_id.clone(), project: b.repo_slug.clone(), expires_at_ms: ms(b.expires_at_ms), online: b.online })
        .collect();
    s.keys = st.keys.iter().map(|k| model::ProviderKey { provider: k.provider.clone(), present: true, models: k.models.clone() }).collect();
    s.alerts = st
        .alerts
        .iter()
        .map(|a| {
            let text = serde_json::from_str::<serde_json::Value>(a).ok().and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_owned)).unwrap_or_default();
            model::Alert { level: "error".into(), text }
        })
        .collect();
    if st.paused {
        s.alerts.push(model::Alert { level: "warn".into(), text: "serving is paused on this device (moochy resume)".into() });
    }
    s.donated_per_day_uusd = per_day(&entries, "worker", now);
    s.used_per_day_uusd = per_day(&entries, "gateway", now);
    s.served = entries
        .iter()
        .rev()
        .take(MAX_SERVED)
        .map(|e| model::Served {
            at_ms: ms(e.t_ms),
            direction: if e.role == "worker" { "served".into() } else { "used".into() },
            project: e.repo.clone(),
            model: e.model.clone(),
            tokens_in: e.tokens_in,
            tokens_out: e.tokens_out,
            cost_uusd: uusd(e.cost_uusd),
            latency_ms: u64::from(e.ms),
            outcome: e.status.clone(),
        })
        .collect();
    s.activity = entries.iter().rev().take(MAX_SERVED).map(|e| model::Activity { at_ms: ms(e.t_ms), text: format!("{} {} {} {}", e.role, e.repo, e.model, e.status), ..model::Activity::default() }).collect();
    Ok(s)
}

/// A donor or member name safe as a CLI argument: a handle, pseudonym or device id. Relay-provided:
/// never an option (`--yes` would skip the confirmation), always after `--`.
fn name_arg(s: &str) -> Option<String> {
    let ok = (1..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) && s.bytes().next().is_some_and(|c| c.is_ascii_alphanumeric());
    ok.then(|| s.to_owned())
}

/// A person profile (`github/LOGIN`, `gitlab/USERNAME`), canonical, or nothing.
fn person_path(p: &str) -> Option<String> {
    crate::config::canonical_org(p).filter(|c| c.matches('/').count() == 1)
}

fn org_args(org: &str, repo: &str, op: &str) -> Option<Vec<String>> {
    let org = crate::config::canonical_org(org)?;
    let repo = crate::config::canonical_slug(repo)?;
    Some(vec!["org".into(), op.into(), "--org".into(), org, "--".into(), repo])
}

/// The CLI command that answers a pending request (`moochy pending` / `decisions`), its values
/// validated: the TUI runs it in the foreground, with the CLI's own checks and confirmation.
fn accept_args(id: &str, pending: &[crate::pb::local::SignResponse], owned: &[Donation]) -> Option<Vec<String>> {
    let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<String>>();
    if let Some(q) = pending.iter().find(|q| q.request_id == id) {
        let who = if q.subject_username.is_empty() { &q.subject } else { &q.subject_username };
        let org = (!q.org_path.is_empty()).then(|| crate::config::canonical_org(&q.org_path)).flatten();
        let person = (!q.person_path.is_empty()).then(|| person_path(&q.person_path)).flatten();
        let slug = crate::config::canonical_slug(&q.repo_slug);
        if let Some(p) = person {
            return match (q.kind.as_str(), slug) {
                ("DONOR_APPROVED", _) => Some(v(&["accept", "--person", &p, "--", &name_arg(who)?])),
                ("PERSON_CLAIMED", _) => Some(v(&["claim", "--person", &p])),
                ("PERSON_REPO_ADDED", Some(r)) => Some(v(&["person", "add", "--person", &p, "--", &r])),
                _ => None,
            };
        }
        return match (q.kind.as_str(), org, slug) {
            ("DONOR_APPROVED", Some(o), _) => Some(v(&["accept", "--org", &o, "--", &name_arg(who)?])),
            ("DONOR_APPROVED", None, Some(r)) => Some(v(&["accept", "--repo", &r, "--", &name_arg(who)?])),
            ("MEMBER_ADDED", None, Some(r)) => Some(v(&["members", "add", "--repo", &r, "--", &name_arg(who)?])),
            ("REPO_CLAIMED", None, Some(r)) => Some(v(&["claim", "--", &r])),
            ("ORG_CLAIMED", Some(o), _) => Some(v(&["claim", "--org", &o])),
            ("ORG_REPO_ADDED", Some(o), Some(r)) => org_args(&o, &r, "add"),
            _ => None,
        };
    }
    // A donation request to my project: accept its donor, or (no public name) the passkey link.
    let d = owned.iter().find(|d| d.pledge_id == id && d.status == "pending")?;
    let pledge = name_arg(&d.pledge_id)?;
    if let (Some(who), Some(p)) = (name_arg(&d.donor), person_path(&d.person)) {
        return Some(v(&["accept", "--person", &p, "--", &who]));
    }
    match (name_arg(&d.donor), crate::config::canonical_org(&d.org), crate::config::canonical_slug(&d.repo_slug)) {
        (Some(who), Some(o), _) => Some(v(&["accept", "--org", &o, "--", &who])),
        (Some(who), None, Some(r)) => Some(v(&["accept", "--repo", &r, "--", &who])),
        _ => Some(v(&["decisions", "accept", "--", &pledge])),
    }
}

impl NodeSource {
    pub fn new(home: Home) -> Result<Self, String> {
        Ok(Self { home, rt: runtime()? })
    }

    /// Live updates: a thread reading `Watch`, folding bursts into one fresh snapshot (≤ ~6/s),
    /// reconnecting every 2 s while the node is away. Ends when the receiver is dropped.
    pub fn events(&self) -> std::sync::mpsc::Receiver<SourceEvent> {
        let (tx, rx) = std::sync::mpsc::sync_channel(64);
        let home = self.home.clone();
        std::thread::spawn(move || {
            if let Ok(rt) = runtime() {
                rt.block_on(watch(home, tx));
            }
        });
        rx
    }

    fn donation_action(&self, id: &str, action: &str, amount_uusd: i64, reason: &str) -> ActionResult {
        let q = DonationActionRequest { pledge_id: id.into(), action: action.into(), amount_uusd, reason: reason.into(), ..DonationActionRequest::default() };
        let r = self.rt.block_on(async {
            let mut c = connect(&self.home).await?;
            bounded(c.donations(DonationsRequest { op: "action".into(), request: q.encode_to_vec() })).await
        });
        match r {
            Ok(_) => ActionResult::Done(format!("{}: {id}", if action == "reclaim" { "updated" } else { action })),
            Err(e) => ActionResult::Refused(e),
        }
    }
}

async fn watch(home: Home, tx: SyncSender<SourceEvent>) {
    // `false` once the UI hung up.
    let send = |e: SourceEvent| !matches!(tx.try_send(e), Err(std::sync::mpsc::TrySendError::Disconnected(_)));
    loop {
        let stream = match connect(&home).await {
            Ok(mut c) => bounded(c.watch(WatchRequest {})).await.map(|s| (c, s)),
            Err(e) => Err(e),
        };
        let (mut c, mut s) = match stream {
            Ok(x) => x,
            Err(e) => {
                if !send(SourceEvent::Disconnected(e)) {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        while let Ok(Some(first)) = s.message().await {
            let mut evs = vec![first];
            while let Ok(Ok(Some(e))) = tokio::time::timeout(COALESCE, s.message()).await {
                evs.push(e);
                if evs.len() >= 64 {
                    break;
                }
            }
            for e in evs.iter().filter(|e| e.kind == "alert" || e.kind == "link") {
                let text = if e.detail == "paused" {
                    "serving paused on this device".into()
                } else if e.kind == "link" {
                    format!("relay link: {}", e.detail)
                } else { "key-log alert: see Activity".into() };
                if !send(SourceEvent::Toast(text)) {
                    return;
                }
            }
            if let Ok(snap) = fetch(&home, &mut c).await
                && !send(SourceEvent::Snapshot(Box::new(snap)))
            {
                return;
            }
        }
        if !send(SourceEvent::Disconnected("the Moochy app stopped (moochy up)".into())) {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

impl Source for NodeSource {
    fn snapshot(&mut self) -> Result<Snapshot, String> {
        self.rt.block_on(async {
            let mut c = connect(&self.home).await?;
            fetch(&self.home, &mut c).await
        })
    }

    fn act(&mut self, action: Action) -> ActionResult {
        match action {
            Action::PauseDonation(id) => self.donation_action(&id, "pause", 0, ""),
            Action::ResumeDonation(id) => self.donation_action(&id, "resume", 0, ""),
            Action::StopDonation(id) => self.donation_action(&id, "reclaim", 0, ""),
            Action::LowerDonation { id, budget_uusd } => match i64::try_from(budget_uusd) {
                Ok(v) if v > 0 => self.donation_action(&id, "reclaim", v, ""),
                _ => ActionResult::Refused("the new monthly limit must be above $0 (stop ends the donation)".into()),
            },
            Action::Refuse { request_id, reason } => {
                if reason.chars().count() > 280 {
                    return ActionResult::Refused("the reason is at most 280 characters".into());
                }
                self.donation_action(&request_id, "refuse", 0, &reason)
            }
            Action::RevokeBox(id) | Action::RevokeBoxToken(id) => {
                if !moochy_keylog::entry::is_id(&id, "d_") && !moochy_keylog::entry::is_id(&id, "bt_") {
                    return ActionResult::Refused("not a box or box token id".into());
                }
                let r = self.rt.block_on(async {
                    let mut c = connect(&self.home).await?;
                    bounded(c.link_call(LinkCallRequest { op: "revoke_box".into(), request: RevokeBoxRequest { id: id.clone() }.encode_to_vec() })).await
                });
                match r {
                    Ok(_) => ActionResult::Done(format!("revoked {id}")),
                    Err(e) => ActionResult::Refused(e),
                }
            }
            // Owner-key signatures need the passphrase and the decoded-body confirmation on the
            // terminal (A217/A218): the TUI suspends and runs the exact CLI command.
            Action::Accept { request_id } => {
                let found = self.rt.block_on(async {
                    let mut c = connect(&self.home).await?;
                    let p = bounded(c.pending(PendingRequest {})).await?;
                    Ok::<_, String>(accept_args(&request_id, &p.requests, &donations(&mut c, true).await))
                });
                match found {
                    Ok(Some(args)) => ActionResult::Terminal(args),
                    Ok(None) => ActionResult::Refused("that request is no longer pending (or names nothing this app can sign): see moochy pending".into()),
                    Err(e) => ActionResult::Refused(e),
                }
            }
            Action::OrgAdd { org, repo } => org_args(&org, &repo, "add").map_or_else(|| ActionResult::Refused("not an organisation or project".into()), ActionResult::Terminal),
            Action::OrgRemove { org, repo } => org_args(&org, &repo, "remove").map_or_else(|| ActionResult::Refused("not an organisation or project".into()), ActionResult::Terminal),
            Action::Refresh => ActionResult::Done("refreshed".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::local::SignResponse;

    #[test]
    fn accept_runs_the_cli_with_checked_args() {
        let q = |kind: &str, repo: &str, org: &str, who: &str| SignResponse { request_id: "q1".into(), kind: kind.into(), repo_slug: repo.into(), org_path: org.into(), subject_username: who.into(), ..SignResponse::default() };
        let a = |q: SignResponse| accept_args("q1", &[q], &[]);
        assert_eq!(a(q("DONOR_APPROVED", "acme/api", "", "ada")).unwrap(), ["accept", "--repo", "acme/api", "--", "ada"]);
        assert_eq!(a(q("DONOR_APPROVED", "", "github/acme", "ada")).unwrap(), ["accept", "--org", "github/acme", "--", "ada"]);
        assert_eq!(a(q("ORG_REPO_ADDED", "github/acme/api", "github/acme", "")).unwrap(), ["org", "add", "--org", "github/acme", "--", "acme/api"]);
        // A hostile relay: an option as a donor name, a control byte, an unknown kind.
        assert!(a(q("DONOR_APPROVED", "acme/api", "", "--yes")).is_none());
        assert!(a(q("DONOR_APPROVED", "acme/api", "", "ada\u{1b}[2J")).is_none());
        assert!(a(q("DONOR_APPROVED", "--yes", "", "ada")).is_none());
        assert!(a(q("KEY_REVOKED", "acme/api", "", "ada")).is_none());
        assert!(accept_args("other", &[q("DONOR_APPROVED", "acme/api", "", "ada")], &[]).is_none());
        // §24 person entries.
        let pq = |kind: &str, repo: &str, person: &str, who: &str| SignResponse { person_path: person.into(), ..q(kind, repo, "", who) };
        assert_eq!(a(pq("DONOR_APPROVED", "", "github/alice", "ada")).unwrap(), ["accept", "--person", "github/alice", "--", "ada"]);
        assert_eq!(a(pq("PERSON_CLAIMED", "", "github/alice", "")).unwrap(), ["claim", "--person", "github/alice"]);
        assert_eq!(a(pq("PERSON_REPO_ADDED", "alice/tool", "github/alice", "")).unwrap(), ["person", "add", "--person", "github/alice", "--", "alice/tool"]);
        assert!(a(pq("DONOR_APPROVED", "", "github/alice/x", "ada")).is_none(), "a person is one segment");
        // The TUI hands over the raw stored slugs (mo-tui-maint): escapes and options are refused
        // here, never cleaned into something else.
        assert!(org_args("github/acme\u{1b}[2J", "acme/api", "add").is_none());
        assert!(org_args("github/acme", "--yes", "add").is_none());
        assert_eq!(org_args("github/acme", "github/acme/api", "remove").unwrap(), ["org", "remove", "--org", "github/acme", "--", "acme/api"]);
        let d = Donation { pledge_id: "p_01J".into(), status: "pending".into(), repo_slug: "acme/api".into(), ..Donation::default() };
        assert_eq!(accept_args("p_01J", &[], &[d]).unwrap(), ["decisions", "accept", "--", "p_01J"], "anonymous donor: the passkey link");
    }

    #[test]
    fn per_day_buckets() {
        let now = 100 * DAY_MS;
        let e = |role: &str, age_ms: u64, cost: i64| JournalEntry { role: role.into(), t_ms: i64::try_from(now - age_ms).unwrap(), cost_uusd: cost, ..JournalEntry::default() };
        let v = [e("worker", 0, 5), e("worker", DAY_MS - 1, 7), e("worker", DAY_MS, 11), e("worker", 30 * DAY_MS, 99), e("gateway", 0, 3), e("worker", 0, -4)];
        let d = per_day(&v, "worker", now);
        assert_eq!(d.len(), DAYS);
        assert_eq!(d[DAYS - 1], 12, "today");
        assert_eq!(d[DAYS - 2], 11, "yesterday");
        assert_eq!(d.iter().sum::<u64>(), 23, "older than 30 days and other roles left out");
    }
}
