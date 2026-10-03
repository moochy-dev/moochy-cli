//! Owner signatures for the key log (plan 06 §5, §10; CONTRACT §15.4; spec/KEYLOG.md §4).
//!
//! The relay pushes `ApprovalRequests`; the Node keeps them and shows them (`moochy pending`,
//! dry-run previews). It never signs them: approvals, memberships and claims are signed with the
//! user's **owner key** by the foreground CLI (`owner.rs`) after the human confirmed, and the
//! Node only relays the signed entry over its session (`SubmitEntry`). Even a fully compromised
//! background process cannot approve a donor (A183).

use crate::node::{Node, lock};
use crate::pb::link::{ApprovalRequest, ApprovalRequests, LogEntryAck, NodeMsg, SignedLogEntry, node_msg};
use crate::pb::local::{SignResponse, SubmitEntryRequest};
use crate::util::{clean, log, now_ms};
use bytes::Bytes;
use moochy_keylog::entry::{Body, parse_body};
use moochy_keylog::Kind;
use serde_json::json;
use std::time::Duration;
use tonic::Status;

const MAX_PENDING: usize = 256;
const MAX_SKEW_MS: u64 = 24 * 3600 * 1000;

pub fn kind_num(kind: &str) -> Option<u32> {
    Some(match kind {
        "REPO_CLAIMED" => 3,
        "DONOR_APPROVED" => 4,
        "DONOR_REVOKED" => 5,
        "MEMBER_ADDED" => 6,
        "MEMBER_REMOVED" => 7,
        "ORG_CLAIMED" => 13,
        "ORG_REPO_ADDED" => 14,
        "ORG_REPO_REMOVED" => 15,
        _ => return None,
    })
}

pub fn on_requests(node: &Node, r: ApprovalRequests) {
    let mut reqs = r.requests;
    reqs.retain(|q| kind_num(&q.kind).is_some() && q.body_to_sign.len() <= 1024);
    reqs.truncate(MAX_PENDING);
    // A241: a box has no owner powers; it never keeps the owner's queue (handles + pseudonyms).
    // Logged as received, so a relay that pushes it to a box stays visible.
    if node.cfg.box_device.is_some() {
        log("warn", "requests waiting for your signature pushed to a box: dropped (no owner powers)", &json!({"count": reqs.len()}));
        return;
    }
    log("info", "requests waiting for your signature (moochy pending)", &json!({"count": reqs.len()}));
    *lock(&node.approvals) = reqs;
    let mut claims = r.claims;
    claims.truncate(MAX_PENDING);
    *lock(&node.claims) = claims;
}

pub fn on_ack(node: &Node, a: LogEntryAck) {
    if let Some(tx) = lock(&node.log_acks).remove(&a.request_id) {
        let _ = tx.send(a);
    }
}

/// `(repo_id, org_id, subject, signer, issued_at_ms)` of an owner-signed body, with the target
/// prefixes checked (CONTRACT §19): a project is `r_…`, an organisation `o_…`, never one for the
/// other. An org approval names the org as both (`DONOR_*` only: members belong to a project).
fn targets<'a>(kind: Kind, body: &Body<'a>) -> Result<(&'a str, &'a str, &'a str, &'a str, u64), &'static str> {
    let t = match *body {
        Body::Claim { repo_id, owner, signer, issued_at_ms, .. } => (repo_id, "", owner, signer, issued_at_ms),
        Body::OrgClaim { org_id, owner, signer, issued_at_ms, .. } => ("", org_id, owner, signer, issued_at_ms),
        Body::OrgRepo { org_id, repo_id, signer, issued_at_ms } => (repo_id, org_id, "", signer, issued_at_ms),
        Body::Grant { repo_id, subject, signer, issued_at_ms } if repo_id.starts_with("o_") && matches!(kind, Kind::DonorApproved | Kind::DonorRevoked) => (repo_id, repo_id, subject, signer, issued_at_ms),
        Body::Grant { repo_id, subject, signer, issued_at_ms } => (repo_id, "", subject, signer, issued_at_ms),
        _ => return Err("body does not match its kind"),
    };
    let (repo_ok, org_ok) = (t.0.is_empty() || t.0.starts_with("r_") || t.0 == t.1, t.1.is_empty() || t.1.starts_with("o_"));
    if !repo_ok || !org_ok || (t.0.is_empty() && t.1.is_empty()) {
        return Err("body names neither a project nor an organisation");
    }
    Ok(t)
}

fn is_grant(kind: Kind) -> bool {
    matches!(kind, Kind::DonorApproved | Kind::DonorRevoked | Kind::MemberAdded | Kind::MemberRemoved)
}

/// Decode and check a relay-proposed body against the request. `Err` = never offer it. The signer
/// and timestamp are rebuilt by the CLI with the owner key (KEYLOG §5), so only what the human
/// approves is checked here: project, organisation and subject (A183).
fn decode(q: &ApprovalRequest, me: Option<&str>) -> Result<SignResponse, String> {
    let kind = Kind::from_name(&q.kind).filter(|k| kind_num(k.name()).is_some()).ok_or("unknown entry kind")?;
    let body = parse_body(kind, &q.body_to_sign).map_err(|_| "body is not the expected key-log format")?;
    let (repo_id, org_id, subject, signer, ts) = targets(kind, &body)?;
    if repo_id != q.repo_id {
        return Err("body names another repository than the request".into());
    }
    if org_id != q.org_id {
        return Err("body names another organisation than the request".into());
    }
    if matches!(kind, Kind::RepoClaimed | Kind::OrgClaimed) {
        // A claim names its owner: it must be this user.
        if me.is_none_or(|m| m != subject) {
            return Err("claim names another owner than this account".into());
        }
    } else if is_grant(kind) && (q.subject_pseudonym.is_empty() || subject != q.subject_pseudonym) {
        return Err("body names another subject than the request".into());
    }
    if ts.abs_diff(now_ms()) > MAX_SKEW_MS {
        return Err("body timestamp is more than a day off".into());
    }
    Ok(SignResponse {
        request_id: q.request_id.clone(),
        kind: q.kind.clone(),
        repo_id: repo_id.to_owned(),
        repo_slug: clean(&q.repo_slug).into_owned(),
        subject: subject.to_owned(),
        subject_username: clean(&q.subject_username).into_owned(),
        signer: signer.to_owned(),
        issued_at_ms: i64::try_from(ts).unwrap_or(0),
        signed: false,
        log_index: 0,
        body_to_sign: q.body_to_sign.to_vec(),
        org_id: org_id.to_owned(),
        org_path: clean(&q.org_path).into_owned(),
        ..SignResponse::default()
    })
}

/// Find the pending request and return its checked preview. Signing happens in the CLI. `org`
/// empty = a project request (never an organisation's, CONTRACT §19.6); set = the organisation's
/// (`repo` empty, except for ORG_REPO_*).
pub fn preview(node: &Node, kind: &str, repo: &str, org: &str, subject: Option<&str>, dry_run: bool) -> Result<SignResponse, Status> {
    if !dry_run {
        return Err(Status::failed_precondition("approvals are signed with your owner key by `moochy approve|members|claim` in a terminal; this app never signs them"));
    }
    let q = lock(&node.approvals)
        .iter()
        .find(|q| q.kind == kind && q.repo_slug.eq_ignore_ascii_case(repo) && q.org_path.eq_ignore_ascii_case(org) && subject.is_none_or(|s| q.subject_username.eq_ignore_ascii_case(s) || q.subject_pseudonym == s))
        .cloned()
        .ok_or_else(|| {
            let target = if repo.is_empty() { org } else { repo };
            Status::not_found(match (kind, subject) {
                // The relay offers a revocation for each donor accepted in the key log.
                ("DONOR_REVOKED", Some(s)) => format!("the server offers no revocation of {} for {}: they are not accepted there (see `moochy decisions`), or this server does not offer revocations yet (update the relay)", clean(s), clean(target)),
                _ => format!("no pending {kind} request for {} (requests appear here after the relay pushes them)", clean(target)),
            })
        })?;
    decode(&q, node.cfg.pseudonym.as_deref()).map_err(|e| Status::failed_precondition(format!("refusing this request: {e}")))
}

/// Relay an entry the foreground CLI signed with the owner key. The Node checks shape only (the
/// relay and every monitor verify the signatures); an answer to a pending request must keep its
/// kind, repository and subject.
pub async fn submit(node: &Node, r: SubmitEntryRequest) -> Result<SignResponse, Status> {
    let kind = Kind::from_name(&r.kind).filter(|k| kind_num(k.name()).is_some() || matches!(k, Kind::OwnerKeyAdded | Kind::KeyAdded | Kind::KeyRevoked)).ok_or_else(|| Status::invalid_argument("entry kind not accepted here"))?;
    // KEY_ADDED = device-key rotation (`moochy keys rotate`): successor PoP + current device.
    let sigs_ok = match kind {
        Kind::KeyAdded => r.sigs.len() == 2,
        Kind::OwnerKeyAdded => (1..=2).contains(&r.sigs.len()),
        _ => r.sigs.len() == 1,
    };
    if r.body.len() > 1024 || !sigs_ok || r.sigs.iter().any(|s| s.len() != 64) {
        return Err(Status::invalid_argument("malformed entry"));
    }
    let body = parse_body(kind, &r.body).map_err(|_| Status::invalid_argument("body is not the expected key-log format"))?;
    let mut out = SignResponse { request_id: r.request_id.clone(), kind: r.kind.clone(), ..SignResponse::default() };
    match body {
        Body::Claim { .. } | Body::Grant { .. } | Body::OrgClaim { .. } | Body::OrgRepo { .. } => {
            let (repo_id, org_id, subject, signer, ts) = targets(kind, &body).map_err(Status::invalid_argument)?;
            (out.repo_id, out.org_id, out.subject, out.signer, out.issued_at_ms) = (repo_id.into(), org_id.into(), subject.into(), signer.into(), i64::try_from(ts).unwrap_or(0));
        }
        Body::OwnerKey { pseudonym, issued_at_ms, .. } => (out.subject, out.issued_at_ms) = (pseudonym.into(), i64::try_from(issued_at_ms).unwrap_or(0)),
        // `moochy keys revoke <device>`: another device of this account (this one: `logout`).
        Body::Revoke { device_id, pseudonym, .. } if Some(pseudonym) == node.cfg.pseudonym.as_deref() && Some(device_id) != node.device_id() => {
            (out.subject, out.signer) = (device_id.into(), node.device_id().unwrap_or_default().into());
        }
        Body::Key { device_id, pseudonym, .. } if Some(pseudonym) == node.cfg.pseudonym.as_deref() => (out.subject, out.signer) = (device_id.into(), node.device_id().unwrap_or_default().into()),
        _ => return Err(Status::invalid_argument("body does not match its kind")),
    }
    if !matches!(kind, Kind::OwnerKeyAdded | Kind::KeyAdded | Kind::KeyRevoked) {
        let q = lock(&node.approvals).iter().find(|q| q.request_id == r.request_id).cloned().ok_or_else(|| Status::not_found("no such pending request"))?;
        if q.kind != r.kind || q.repo_id != out.repo_id || q.org_id != out.org_id || (is_grant(kind) && q.subject_pseudonym != out.subject) {
            return Err(Status::failed_precondition("entry does not answer the pending request"));
        }
        out.repo_slug = clean(&q.repo_slug).into_owned();
        out.org_path = clean(&q.org_path).into_owned();
        out.subject_username = clean(&q.subject_username).into_owned();
    }
    // Our own new key: acknowledged before the relay logs it, so the monitor never flags it.
    if let Some(l) = &node.keylog {
        match body {
            Body::OwnerKey { owner_pub, .. } => l.acknowledge(Some(owner_pub), None),
            Body::Key { sign_pub, .. } => l.acknowledge(None, Some(sign_pub)),
            _ => {}
        }
    }
    // A224 (KEYLOG §4c/§4b): a first owner key is held by the relay until the human confirms the
    // emailed link or approves it with a passkey on the web (10 min); everything else is quick.
    let wait = if matches!(body, Body::OwnerKey { prev: None, .. }) { OWNER_KEY_WAIT } else { Duration::from_secs(15) };
    let id = if r.request_id.is_empty() { format!("{}-{}", r.kind, now_ms()) } else { r.request_id.clone() };
    let ack = submit_entry(node, &id, &r.kind, Bytes::from(r.body), r.sigs.into_iter().map(Bytes::from).collect(), wait).await?;
    if !ack.error.is_empty() {
        return Err(Status::failed_precondition(format!("relay refused the entry: {}", clean(&ack.error))));
    }
    lock(&node.approvals).retain(|x| x.request_id != r.request_id);
    out.signed = true;
    out.log_index = ack.index;
    log("info", "owner-signed key-log entry relayed", &json!({"kind": r.kind, "log_index": ack.index}));
    Ok(out)
}

/// How long a first owner key may wait for its proof: the relay's 10 min hold, plus margin.
pub const OWNER_KEY_WAIT: Duration = Duration::from_secs(11 * 60);

/// Send one signed key-log entry over the session and wait for its `LogEntryAck`.
pub async fn submit_entry(node: &Node, request_id: &str, kind: &str, body: Bytes, sigs: Vec<Bytes>, wait: Duration) -> Result<LogEntryAck, Status> {
    let link = node.link().ok_or_else(|| Status::unavailable("relay link is down"))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    lock(&node.log_acks).insert(request_id.to_owned(), tx);
    let e = SignedLogEntry { request_id: request_id.into(), kind: kind.into(), body, sigs };
    if link.up.send(NodeMsg { msg: Some(node_msg::Msg::LogEntry(e)) }).await.is_err() {
        lock(&node.log_acks).remove(request_id);
        return Err(Status::unavailable("relay link is down"));
    }
    let ack = tokio::time::timeout(wait, rx).await;
    lock(&node.log_acks).remove(request_id);
    ack.map_err(|_| Status::deadline_exceeded("relay did not acknowledge the entry"))?.map_err(|_| Status::unavailable("relay link lost"))
}

/// `moochy logout`: a KEY_REVOKED request for this device, self-signed (KEYLOG §2 body
/// `device_id, pseudonym, reason`); the relay asserts it in the log and drops the device.
pub async fn revoke_self(node: &Node, reason: &str) -> Result<LogEntryAck, Status> {
    let (Some(keys), Some(me)) = (node.keys.as_ref(), node.device_id()) else {
        return Err(Status::failed_precondition("not logged in"));
    };
    let pseudonym = node.cfg.pseudonym.as_deref().unwrap_or_default();
    let body = moochy_keylog::entry::revoke_body(me, pseudonym, reason);
    // A device's revocation request (KEYLOG §2a): not a log signature.
    let sig = keys.sign.sign(&moochy_keylog::entry::revoke_request_message(&body));
    submit_entry(node, &format!("revoke-{me}"), "KEY_REVOKED", Bytes::from(body), vec![Bytes::copy_from_slice(&sig)], Duration::from_secs(5)).await
}

pub fn pending(node: &Node) -> Vec<SignResponse> {
    let me = node.cfg.pseudonym.as_deref();
    lock(&node.approvals).iter().filter_map(|q| decode(q, me).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_checks_what_is_signed() {
        let now = now_ms();
        let q = |body: Vec<u8>, subj: &str| ApprovalRequest {
            request_id: "q1".into(),
            kind: "DONOR_APPROVED".into(),
            repo_id: "r_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            repo_slug: "acme/widget".into(),
            subject_username: "alice".into(),
            subject_pseudonym: subj.into(),
            body_to_sign: body.into(),
            ..ApprovalRequest::default()
        };
        let (r, ps, ok) = ("r_01ARZ3NDEKTSV4RRFFQ69G5FAV", "ps_aaaaaaaaaaaaaaaa", "ok_00000000000000000000000000000000");
        let g = |repo: &str, subj: &str, ts: u64| moochy_keylog::entry::grant_body(repo, subj, ok, ts);
        assert!(decode(&q(g(r, ps, now), ps), None).is_ok());
        assert!(decode(&q(g("r_01ARZ3NDEKTSV4RRFFQ69G5FAW", ps, now), ps), None).is_err(), "other repo");
        assert!(decode(&q(g(r, "ps_bbbbbbbbbbbbbbbb", now), ps), None).is_err(), "other subject");
        assert!(decode(&q(g(r, ps, now), ""), None).is_err(), "empty subject is never a wildcard (A183)");
        assert!(decode(&q(g(r, ps, now.saturating_sub(3 * MAX_SKEW_MS)), ps), None).is_err(), "stale");
        assert!(decode(&q(b"garbage".to_vec(), ps), None).is_err());
    }

    #[test]
    fn decode_org_entries() {
        use moochy_keylog::entry::{claim_body, grant_body, org_claim_body, org_repo_body};
        let now = now_ms();
        let (o, r, ps, me, ok) = ("o_01ARZ3NDEKTSV4RRFFQ69G5FAV", "r_01ARZ3NDEKTSV4RRFFQ69G5FAV", "ps_aaaaaaaaaaaaaaaa", "ps_zzzzzzzzzzzzzzzz", "ok_00000000000000000000000000000000");
        let q = |kind: &str, repo_id: &str, org_id: &str, subj: &str, body: Vec<u8>| ApprovalRequest {
            request_id: "q1".into(),
            kind: kind.into(),
            repo_id: repo_id.into(),
            org_id: org_id.into(),
            org_path: "github/acme".into(),
            subject_pseudonym: subj.into(),
            body_to_sign: body.into(),
            ..ApprovalRequest::default()
        };
        // ORG_CLAIMED names this account; no repo.
        let c = decode(&q("ORG_CLAIMED", "", o, "", org_claim_body(o, "github", "42", me, ok, now)), Some(me)).unwrap();
        assert_eq!((c.repo_id.as_str(), c.org_id.as_str(), c.subject.as_str(), c.org_path.as_str()), ("", o, me, "github/acme"));
        assert!(decode(&q("ORG_CLAIMED", "", o, "", org_claim_body(o, "github", "42", ps, ok, now)), Some(me)).is_err(), "another owner");
        assert!(decode(&q("ORG_CLAIMED", "", "o_01ARZ3NDEKTSV4RRFFQ69G5FAW", "", org_claim_body(o, "github", "42", me, ok, now)), Some(me)).is_err(), "another org");
        assert!(decode(&q("ORG_CLAIMED", "", r, "", org_claim_body(r, "github", "42", me, ok, now)), Some(me)).is_err(), "a repo id as an org");
        // ORG_REPO_ADDED: the org and the project, both as requested.
        let a = decode(&q("ORG_REPO_ADDED", r, o, "", org_repo_body(o, r, ok, now)), Some(me)).unwrap();
        assert_eq!((a.repo_id.as_str(), a.org_id.as_str()), (r, o));
        assert!(decode(&q("ORG_REPO_ADDED", "r_01ARZ3NDEKTSV4RRFFQ69G5FAW", o, "", org_repo_body(o, r, ok, now)), Some(me)).is_err(), "another project");
        assert!(decode(&q("ORG_REPO_ADDED", o, o, "", org_repo_body(o, o, ok, now)), Some(me)).is_err(), "an org as a project");
        // An org approval: the o_ id is both targets; members never belong to an org.
        let g = decode(&q("DONOR_APPROVED", o, o, ps, grant_body(o, ps, ok, now)), Some(me)).unwrap();
        assert_eq!((g.repo_id.as_str(), g.org_id.as_str(), g.subject.as_str()), (o, o, ps));
        assert!(decode(&q("MEMBER_ADDED", o, o, ps, grant_body(o, ps, ok, now)), Some(me)).is_err());
        assert!(decode(&q("DONOR_APPROVED", o, "", ps, grant_body(o, ps, ok, now)), Some(me)).is_err(), "an org approval labelled as a project's");
        assert!(decode(&q("DONOR_APPROVED", r, o, ps, grant_body(r, ps, ok, now)), Some(me)).is_err(), "a project approval labelled as an org's");
        assert!(decode(&q("REPO_CLAIMED", o, "", "", claim_body(o, "github", "42", me, ok, now)), Some(me)).is_err(), "an org id in a repo claim");
    }
}
