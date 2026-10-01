//! Owner signatures for the key log (plan 06 §5, §10): donor approvals, memberships, repo claims.
//!
//! The relay pushes `ApprovalRequests`; the Node keeps them and signs one **only** on an explicit
//! `moochy approve` / `members add|remove` / `claim`, after decoding `body_to_sign` and checking
//! that it says what the request claims (repo, subject, this device as signer, a sane timestamp).
//! Formats follow the key-log spec (`moochy-keylog` `grant_body` / `claim_body` / `sig_message`);
//! switch to that crate's functions once it is on main.

use crate::node::{Node, lock};
use crate::pb::link::{ApprovalRequest, ApprovalRequests, LogEntryAck, NodeMsg, SignedLogEntry, node_msg};
use crate::pb::local::SignResponse;
use crate::util::{clean, log, now_ms};
use bytes::Bytes;
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
        _ => return None,
    })
}

pub fn on_requests(node: &Node, r: ApprovalRequests) {
    let mut reqs = r.requests;
    reqs.retain(|q| kind_num(&q.kind).is_some() && q.body_to_sign.len() <= 1024);
    reqs.truncate(MAX_PENDING);
    log("info", "requests waiting for your signature (moochy pending)", &json!({"count": reqs.len()}));
    *lock(&node.approvals) = reqs;
}

pub fn on_ack(node: &Node, a: LogEntryAck) {
    if let Some(tx) = lock(&node.log_acks).remove(&a.request_id) {
        let _ = tx.send(a);
    }
}

/// Split an `lp(...)` byte string into exactly `n` fields.
fn split_lp(mut b: &[u8], n: usize) -> Option<Vec<&[u8]>> {
    let mut out = Vec::with_capacity(n);
    while !b.is_empty() {
        let (len, rest) = b.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        let (f, rest) = rest.split_at_checked(len)?;
        out.push(f);
        b = rest;
    }
    (out.len() == n).then_some(out)
}

fn text(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    s.bytes().all(|c| c.is_ascii_graphic()).then(|| s.to_owned())
}

/// Decode and check a request's body against the request and this device. `Err` = refuse to sign.
fn decode(q: &ApprovalRequest, me: &str) -> Result<SignResponse, String> {
    let claim = q.kind == "REPO_CLAIMED";
    let f = split_lp(&q.body_to_sign, if claim { 6 } else { 4 }).ok_or("body is not the expected key-log format")?;
    let get = |i: usize| f.get(i).and_then(|b| text(b)).ok_or("body field is not printable ASCII");
    let repo_id = get(0)?;
    let (subject, signer, ts) = if claim { (get(3)?, get(4)?, f.get(5)) } else { (get(1)?, get(2)?, f.get(3)) };
    let ts = ts.and_then(|b| <[u8; 8]>::try_from(*b).ok()).map(u64::from_be_bytes).ok_or("bad timestamp")?;
    if repo_id != q.repo_id {
        return Err("body names another repository than the request".into());
    }
    if signer != me {
        return Err("body names another signer than this device".into());
    }
    if !claim && !q.subject_pseudonym.is_empty() && subject != q.subject_pseudonym {
        return Err("body names another subject than the request".into());
    }
    if ts.abs_diff(now_ms()) > MAX_SKEW_MS {
        return Err("body timestamp is more than a day off".into());
    }
    Ok(SignResponse {
        request_id: q.request_id.clone(),
        kind: q.kind.clone(),
        repo_id,
        repo_slug: clean(&q.repo_slug).into_owned(),
        subject,
        subject_username: clean(&q.subject_username).into_owned(),
        signer,
        issued_at_ms: i64::try_from(ts).unwrap_or(0),
        signed: false,
        log_index: 0,
    })
}

/// Find the pending request, check it, and (unless `dry_run`) sign + submit it.
pub async fn sign(node: &Node, kind: &str, repo: &str, subject: Option<&str>, dry_run: bool) -> Result<SignResponse, Status> {
    let kn = kind_num(kind).ok_or_else(|| Status::invalid_argument("unknown entry kind"))?;
    let (Some(keys), Some(me)) = (node.keys.as_ref(), node.device_id()) else {
        return Err(Status::failed_precondition("not logged in"));
    };
    let q = lock(&node.approvals)
        .iter()
        .find(|q| q.kind == kind && q.repo_slug.eq_ignore_ascii_case(repo) && subject.is_none_or(|s| q.subject_username.eq_ignore_ascii_case(s) || q.subject_pseudonym == s))
        .cloned()
        .ok_or_else(|| Status::not_found(format!("no pending {kind} request for {repo} (requests appear here after the relay pushes them)")))?;
    let mut preview = decode(&q, me).map_err(|e| Status::failed_precondition(format!("refusing to sign: {e}")))?;
    if dry_run {
        return Ok(preview);
    }
    let kind_k = moochy_keylog::Kind::from_u32(kn).ok_or_else(|| Status::invalid_argument("unknown entry kind"))?;
    let sig = keys.sign.sign(&moochy_keylog::entry::sig_message(kind_k, &q.body_to_sign));
    let ack = submit_entry(node, &q.request_id, &q.kind, q.body_to_sign.clone(), &sig, Duration::from_secs(15)).await?;
    if !ack.error.is_empty() {
        return Err(Status::failed_precondition(format!("relay refused the entry: {}", clean(&ack.error))));
    }
    lock(&node.approvals).retain(|x| x.request_id != q.request_id);
    preview.signed = true;
    preview.log_index = ack.index;
    Ok(preview)
}

/// Send one signed key-log entry over the session and wait for its `LogEntryAck`.
pub async fn submit_entry(node: &Node, request_id: &str, kind: &str, body: Bytes, sig: &[u8; 64], wait: Duration) -> Result<LogEntryAck, Status> {
    let link = node.link().ok_or_else(|| Status::unavailable("relay link is down"))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    lock(&node.log_acks).insert(request_id.to_owned(), tx);
    let e = SignedLogEntry { request_id: request_id.into(), kind: kind.into(), body, sigs: vec![Bytes::copy_from_slice(sig)] };
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
    let body = moochy_keylog::entry::lp(&[me.as_bytes(), pseudonym.as_bytes(), reason.as_bytes()]);
    let sig = keys.sign.sign(&moochy_keylog::entry::sig_message(moochy_keylog::Kind::KeyRevoked, &body));
    submit_entry(node, &format!("revoke-{me}"), "KEY_REVOKED", Bytes::from(body), &sig, Duration::from_secs(5)).await
}

pub fn pending(node: &Node) -> Vec<SignResponse> {
    let me = node.device_id().unwrap_or_default();
    lock(&node.approvals).iter().filter_map(|q| decode(q, me).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::lp;

    fn grant(repo: &str, subj: &str, signer: &str, ts: u64) -> Vec<u8> {
        lp(&[repo.as_bytes(), subj.as_bytes(), signer.as_bytes(), &ts.to_be_bytes()])
    }

    #[test]
    fn decode_checks_what_is_signed() {
        let now = now_ms();
        let q = |body: Vec<u8>| ApprovalRequest {
            request_id: "q1".into(),
            kind: "DONOR_APPROVED".into(),
            repo_id: "r_1".into(),
            repo_slug: "acme/widget".into(),
            subject_username: "alice".into(),
            subject_pseudonym: "ps_AAAA".into(),
            body_to_sign: body.into(),
            ..ApprovalRequest::default()
        };
        assert!(decode(&q(grant("r_1", "ps_AAAA", "d_me", now)), "d_me").is_ok());
        assert!(decode(&q(grant("r_2", "ps_AAAA", "d_me", now)), "d_me").is_err(), "other repo");
        assert!(decode(&q(grant("r_1", "ps_BBBB", "d_me", now)), "d_me").is_err(), "other subject");
        assert!(decode(&q(grant("r_1", "ps_AAAA", "d_other", now)), "d_me").is_err(), "other signer");
        assert!(decode(&q(grant("r_1", "ps_AAAA", "d_me", now - 3 * MAX_SKEW_MS)), "d_me").is_err(), "stale");
        assert!(decode(&q(b"garbage".to_vec()), "d_me").is_err());
    }
}
