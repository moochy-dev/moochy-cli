//! Cloud boxes (CONTRACT §17): boat.dev VMs, E2B/Daytona/Modal sandboxes, Codespaces.
//!
//! - The maintainer (or a member) creates an enrollment token: `moochy box token create`.
//! - Inside the box, `MOOCHY_ENROLL=<token> moochy up --headless` generates the box's own keys and
//!   enrolls an ephemeral gateway device: repo-scoped, expiring, its own cap, no owner powers, no
//!   donor role. The maintainer's device key never leaves the maintainer's machine.
//! - Clone detection (integrator decision, CONTRACT §17.1): every process start sends a fresh
//!   random instance value with its Auth (`link::instance`); the relay refuses a second live
//!   session of one device key with another instance and alerts the owner. The machine-id is
//!   copied by forks, templates and memory snapshots, so here it is only a hint: a box that starts
//!   on another machine-id says so, and still starts.
//!
//! Owner/member calls go through the running app (LocalControl `LinkCall`), which relays the
//! link.proto message on its authenticated session, like donations.

use crate::config::{Config, Home};
use crate::node::Node;
use crate::pb::link::{BoxDevice, BoxToken, CreateBoxTokenRequest, DevicePollResponse, ListBoxesRequest, ListBoxesResponse, RevokeBoxRequest, RevokeBoxResponse, SetDeviceCapRequest, SetDeviceCapResponse};
use crate::pb::local::{LinkCallRequest, LinkCallResponse};
use crate::util::{Result, auth, b64e, clean, emit, fmt_dollars, internal, net, now_ms, usage};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::time::Duration;
use tonic::Status;

pub const ENROLL_ENV: &str = "MOOCHY_ENROLL";
const TOKEN_PREFIX: &str = "mbx_";
const MIN_TTL_MS: i64 = 10 * 60 * 1000;
const MAX_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
const DEFAULT_TTL_MS: i64 = 24 * 3600 * 1000;
pub const DEFAULT_CAP_UUSD: i64 = 20_000_000;
const MAX_BOXES: u32 = 100;

/// What makes this device a box, saved in `config.json` at enrollment.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoxState {
    pub repo: String,
    pub expires_at_ms: i64,
    pub cap_uusd_month: i64,
    /// Labelled SHA-256 of the machine-id at enrollment (never the raw id); "" = unknown. A hint.
    pub machine: String,
}

/// The machine fingerprint of the running system, when it has one.
pub fn fingerprint() -> Option<String> {
    let m = machine_id()?;
    Some(b64e(&Sha256::digest(crate::util::lp(&[b"moochy/v1/box-machine", m.trim().as_bytes()]))))
}

#[cfg(target_os = "linux")]
fn machine_id() -> Option<String> {
    let read = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty() && s.len() <= 128);
    read("/etc/machine-id").or_else(|| read("/var/lib/dbus/machine-id"))
}

#[cfg(target_os = "macos")]
fn machine_id() -> Option<String> {
    let o = crate::util::command("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).stderr(std::process::Stdio::null()).output().ok()?;
    let t = String::from_utf8_lossy(&o.stdout).into_owned();
    t.lines().find(|l| l.contains("\"IOPlatformUUID\"")).and_then(|l| l.rsplit('"').nth(1).map(str::to_owned))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn machine_id() -> Option<String> {
    None
}

/// The box's expiry refusal, if it is past it.
pub fn refusal(b: &BoxState, now: u64) -> Option<String> {
    (i64::try_from(now).unwrap_or(i64::MAX) >= b.expires_at_ms).then(|| "this box device has expired".to_owned())
}

/// The hint when this box runs on another machine-id than the one it enrolled on.
pub fn machine_hint(b: &BoxState, fp: Option<&str>) -> Option<&'static str> {
    (!b.machine.is_empty() && fp.is_some_and(|f| f != b.machine)).then_some(
        "this box runs on another machine-id than the one it enrolled on (a fork, template or snapshot?). If the original is still running, the server refuses one of them and tells the owner; a fork should enroll with its own token use",
    )
}

/// The box scope from an approved enrollment (`login` with a token), with the machine hint.
pub fn bind(p: &DevicePollResponse, machine: Option<String>) -> Result<BoxState> {
    let exp = p.expires_at_ms;
    if !p.r#box || !crate::config::valid_slug(&p.repo_slug) || exp <= i64::try_from(now_ms()).unwrap_or(i64::MAX) || p.cap_uusd_month <= 0 {
        return Err(net("the server approved the enrollment without a valid box scope (project, expiry, cap): not saved"));
    }
    Ok(BoxState { repo: p.repo_slug.to_ascii_lowercase(), expires_at_ms: exp, cap_uusd_month: p.cap_uusd_month, machine: machine.unwrap_or_default() })
}

/// The enrollment token, checked for shape (never printed): `MOOCHY_ENROLL`, else the owner-only
/// file named by `MOOCHY_ENROLL_FILE`, else the systemd credential `moochy-enroll`.
pub fn enroll_token() -> Result<Option<zeroize::Zeroizing<String>>> {
    let Some(t) = crate::keystore::secret_source(ENROLL_ENV, "moochy-enroll", "enrollment token")? else { return Ok(None) };
    let t = zeroize::Zeroizing::new(t.trim().to_owned());
    let ok = t.strip_prefix(TOKEN_PREFIX).is_some_and(|r| (32..=128).contains(&r.len()) && r.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
    if !ok {
        return Err(usage("MOOCHY_ENROLL is not a box enrollment token (mbx_…, from `moochy box token create`)"));
    }
    Ok(Some(t))
}

/// What `moochy up` must do first on this machine.
#[derive(Debug, PartialEq, Eq)]
pub enum Start {
    /// Start as is (a box still bound here, or a regular device).
    Run,
    /// Enroll with `MOOCHY_ENROLL` first (no device yet, or a stale box).
    Enroll,
}

/// Decide before `moochy up` starts the node. `token`: `MOOCHY_ENROLL` is set.
pub fn plan(cfg: &Config, token: bool, now: u64) -> Result<Start> {
    match (&cfg.box_device, cfg.device_id.is_some()) {
        (Some(b), true) => match refusal(b, now) {
            None => Ok(Start::Run),
            Some(_) if token => Ok(Start::Enroll),
            Some(why) => Err(auth(format!("{why}: refusing to start. A box enrolls again with a new token: MOOCHY_ENROLL=<token> moochy up --headless"))),
        },
        (_, false) if token => Ok(Start::Enroll),
        // A regular device never turns into a box (and keeps its own keys).
        (None, true) if token => Err(usage("this machine is already a device of your account: MOOCHY_ENROLL is only for a fresh box (unset it, or use a separate --home)")),
        _ => Ok(Start::Run),
    }
}

/// Commands a box device may not run (no owner powers, no donor role, §17.1).
pub fn refuse_on_box(cfg: &Config, what: &str) -> Result<()> {
    match &cfg.box_device {
        Some(b) => Err(usage(format!("this is a cloud box for {} (agents only): {what} is not available on a box; run it on your own machine", clean(&b.repo)))),
        None => Ok(()),
    }
}

/// `--ttl 24h` (m, h, d), 10 minutes to 30 days.
pub fn parse_ttl(s: &str) -> Result<i64> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.len().saturating_sub(1));
    let mult: i64 = match unit {
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(usage("--ttl is a duration like 30m, 24h or 7d")),
    };
    let ms = n.parse::<i64>().ok().and_then(|n| n.checked_mul(mult)).ok_or_else(|| usage("--ttl is a duration like 30m, 24h or 7d"))?;
    if !(MIN_TTL_MS..=MAX_TTL_MS).contains(&ms) {
        return Err(usage("--ttl is between 10m and 30d"));
    }
    Ok(ms)
}

// ---------------------------------------------------------------- LinkCall (node side)

/// Node side of LocalControl `LinkCall`: relay one owner/member call on the session.
pub async fn link_call(node: &Node, r: LinkCallRequest) -> std::result::Result<LinkCallResponse, Status> {
    if r.request.len() > 16 << 10 {
        return Err(Status::invalid_argument("request too large"));
    }
    let link = node.link_now(Duration::from_secs(5)).await.ok_or_else(|| Status::unavailable("not connected to the Moochy server"))?;
    let mut c = link.client.clone();
    let bad = |_| Status::invalid_argument("malformed request");
    let req = r.request.as_slice();
    let call = async {
        Ok(match r.op.as_str() {
            "set_device_cap" => c.set_device_cap(crate::link::with_session(&link, SetDeviceCapRequest::decode(req).map_err(bad)?)).await?.into_inner().encode_to_vec(),
            "create_box_token" => c.create_box_token(crate::link::with_session(&link, CreateBoxTokenRequest::decode(req).map_err(bad)?)).await?.into_inner().encode_to_vec(),
            "list_boxes" => c.list_boxes(crate::link::with_session(&link, ListBoxesRequest::decode(req).map_err(bad)?)).await?.into_inner().encode_to_vec(),
            "revoke_box" => c.revoke_box(crate::link::with_session(&link, RevokeBoxRequest::decode(req).map_err(bad)?)).await?.into_inner().encode_to_vec(),
            _ => return Err(Status::invalid_argument("unknown op")),
        })
    };
    let response = tokio::time::timeout(Duration::from_secs(15), call).await.map_err(|_| Status::deadline_exceeded("the server did not answer"))??;
    Ok(LinkCallResponse { response })
}

fn status(s: &Status) -> crate::util::Error {
    let m = clean(s.message()).into_owned();
    match s.code() {
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => net(m),
        // A relay without §17 support answers UNIMPLEMENTED.
        tonic::Code::Unimplemented => usage("the Moochy server does not support this yet (update pending)"),
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => auth(m),
        tonic::Code::InvalidArgument | tonic::Code::NotFound | tonic::Code::AlreadyExists | tonic::Code::FailedPrecondition | tonic::Code::ResourceExhausted => usage(m),
        _ => internal(m),
    }
}

/// CLI side: one call through the running app.
pub fn call<Q: prost::Message, A: prost::Message + Default>(home: &Home, op: &str, q: &Q) -> Result<A> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| internal(format!("runtime: {e}")))?;
    let bytes = rt.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.link_call(LinkCallRequest { op: op.into(), request: q.encode_to_vec() }).await.map(|r| r.into_inner().response).map_err(|e| status(&e))
    })?;
    A::decode(bytes.as_slice()).map_err(|_| net("malformed answer from the server"))
}

// ---------------------------------------------------------------- CLI

/// `moochy members add <d_…> --device --cap $N`: the device's cap, after the signed membership.
pub fn set_device_cap(home: &Home, slug: &str, device: &str, cap: i64) -> Result<()> {
    let r: SetDeviceCapResponse = call(home, "set_device_cap", &SetDeviceCapRequest { repo_slug: slug.into(), device: device.into(), cap_uusd_month: cap })?;
    emit(&json!({"event": "device_cap_set", "repo": slug, "device_id": clean(&r.device_id), "monthly_limit": fmt_dollars(u64::try_from(r.cap_uusd_month).unwrap_or(0))}));
    Ok(())
}

fn token_json(t: &BoxToken) -> serde_json::Value {
    json!({"token_id": clean(&t.token_id), "repo": clean(&t.repo_slug), "expires_at_ms": t.expires_at_ms, "monthly_limit": fmt_dollars(u64::try_from(t.cap_uusd_month).unwrap_or(0)),
        "max_boxes": t.max_boxes, "used": t.used, "revoked": t.revoked, "created_by": clean(&t.created_by)})
}

fn box_json(b: &BoxDevice) -> serde_json::Value {
    json!({"device_id": clean(&b.device_id), "name": clean(&b.name), "token_id": clean(&b.token_id), "repo": clean(&b.repo_slug), "enrolled_at_ms": b.enrolled_at_ms,
        "expires_at_ms": b.expires_at_ms, "monthly_limit": fmt_dollars(u64::try_from(b.cap_uusd_month).unwrap_or(0)), "spent": fmt_dollars(u64::try_from(b.spent_uusd_month).unwrap_or(0)),
        "online": b.online, "revoked": b.revoked, "clone_refusals": b.clone_refusals})
}

/// `moochy box token create --repo P [--ttl 24h] [--cap $20] [--max-boxes N]`.
pub fn token_create(home: &Home, slug: &str, ttl: Option<&str>, cap: Option<i64>, max_boxes: Option<u32>) -> Result<()> {
    let ttl_ms = ttl.map_or(Ok(DEFAULT_TTL_MS), parse_ttl)?;
    let cap = cap.unwrap_or(DEFAULT_CAP_UUSD);
    if cap <= 0 {
        return Err(usage("--cap must be more than $0 (each box's own monthly limit)"));
    }
    let max_boxes = max_boxes.unwrap_or(1);
    if !(1..=MAX_BOXES).contains(&max_boxes) {
        return Err(usage(format!("--max-boxes is between 1 and {MAX_BOXES}")));
    }
    let q = CreateBoxTokenRequest { request_id: crate::util::ulid()?, repo_slug: slug.into(), ttl_ms, cap_uusd_month: cap, max_boxes };
    let t: BoxToken = call(home, "create_box_token", &q)?;
    let secret = zeroize::Zeroizing::new(t.token.clone());
    if !secret.starts_with(TOKEN_PREFIX) || !moochy_keylog::entry::is_id(&t.token_id, "bt_") {
        return Err(net("the server sent a malformed box token"));
    }
    let mut v = token_json(&t);
    if let Some(o) = v.as_object_mut() {
        o.insert("token".into(), json!(clean(&secret)));
    }
    emit(&json!({"event": "box_token_created", "token": v}));
    eprintln!(
        "Box token for {} ({} box(es), each up to {} a month, until it expires). Shown once: keep it in the platform's secret store.\nIn the box: MOOCHY_ENROLL=<token> moochy up --headless (presets: deploy/client/boxes). Revoke: moochy box token revoke {}",
        clean(slug),
        t.max_boxes,
        fmt_dollars(u64::try_from(t.cap_uusd_month).unwrap_or(0)),
        clean(&t.token_id)
    );
    Ok(())
}

/// `moochy box token list` / `moochy box list` (`tokens`: which half to print). `box list` checks
/// the relay's answer against the verified key-log mirror on disk (`in_key_log`) and also shows
/// the boxes the log has and the relay did not list (`"source": "key_log"`); with a relay that
/// cannot list boxes yet, the key log alone.
pub fn list(home: &Home, slug: Option<&str>, tokens: bool) -> Result<()> {
    let relay: Result<ListBoxesResponse> = call(home, "list_boxes", &ListBoxesRequest { repo_slug: slug.unwrap_or_default().into() });
    if tokens {
        relay?.tokens.iter().for_each(|t| emit(&token_json(t)));
        return Ok(());
    }
    let cfg = home.load()?;
    let log = cfg.pseudonym.as_deref().and_then(|ps| crate::keylog::KeyLog::boxes_on_disk(home, &cfg, ps));
    let r = match (relay, &log) {
        (Ok(r), _) => r,
        (Err(e), Some(_)) => {
            eprintln!("moochy: {} — showing the boxes in the key log only", e.msg);
            ListBoxesResponse::default()
        }
        (Err(e), None) => return Err(e),
    };
    for b in &r.boxes {
        let mut v = box_json(b);
        if let (Some(o), Some(l)) = (v.as_object_mut(), &log) {
            o.insert("in_key_log".into(), json!(l.iter().any(|(id, ..)| *id == b.device_id)));
        }
        emit(&v);
    }
    // The key log is per account, not per project: only unfiltered lists add its extra boxes.
    if slug.is_none() {
        let now = now_ms();
        for (id, token, exp, revoked) in log.iter().flatten().filter(|(id, ..)| !r.boxes.iter().any(|b| b.device_id == *id)) {
            emit(&json!({"device_id": clean(id), "token_id": clean(token), "expires_at_ms": exp, "revoked": revoked, "expired": now >= *exp, "source": "key_log"}));
        }
    }
    Ok(())
}

/// `moochy box token revoke <bt_…>` / `moochy box revoke <d_…>`.
pub fn revoke(home: &Home, id: &str, prefix: &str) -> Result<()> {
    if !moochy_keylog::entry::is_id(id, prefix) {
        return Err(usage(if prefix == "bt_" { "box token revoke <bt_…> (from `moochy box token list`)" } else { "box revoke <d_…> (from `moochy box list`)" }));
    }
    let r: RevokeBoxResponse = call(home, "revoke_box", &RevokeBoxRequest { id: id.into() })?;
    emit(&json!({"event": "box_revoked", "id": id, "token_revoked": r.token_revoked, "revoked_devices": r.revoked_devices.iter().map(|d| clean(d).into_owned()).collect::<Vec<_>>()}));
    Ok(())
}

/// `moochy doctor` lines for a box: its scope, and what the runtime lacks for `moochy run`.
/// Level `ok`, `note` or `FAIL` (only a refused box fails).
pub fn doctor_lines(cfg: &Config, sandbox_ok: bool) -> Vec<(&'static str, &'static str, String)> {
    let mut v = Vec::new();
    if let Some(b) = &cfg.box_device {
        let left_h = (b.expires_at_ms.saturating_sub(i64::try_from(now_ms()).unwrap_or(i64::MAX))) / 3_600_000;
        v.push(match refusal(b, now_ms()) {
            None => ("ok  ", "box", format!("cloud box for {}: expires in {left_h} h, up to {} a month", clean(&b.repo), fmt_dollars(u64::try_from(b.cap_uusd_month).unwrap_or(0)))),
            Some(why) => ("FAIL", "box", format!("{why}: enroll again (MOOCHY_ENROLL=<token> moochy up --headless)")),
        });
        if let Some(h) = machine_hint(b, fingerprint().as_deref()) {
            v.push(("note", "box", h.to_owned()));
        }
    }
    if !sandbox_ok {
        v.push((
            "note",
            "box",
            "`moochy run` cannot build its sandbox here (see the sandbox lines). In a single-purpose VM or container, `moochy run --box-is-sandbox -- <agent>` declares the box itself the sandbox: clean environment, project token, loud warning; tool calls only if the project allows platform sandboxes".into(),
        ));
    }
    if cfg!(target_os = "linux") && !seccomp_available() {
        v.push(("note", "seccomp", "no seccomp in this kernel or runtime (/proc/self/status has no Seccomp line): the donor lockdown and `moochy run` filters cannot load".into()));
    }
    v
}

fn seccomp_available() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| s.lines().any(|l| l.starts_with("Seccomp:")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(exp: i64) -> Config {
        Config {
            device_id: Some("d_01J0000000000000000000000A".into()),
            box_device: Some(BoxState { repo: "acme/widget".into(), expires_at_ms: exp, cap_uusd_month: 1, machine: "m".into() }),
            ..Config::default()
        }
    }

    #[test]
    fn start_plan_refuses_expired_boxes_and_hints_at_forks() {
        let cfg = boxed(2_000);
        assert_eq!(plan(&cfg, false, 1_000).unwrap(), Start::Run);
        // Expiry (E105): refused, or enroll again with a token.
        assert!(plan(&cfg, false, 2_000).unwrap_err().msg.contains("expired"));
        assert_eq!(plan(&cfg, true, 2_000).unwrap(), Start::Enroll);
        // Another machine-id is only a hint (the relay's instance check refuses clones, E106).
        let b = cfg.box_device.as_ref().unwrap();
        assert!(machine_hint(b, Some("m2")).is_some() && machine_hint(b, Some("m")).is_none() && machine_hint(b, None).is_none());
        // Fresh machine with a token: enroll; a regular device never turns into a box.
        assert_eq!(plan(&Config::default(), true, 0).unwrap(), Start::Enroll);
        let regular = Config { device_id: Some("d_x".into()), ..Config::default() };
        assert!(plan(&regular, true, 0).is_err());
        assert_eq!(plan(&regular, false, 0).unwrap(), Start::Run);
        assert!(refuse_on_box(&cfg, "members").is_err() && refuse_on_box(&regular, "members").is_ok());
    }

    #[test]
    fn ttl_and_fingerprint() {
        assert_eq!(parse_ttl("24h").unwrap(), 86_400_000);
        assert_eq!(parse_ttl("10m").unwrap(), 600_000);
        assert_eq!(parse_ttl("30d").unwrap(), MAX_TTL_MS);
        for bad in ["9m", "31d", "24", "h", "-1h", "1.5h", "99999999999999999d", ""] {
            assert!(parse_ttl(bad).is_err(), "{bad}");
        }
        if cfg!(target_os = "linux") && std::path::Path::new("/etc/machine-id").exists() {
            let m = fingerprint().unwrap();
            assert_eq!(fingerprint().unwrap(), m, "stable");
            let raw = std::fs::read_to_string("/etc/machine-id").unwrap();
            assert!(!m.contains(raw.trim()), "a labelled hash, never the raw id");
        }
    }

    #[test]
    fn presets_share_one_setup_script() {
        // A devcontainer feature must be self-contained: its copy stays byte-identical.
        let canonical = include_str!("../../../../deploy/client/boxes/moochy-box.sh");
        assert_eq!(include_str!("../../../../deploy/client/devcontainer/moochy/moochy-box.sh"), canonical, "cp deploy/client/boxes/moochy-box.sh deploy/client/devcontainer/moochy/");
        assert!(canonical.contains(ENROLL_ENV) && !canonical.contains("mbx_"), "secret-free: the token comes from the environment");
    }

    #[test]
    fn bind_needs_a_full_scope() {
        let future = i64::try_from(now_ms()).unwrap() + 3_600_000;
        let p = DevicePollResponse { r#box: true, repo_slug: "Acme/Widget".into(), expires_at_ms: future, cap_uusd_month: 5, ..DevicePollResponse::default() };
        let fp = || Some("m".to_owned());
        assert_eq!(bind(&p, fp()).unwrap(), BoxState { repo: "acme/widget".into(), expires_at_ms: future, cap_uusd_month: 5, machine: "m".into() });
        for broken in [
            DevicePollResponse { r#box: false, ..p.clone() },
            DevicePollResponse { repo_slug: "nope".into(), ..p.clone() },
            DevicePollResponse { expires_at_ms: 1, ..p.clone() },
            DevicePollResponse { cap_uusd_month: 0, ..p.clone() },
        ] {
            assert!(bind(&broken, fp()).is_err());
        }
    }
}
