//! `moochy.v1.LocalControl` (spec/proto/moochy/v1/local.proto): gRPC over HTTP/2 cleartext on the
//! Unix socket `<home>/state/node.sock` (dir 0700, socket 0600, peer uid checked).

use crate::config::valid_slug;
use crate::node::{LinkState, Node, lock};
use crate::pb::local::local_control_client::LocalControlClient;
use crate::pb::local::local_control_server::{LocalControl, LocalControlServer};
use crate::pb::local::{
    ApproveRequest, ClaimRequest, OrgRepoRequest, EnvRequest, EnvResponse, JournalEntry, JournalRequest, McpDown, McpUp, MembersRequest, PauseRequest,
    LogoutRequest, LogoutResponse, PauseResponse, PendingRequest, PendingResponse, PoolSummary, ReportRequest, ReportResponse, ShutdownRequest, ShutdownResponse, SignResponse, StatusRequest, SubmitEntryRequest, DonationsRequest, DonationsResponse, VerifyRequest, VerifyResponse, TrustOwnerKeyRequest, TrustOwnerKeyResponse,
    StatusResponse, mcp_up, members_request,
};
use crate::util::{Result, internal, log, net};
use bytes::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use serde_json::json;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

const MAX_MSG: usize = 8 << 20;

/// Bind the control socket (refuses if a live Node already owns it). Synchronous: `up` binds
/// every listener before the lockdown (macOS Seatbelt refuses a Unix-socket bind afterwards).
pub fn bind(path: &Path) -> Result<std::os::unix::net::UnixListener> {
    if path.as_os_str().len() > 100 {
        return Err(crate::util::usage(format!("socket path too long for a Unix socket: {}", path.display())));
    }
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(crate::util::usage("Moochy is already running for this --home (`moochy status` shows it, `moochy down` stops it)"));
    }
    let _ = std::fs::remove_file(path);
    let l = std::os::unix::net::UnixListener::bind(path).map_err(|e| internal(format!("bind {}: {e}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| internal(format!("chmod socket: {e}")))?;
    l.set_nonblocking(true).map_err(|e| internal(format!("control socket: {e}")))?;
    Ok(l)
}

pub async fn serve(node: Arc<Node>, listener: UnixListener, path: PathBuf) {
    let uid = std::fs::metadata(&path).map(|m| m.uid()).ok();
    let svc = LocalControlServer::new(Ctl { node: node.clone() }).max_decoding_message_size(MAX_MSG).max_encoding_message_size(MAX_MSG);
    let mut shutdown = node.shutdown.subscribe();
    loop {
        let stream = tokio::select! {
            r = listener.accept() => match r { Ok((s, _)) => s, Err(_) => continue },
            _ = shutdown.changed() => return,
        };
        // Same-user only (the 0600 mode already says so; check the peer anyway).
        let peer = stream.peer_cred().ok().map(|c| c.uid());
        if uid.is_none() || peer != uid {
            log("warn", "control socket: peer uid mismatch, dropped", &json!({}));
            continue;
        }
        let svc = svc.clone();
        tokio::spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .max_concurrent_streams(64)
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(svc))
                .await;
        });
    }
}

/// Connect the CLI to a running Node; `Err(Network)` when none is listening.
pub async fn connect(sock: &Path) -> Result<LocalControlClient<Channel>> {
    let p = sock.to_path_buf();
    let ep = Endpoint::from_static("http://node.sock").connect_timeout(Duration::from_secs(2));
    let ch = ep
        .connect_with_connector(tower::service_fn(move |_| {
            let p = p.clone();
            async move { UnixStream::connect(p).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|_| not_running(sock))?;
    Ok(LocalControlClient::new(ch).max_decoding_message_size(MAX_MSG).max_encoding_message_size(MAX_MSG))
}

/// m2: why nothing answers on `<home>/state/node.sock`: not signed in (the config names no device
/// or server, which `Boot::load` refuses too), or the app is not started.
fn not_running(sock: &Path) -> crate::util::Error {
    let home = sock.parent().and_then(Path::parent).map(|d| crate::config::Home { dir: d.to_path_buf() });
    match home.map(|h| h.load()) {
        Some(Ok(c)) if c.device_id.is_none() || c.relay.is_none() => crate::util::auth("not logged in: run `moochy login` first"),
        _ => net("the Moochy app is not running: start it with `moochy up`"),
    }
}

struct Ctl {
    node: Arc<Node>,
}

/// m14: after a self-revocation request, the relay link drops and the reconnect is refused (waits
/// at most 5 s).
async fn revoked_since(node: &Node) -> bool {
    node.link_kick.notify_one();
    let mut rx = node.link_state.subscribe();
    tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|s| matches!(s, LinkState::Refused(_)))).await.is_ok_and(|r| r.is_ok())
}

pub(crate) fn link_state(node: &Node) -> String {
    if node.offline {
        return "offline".into();
    }
    match &*node.link_state.borrow() {
        LinkState::Down => "down".into(),
        LinkState::Up => "up".into(),
        LinkState::Refused(e) => format!("refused: {e}"),
    }
}

/// CONTRACT §19.6: `org` set names an organisation (canonical form; `repo` only for ORG_REPO_*),
/// empty = a project request. Returns the canonical org, `""` for none.
fn org_arg(org: &str, repo: &str, with_repo: bool) -> std::result::Result<String, Status> {
    if org.is_empty() {
        return Ok(String::new());
    }
    let o = crate::config::canonical_org(org).ok_or_else(|| Status::invalid_argument("org must be github/ORG or gitlab/GROUP[/SUB…]"))?;
    if repo.is_empty() == with_repo {
        return Err(Status::invalid_argument(if with_repo { "repo is required" } else { "org and repo do not go together" }));
    }
    Ok(o)
}

/// CONTRACT §24.6: `person` set names a person profile, `github/LOGIN` or `gitlab/USERNAME`, never
/// with `org` (`repo` only for PERSON_REPO_*); empty = none. Returns the canonical path.
fn person_arg(person: &str, org: &str, repo: &str, with_repo: bool) -> std::result::Result<String, Status> {
    if person.is_empty() {
        return Ok(String::new());
    }
    let p = crate::config::canonical_org(person).filter(|p| p.matches('/').count() == 1).ok_or_else(|| Status::invalid_argument("person must be github/LOGIN or gitlab/USERNAME"))?;
    if !org.is_empty() {
        return Err(Status::invalid_argument("person and org do not go together"));
    }
    if repo.is_empty() == with_repo {
        return Err(Status::invalid_argument(if with_repo { "repo is required" } else { "person and repo do not go together" }));
    }
    Ok(p)
}

#[tonic::async_trait]
impl LocalControl for Ctl {
    async fn status(&self, _: Request<StatusRequest>) -> std::result::Result<Response<StatusResponse>, Status> {
        let n = &self.node;
        let pools = lock(&n.pools)
            .values()
            .map(|p| PoolSummary {
                repo_id: p.repo_id.clone(),
                slug: p.slug.clone().unwrap_or_default(),
                workers: u32::try_from(p.workers.len()).unwrap_or(u32::MAX),
                models: p.models().into_iter().map(|(m, _)| m).collect(),
            })
            .collect();
        let url = n.gateway_url();
        let (lockdown, lockdown_detail) = crate::lockdown::state(&n.home, n.locked);
        Ok(Response::new(StatusResponse {
            version: env!("CARGO_PKG_VERSION").into(),
            device_id: n.device_id().unwrap_or_default().into(),
            roles: n.cfg.roles.clone(),
            relay: n.cfg.relay.clone().unwrap_or_default(),
            link_state: link_state(n),
            mcp_url: format!("{url}/mcp"),
            gateway_url: url,
            paused: n.paused.load(Ordering::Relaxed),
            slots_max: n.cfg.slots_max.unwrap_or(crate::config::DEFAULT_SLOTS),
            slots_busy: n.worker_busy.load(Ordering::Relaxed),
            gateway_tasks: n.gateway_tasks.load(Ordering::Relaxed),
            pools,
            pid: std::process::id(),
            clock_skew_ms: n.clock_skew_ms.load(Ordering::Relaxed),
            provider_keys: u32::try_from(n.secrets.providers.len()).unwrap_or(u32::MAX),
            warm_adapters: u32::try_from(n.adapters.len()).unwrap_or(u32::MAX),
            catalog_version: n.catalog().version,
            keys: n
                .secrets
                .providers
                .iter()
                .map(|p| crate::pb::local::ProviderKeyInfo { provider: p.provider.clone(), models: p.models.keys().cloned().collect() })
                .collect(),
            locked: n.locked,
            lockdown: lockdown.into(),
            lockdown_detail,
            alerts: n.keylog.as_ref().map(|k| k.alerts.borrow().clone()).unwrap_or_default(),
        }))
    }

    async fn pause(&self, _: Request<PauseRequest>) -> std::result::Result<Response<PauseResponse>, Status> {
        self.node.paused.store(true, Ordering::Relaxed);
        crate::worker::reoffer(&self.node);
        Ok(Response::new(PauseResponse { paused: true }))
    }

    async fn resume(&self, _: Request<PauseRequest>) -> std::result::Result<Response<PauseResponse>, Status> {
        self.node.paused.store(false, Ordering::Relaxed);
        crate::worker::reoffer(&self.node);
        Ok(Response::new(PauseResponse { paused: false }))
    }

    async fn env(&self, r: Request<EnvRequest>) -> std::result::Result<Response<EnvResponse>, Status> {
        let r = r.into_inner();
        if !valid_slug(&r.repo) {
            return Err(Status::invalid_argument("repo must be owner/name"));
        }
        let n = &self.node;
        if r.rotate {
            let g = n.token_gen.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
            // In the state dir: the locked-down node cannot write its config (CONTRACT §15.2).
            crate::config::write_private(&n.home.state_dir().join("token_gen"), g.to_string().as_bytes()).map_err(|e| Status::internal(e.msg))?;
        }
        let url = n.gateway_url();
        Ok(Response::new(EnvResponse {
            anthropic_base_url: url.clone(),
            openai_base_url: format!("{url}/v1"),
            mcp_url: format!("{url}/mcp"),
            token: n.token(&r.repo),
        }))
    }

    async fn approve(&self, r: Request<ApproveRequest>) -> std::result::Result<Response<SignResponse>, Status> {
        let r = r.into_inner();
        let kind = if r.revoke { "DONOR_REVOKED" } else { "DONOR_APPROVED" };
        let (org, person) = (org_arg(&r.org, &r.repo, false)?, person_arg(&r.person, &r.org, &r.repo, false)?);
        crate::approve::preview(&self.node, kind, &r.repo, &org, &person, Some(&r.donor), r.dry_run).map(Response::new)
    }

    async fn members(&self, r: Request<MembersRequest>) -> std::result::Result<Response<SignResponse>, Status> {
        let r = r.into_inner();
        let kind = match members_request::Op::try_from(r.op) {
            Ok(members_request::Op::Add) => "MEMBER_ADDED",
            Ok(members_request::Op::Remove) => "MEMBER_REMOVED",
            _ => return Err(Status::invalid_argument("op must be add or remove")),
        };
        if r.device && !r.user.starts_with("d_") {
            return Err(Status::invalid_argument("--device expects a device id (d_…)"));
        }
        crate::approve::preview(&self.node, kind, &r.repo, "", "", Some(&r.user), r.dry_run).map(Response::new)
    }

    async fn claim(&self, r: Request<ClaimRequest>) -> std::result::Result<Response<SignResponse>, Status> {
        let r = r.into_inner();
        let (org, person) = (org_arg(&r.org, &r.repo, false)?, person_arg(&r.person, &r.org, &r.repo, false)?);
        let kind = if !person.is_empty() { "PERSON_CLAIMED" } else if org.is_empty() { "REPO_CLAIMED" } else { "ORG_CLAIMED" };
        crate::approve::preview(&self.node, kind, &r.repo, &org, &person, None, r.dry_run).map(Response::new)
    }

    async fn org_repo(&self, r: Request<OrgRepoRequest>) -> std::result::Result<Response<SignResponse>, Status> {
        let r = r.into_inner();
        let (org, person) = (org_arg(&r.org, &r.repo, true)?, person_arg(&r.person, &r.org, &r.repo, true)?);
        let kind = match (org.is_empty(), person.is_empty(), r.remove) {
            (true, true, _) => return Err(Status::invalid_argument("org or person is required")),
            (_, true, false) => "ORG_REPO_ADDED",
            (_, true, true) => "ORG_REPO_REMOVED",
            (_, false, false) => "PERSON_REPO_ADDED",
            (_, false, true) => "PERSON_REPO_REMOVED",
        };
        crate::approve::preview(&self.node, kind, &r.repo, &org, &person, None, r.dry_run).map(Response::new)
    }

    async fn trust_owner_key(&self, r: Request<TrustOwnerKeyRequest>) -> std::result::Result<Response<TrustOwnerKeyResponse>, Status> {
        let r = r.into_inner();
        let l = self.node.keylog.as_ref().ok_or_else(|| Status::failed_precondition("no key-log key: nothing to trust"))?;
        let me = self.node.cfg.pseudonym.as_deref().ok_or_else(|| Status::failed_precondition("not logged in"))?;
        let (idx, revoked) = l.trust_owner_key(&r.owner_key_id, me, r.dry_run).ok_or_else(|| Status::not_found("no such owner key on this account in the key log"))?;
        Ok(Response::new(TrustOwnerKeyResponse { owner_key_id: r.owner_key_id, log_index: idx, revoked, trusted: !r.dry_run }))
    }

    async fn verify(&self, r: Request<VerifyRequest>) -> std::result::Result<Response<VerifyResponse>, Status> {
        let r = r.into_inner().receipt_ref;
        // A receipt of this device's own request: checked from local evidence (also its
        // commitment to the signed receipt); any other public receipt: fetched from the relay
        // and checked against the key log.
        let v = match crate::task::verify(&self.node, &r) {
            Ok(v) => v,
            Err(_) => crate::keylog::verify_ref(&self.node, &r).await.map_err(Status::failed_precondition)?,
        };
        Ok(Response::new(VerifyResponse { result_json: v.to_string() }))
    }

    async fn donations(&self, r: Request<DonationsRequest>) -> std::result::Result<Response<DonationsResponse>, Status> {
        crate::donations::relay(&self.node, r.into_inner()).await.map(Response::new)
    }

    async fn submit_entry(&self, r: Request<SubmitEntryRequest>) -> std::result::Result<Response<SignResponse>, Status> {
        crate::approve::submit(&self.node, r.into_inner()).await.map(Response::new)
    }

    async fn pending(&self, _: Request<PendingRequest>) -> std::result::Result<Response<PendingResponse>, Status> {
        let claims = lock(&self.node.claims)
            .iter()
            .map(|c| crate::pb::local::ClaimState { target_id: c.target_id.clone(), path: c.path.clone(), verified_at_ms: c.verified_at_ms, paused_since_ms: c.paused_since_ms, releases_at_ms: c.releases_at_ms })
            .collect();
        Ok(Response::new(PendingResponse { requests: crate::approve::pending(&self.node), claims }))
    }

    type JournalStream = ReceiverStream<std::result::Result<JournalEntry, Status>>;

    async fn journal(&self, r: Request<JournalRequest>) -> std::result::Result<Response<Self::JournalStream>, Status> {
        let follow = r.into_inner().follow;
        let (tx, rx) = mpsc::channel(64);
        let mut live = self.node.journal_tx.subscribe();
        let past: Vec<JournalEntry> = lock(&self.node.journal).iter().cloned().collect();
        tokio::spawn(async move {
            for e in past {
                if tx.send(Ok(e)).await.is_err() {
                    return;
                }
            }
            if !follow {
                return;
            }
            loop {
                match live.recv().await {
                    Ok(e) => {
                        if tx.send(Ok(e)).await.is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return,
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type WatchStream = ReceiverStream<std::result::Result<crate::pb::local::WatchEvent, Status>>;

    async fn watch(&self, _: Request<crate::pb::local::WatchRequest>) -> std::result::Result<Response<Self::WatchStream>, Status> {
        let (tx, rx) = mpsc::channel(crate::watch::QUEUE);
        tokio::spawn(crate::watch::run(self.node.clone(), tx));
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type McpPipeStream = ReceiverStream<std::result::Result<McpDown, Status>>;

    async fn mcp_pipe(&self, r: Request<tonic::Streaming<McpUp>>) -> std::result::Result<Response<Self::McpPipeStream>, Status> {
        let mut inp = r.into_inner();
        let Ok(Some(McpUp { msg: Some(mcp_up::Msg::Open(open)) })) = inp.message().await else {
            return Err(Status::invalid_argument("first message must be McpOpen"));
        };
        if !valid_slug(&open.repo) {
            return Err(Status::invalid_argument("repo must be owner/name"));
        }
        let cwd = PathBuf::from(&open.cwd);
        if !cwd.is_absolute() {
            return Err(Status::invalid_argument("cwd must be absolute"));
        }
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(32);
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(32);
        let (down_tx, down_rx) = mpsc::channel(32);
        tokio::spawn(async move {
            while let Ok(Some(m)) = inp.message().await {
                if let Some(mcp_up::Msg::Data(d)) = m.msg
                    && in_tx.send(Bytes::from(d)).await.is_err()
                {
                    return;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(b) = out_rx.recv().await {
                if down_tx.send(Ok(McpDown { data: b.to_vec() })).await.is_err() {
                    return;
                }
            }
        });
        tokio::spawn(crate::mcp::run_pipe(self.node.clone(), open.repo, cwd, in_rx, out_tx));
        Ok(Response::new(ReceiverStream::new(down_rx)))
    }

    async fn logout(&self, r: Request<LogoutRequest>) -> std::result::Result<Response<LogoutResponse>, Status> {
        let reason = r.into_inner().reason;
        let reason = if !reason.is_empty() && reason.len() <= 32 && reason.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c)) { reason } else { "logout".into() };
        let mut res = crate::approve::revoke_self(&self.node, &reason).await;
        // m14: revoking this device closes its own session, often before the relay's ack is
        // flushed. A revoked device is refused at once when it reconnects (its key no longer
        // authenticates): that refusal confirms the revocation.
        if res.is_err() && revoked_since(&self.node).await {
            res = Ok(crate::pb::link::LogEntryAck::default());
        }
        // Stop either way: the session closes, so the relay drops the device at once.
        let stop = self.node.shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            stop.send_replace(true);
        });
        Ok(Response::new(match res {
            Ok(a) if a.error.is_empty() && a.index > 0 => LogoutResponse { revoked: true, detail: format!("KEY_REVOKED at log index {}", a.index) },
            Ok(a) if a.error.is_empty() => LogoutResponse { revoked: true, detail: "the server closed this device's session and now refuses its key".into() },
            Ok(a) => LogoutResponse { revoked: false, detail: crate::util::clean(&a.error).into_owned() },
            Err(s) => LogoutResponse { revoked: false, detail: crate::util::clean(s.message()).into_owned() },
        }))
    }

    async fn link_call(&self, r: Request<crate::pb::local::LinkCallRequest>) -> std::result::Result<Response<crate::pb::local::LinkCallResponse>, Status> {
        crate::boxes::link_call(&self.node, r.into_inner()).await.map(Response::new)
    }

    async fn report(&self, r: Request<ReportRequest>) -> std::result::Result<Response<ReportResponse>, Status> {
        let r = r.into_inner();
        let ev = lock(&self.node.evidence);
        let e = ev.iter().find(|e| e.task == r.task).ok_or_else(|| Status::not_found("no evidence kept for that task (only the last 32 consumed tasks, at most 8 MiB of responses, while the node runs)"))?;
        Ok(Response::new(ReportResponse { bundle: e.bundle(&r.reason).to_string().into_bytes() }))
    }

    async fn shutdown(&self, _: Request<ShutdownRequest>) -> std::result::Result<Response<ShutdownResponse>, Status> {
        self.node.shutdown.send_replace(true);
        Ok(Response::new(ShutdownResponse {}))
    }
}

#[cfg(test)]
mod tests {
    /// m2: nothing on node.sock is "not logged in" (auth) until the config names a device and a
    /// server, then "not running" (network).
    #[test]
    fn not_running_says_why() {
        let dir = std::env::temp_dir().join(format!("moochy-ctl-{}", std::process::id()));
        let home = crate::config::Home { dir: dir.clone() };
        std::fs::create_dir_all(home.state_dir()).unwrap();
        let exit = || super::not_running(&home.socket_path()).exit;
        assert_eq!(exit(), crate::util::Exit::Auth);
        home.save(&crate::config::Config { device_id: Some("d_x".into()), relay: Some("https://relay.example".into()), ..Default::default() }).unwrap();
        assert_eq!(exit(), crate::util::Exit::Network);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
