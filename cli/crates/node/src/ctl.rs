//! `moochy.v1.LocalControl` (spec/proto/moochy/v1/local.proto): gRPC over HTTP/2 cleartext on the
//! Unix socket `<home>/state/node.sock` (dir 0700, socket 0600, peer uid checked).

use crate::config::valid_slug;
use crate::node::{LinkState, Node, lock};
use crate::pb::local::local_control_client::LocalControlClient;
use crate::pb::local::local_control_server::{LocalControl, LocalControlServer};
use crate::pb::local::{
    ApproveRequest, ClaimRequest, EnvRequest, EnvResponse, JournalEntry, JournalRequest, McpDown, McpUp, MembersRequest, PauseRequest,
    PauseResponse, PendingRequest, PendingResponse, PoolSummary, ShutdownRequest, ShutdownResponse, SignResponse, StatusRequest,
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

/// Bind the control socket (refuses if a live Node already owns it).
pub async fn bind(path: &Path) -> Result<UnixListener> {
    if path.as_os_str().len() > 100 {
        return Err(crate::util::usage(format!("socket path too long for a Unix socket: {}", path.display())));
    }
    if UnixStream::connect(path).await.is_ok() {
        return Err(crate::util::usage("a moochy node is already running for this --home"));
    }
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).map_err(|e| internal(format!("bind {}: {e}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| internal(format!("chmod socket: {e}")))?;
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
        .map_err(|_| net("moochy node is not running (start it with `moochy up`)"))?;
    Ok(LocalControlClient::new(ch).max_decoding_message_size(MAX_MSG).max_encoding_message_size(MAX_MSG))
}

struct Ctl {
    node: Arc<Node>,
}

fn link_state(node: &Node) -> String {
    if node.offline {
        return "offline".into();
    }
    match &*node.link_state.borrow() {
        LinkState::Down => "down".into(),
        LinkState::Up => "up".into(),
        LinkState::Refused(e) => format!("refused: {e}"),
    }
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
            let mut cfg = n.home.load().map_err(|e| Status::internal(e.msg))?;
            cfg.token_gen = g;
            n.home.save(&cfg).map_err(|e| Status::internal(e.msg))?;
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
        crate::approve::sign(&self.node, kind, &r.repo, Some(&r.donor), r.dry_run).await.map(Response::new)
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
        crate::approve::sign(&self.node, kind, &r.repo, Some(&r.user), r.dry_run).await.map(Response::new)
    }

    async fn claim(&self, r: Request<ClaimRequest>) -> std::result::Result<Response<SignResponse>, Status> {
        let r = r.into_inner();
        crate::approve::sign(&self.node, "REPO_CLAIMED", &r.repo, None, r.dry_run).await.map(Response::new)
    }

    async fn pending(&self, _: Request<PendingRequest>) -> std::result::Result<Response<PendingResponse>, Status> {
        Ok(Response::new(PendingResponse { requests: crate::approve::pending(&self.node) }))
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

    async fn shutdown(&self, _: Request<ShutdownRequest>) -> std::result::Result<Response<ShutdownResponse>, Status> {
        self.node.shutdown.send_replace(true);
        Ok(Response::new(ShutdownResponse {}))
    }
}
