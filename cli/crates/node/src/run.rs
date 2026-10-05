//! `moochy run` (CONTRACT §15.1, on `moochy-sandbox`) and its sandboxed run tokens (§15.4).
//!
//! Tool calls from donated tokens are released only to sandboxed sessions. A session proves it is
//! sandboxed with a run token, minted by the gateway door `POST /moochy/run` for the `moochy run`
//! process that just built the sandbox:
//!
//! - the request carries the project's repo token (which project) **and** the run key from
//!   `<home>/state/run.key` (0600, written at gateway start) in `x-moochy-run-key`. The key lives
//!   outside every sandbox's view, so neither a sandboxed agent nor a client that only knows a
//!   repo token can mint one;
//! - the token is valid while that response stays open: `moochy run` holds it for the life of the
//!   sandbox, and the token dies with it (heartbeat writes detect a vanished client).

use crate::gateway::{Body, Resp, json_resp};
use crate::util::{Result, b64e, ct_eq, internal, usage};
use bytes::Bytes;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub const RUN_KEY_FILE: &str = "run.key";
pub const RUN_KEY_HEADER: &str = "x-moochy-run-key";
/// `moochy run --box-is-sandbox` (§17.2): the session's sandbox is the box, not moochy-sandbox.
pub const PLATFORM_HEADER: &str = "x-moochy-platform-sandbox";
const TOKEN_PREFIX: &str = "mrun_";
const MAX_RUNS: usize = 256;
const HEARTBEAT: Duration = Duration::from_secs(5);

/// A live run token: its project, and whether the box is the sandbox (§17.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub slug: String,
    pub platform: bool,
}

/// SHA-256(run token) → run. Looked up by digest so timing reveals nothing of the token.
static RUNS: LazyLock<Mutex<HashMap<[u8; 32], Run>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// The run key of this process (set at gateway start).
static RUN_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

fn runs() -> std::sync::MutexGuard<'static, HashMap<[u8; 32], Run>> {
    RUNS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Gateway start: a fresh run key in `<state>/run.key` (0600). Old run tokens die with the old process.
pub fn init_key(state_dir: &Path) -> Result<()> {
    let key = crate::util::rand_bytes::<32>()?;
    crate::config::write_private(&state_dir.join(RUN_KEY_FILE), b64e(&key).as_bytes())?;
    *RUN_KEY.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(key);
    Ok(())
}

/// The run a live run token belongs to.
pub fn check(token: &str) -> Option<Run> {
    if !token.starts_with(TOKEN_PREFIX) {
        return None;
    }
    runs().get(&moochy_proto::crypto::sha256(token.as_bytes())).cloned()
}

pub fn key_ok(presented: Option<&str>) -> bool {
    let key = *RUN_KEY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    match (key, presented.and_then(crate::util::b64d32)) {
        (Some(k), Some(p)) => ct_eq(&k, &p),
        _ => false,
    }
}

/// Credentials of a Unix-socket peer (SO_PEERCRED / LOCAL_PEERCRED).
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub uid: u32,
    pub pid: Option<i32>,
}

/// A201: only this user's processes, over the 0600 gateway socket and holding the 0600 run key,
/// may mint a sandboxed run token (a TCP client holding run.key and a repo token cannot). Where
/// `/proc` is readable, the peer must also be the `moochy` binary itself. Under the background
/// process's own lockdown (§15.2, Landlock) `/proc` is not visible, and the uid + run key
/// binding stands alone.
/// A Unix-socket peer running as the owner of the state dir (SO_PEERCRED / LOCAL_PEERCRED).
pub fn same_user(peer: Option<Peer>, state_dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    peer.is_some_and(|p| std::fs::metadata(state_dir).map(|m| m.uid()).ok() == Some(p.uid))
}

fn launcher_ok(peer: Option<Peer>, state_dir: &Path) -> bool {
    if !same_user(peer, state_dir) {
        return false;
    }
    let Some(p) = peer else { return false };
    #[cfg(target_os = "linux")]
    {
        let Some(pid) = p.pid else { return false };
        match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(exe) => std::env::current_exe().is_ok_and(|me| me == exe),
            // Locked down (Landlock: /proc out of view, other processes out of scope).
            Err(_) if std::fs::File::open("/proc/self/status").is_err() => true,
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        p.pid.is_some()
    }
}

/// The launcher process is known to be gone. Only a definite "no such process" counts: under
/// lockdown `/proc` is unreadable, and the closed minting connection is the signal instead
/// (sockets are close-on-exec, so no child inherits it).
fn launcher_gone(pid: Option<i32>) -> bool {
    cfg!(target_os = "linux") && pid.is_some_and(|p| std::fs::metadata(format!("/proc/{p}")).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound))
}

/// Removes the token when the holding response ends.
struct Live([u8; 32]);
impl Drop for Live {
    fn drop(&mut self) {
        runs().remove(&self.0);
    }
}

/// `POST /moochy/run` for `slug` (already authenticated by its repo token). `platform`:
/// `--box-is-sandbox`, the session is marked platform-sandboxed.
pub fn open(slug: String, platform: bool, presented_key: Option<&str>, peer: Option<Peer>, state_dir: &Path) -> Resp {
    if !key_ok(presented_key) {
        return json_resp(403, &serde_json::json!({"error": "run_key_required"}));
    }
    if !launcher_ok(peer, state_dir) {
        return json_resp(403, &serde_json::json!({"error": "launcher_required"}));
    }
    let pid = peer.and_then(|p| p.pid);
    let Ok(raw) = crate::util::rand_bytes::<32>() else { return json_resp(500, &serde_json::json!({"error": "internal"})) };
    let token = format!("{TOKEN_PREFIX}{}", b64e(&raw));
    let digest = moochy_proto::crypto::sha256(token.as_bytes());
    {
        let mut r = runs();
        if r.len() >= MAX_RUNS {
            return json_resp(429, &serde_json::json!({"error": "too_many_runs"}));
        }
        r.insert(digest, Run { slug, platform });
    }
    let live = Live(digest);
    let (tx, rx) = mpsc::channel::<Bytes>(2);
    let first = Bytes::from(format!("{}\n", serde_json::json!({"token": token, "sandboxed": true, "platform": platform})));
    tokio::spawn(async move {
        let _live = live;
        if tx.send(first).await.is_err() {
            return;
        }
        loop {
            tokio::select! {
                () = tx.closed() => return,
                () = tokio::time::sleep(HEARTBEAT) => {
                    // Bound to the launcher: its exit revokes the token even if the socket lingers.
                    if launcher_gone(pid) || tx.send(Bytes::from_static(b"\n")).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    let mut r = hyper::Response::new(Body::Chan(rx));
    r.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/x-ndjson"));
    r
}

/// Environment for a command run against the gateway (`moochy run`): base URLs, the token and the
/// MCP URL. Only these variables carry a credential.
pub fn gateway_env(anthropic: &str, openai: &str, mcp: &str, token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("ANTHROPIC_BASE_URL", anthropic.to_owned()),
        ("ANTHROPIC_AUTH_TOKEN", token.to_owned()),
        ("ANTHROPIC_API_KEY", token.to_owned()),
        ("OPENAI_BASE_URL", openai.to_owned()),
        ("OPENAI_API_BASE", openai.to_owned()),
        ("OPENAI_API_KEY", token.to_owned()),
        ("MOOCHY_MCP_URL", mcp.to_owned()),
        ("MOOCHY_TOKEN", token.to_owned()),
    ]
}

/// What `moochy run` needs from the running node (`moochy env` answer).
pub struct GatewayInfo {
    pub anthropic: String,
    pub openai: String,
    pub mcp: String,
    pub repo_token: String,
    pub state_dir: std::path::PathBuf,
    /// `--allow-host`: exact host names reachable on :443 through the sandbox's CONNECT proxy.
    pub allow_hosts: Vec<String>,
    /// `--git-writable`: the agent may commit (`hooks/`, `config` stay read-only).
    pub git_writable: bool,
}

/// `moochy run -- <cmd…>` (§15.1): mint a sandboxed run token, run the command in
/// `moochy-sandbox` with only the gateway reachable, revoke the token when it ends (also when
/// this process is killed: the minting response closes). Returns the command's exit code.
/// Fails closed: no sandbox, no run.
pub fn run_sandboxed(gw: &GatewayInfo, cmd: &[String], worktree: Option<std::path::PathBuf>) -> Result<i32> {
    let (prog, args) = cmd.split_first().ok_or_else(|| usage("moochy run -- <command> [args…]"))?;
    let port: u16 = gw.anthropic.rsplit(':').next().and_then(|p| p.trim_end_matches('/').parse().ok()).ok_or_else(|| internal("gateway URL without a port"))?;
    let key = std::fs::read_to_string(gw.state_dir.join(RUN_KEY_FILE)).map_err(|_| internal("no run key: restart the Moochy app (`moochy down`, `moochy up`)"))?;
    let cwd = std::env::current_dir().map_err(|e| internal(format!("cwd: {e}")))?;
    // The only read-write project dir: --worktree, else the git top-level of cwd, else cwd.
    let worktree = worktree.or_else(|| crate::files::git_root(&cwd)).unwrap_or_else(|| std::fs::canonicalize(&cwd).unwrap_or(cwd.clone()));
    if !worktree.is_dir() {
        return Err(usage("--worktree must be a directory"));
    }
    guard_worktree(&worktree, gw.state_dir.parent().unwrap_or(&gw.state_dir))?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| internal(format!("runtime: {e}")))?;
    rt.block_on(async {
        // The minting response stays open for the whole run: the token dies with it.
        let sock = gw.state_dir.join("gateway.sock");
        let (token, hold) = mint(&sock, port, &gw.repo_token, key.trim(), false).await?;
        // G42: Linux bridges the gateway's port inside the sandbox netns to its socket. macOS has
        // no netns, and a run token counts only on the socket (A215): bridge a loopback port here.
        let (agent_port, bridged) = if cfg!(target_os = "macos") {
            let (local, task) = start_bridge(&sock, port).await?;
            (local, Some(task))
        } else {
            (port, None)
        };
        let at = |url: &str| url.replacen(&format!(":{port}"), &format!(":{agent_port}"), 1);
        let mut spec = moochy_sandbox::Spec::new(worktree.clone());
        spec.cwd = cwd.starts_with(&worktree).then_some(cwd);
        spec.gateway_socket = Some(sock);
        spec.gateway_loopback_port = Some(agent_port);
        for (k, v) in gateway_env(&at(&gw.anthropic), &at(&gw.openai), &at(&gw.mcp), &token) {
            spec.env.insert(k.into(), v.into());
        }
        spec.run_token = Some(token);
        spec.allow_hosts.clone_from(&gw.allow_hosts);
        spec.git_writable = gw.git_writable;
        // F09: masks kept per worktree, in the state dir the agent never sees (A197).
        let id = crate::util::b64e(&moochy_proto::crypto::sha256(worktree.as_os_str().as_encoded_bytes()));
        spec.mask_record = Some(gw.state_dir.join("masks").join(id));
        // A197, second layer: nothing visible may contain the Moochy home (keys, run key, state).
        spec.protected.push(gw.state_dir.parent().unwrap_or(&gw.state_dir).to_path_buf());
        spec.protected.push(gw.state_dir.clone());
        // Agents installed outside the system dirs (e.g. ~/.local/bin): their install dir, ro.
        if let Some(dirs) = install_dirs(prog) {
            spec.ro_paths.extend(dirs);
        }
        let (prog, args): (std::ffi::OsString, Vec<std::ffi::OsString>) = (prog.into(), args.iter().map(Into::into).collect());
        let r = tokio::task::spawn_blocking(move || spec.run(&prog, &args)).await.map_err(|_| internal("sandbox launcher failed"))?;
        if let Some(b) = bridged {
            b.abort();
        }
        drop(hold);
        r.map_err(|e| usage(format!("the sandbox could not be set up, nothing ran: {e}")))
    })
}

/// `GET path` on the local gateway with the run key (CLI-only endpoints). Returns (status, body).
pub fn local_get(state_dir: &Path, gateway_url: &str, path: &str) -> Result<(u16, Vec<u8>)> {
    use http_body_util::BodyExt as _;
    let port: u16 = gateway_url.rsplit(':').next().and_then(|p| p.trim_end_matches('/').parse().ok()).ok_or_else(|| internal("gateway URL without a port"))?;
    let key = std::fs::read_to_string(state_dir.join(RUN_KEY_FILE)).map_err(|_| internal("the Moochy app is not running (start it with `moochy up`)"))?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| internal(format!("runtime: {e}")))?;
    rt.block_on(async {
        let tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(("127.0.0.1", port)))
            .await
            .map_err(|_| internal("gateway timeout"))?
            .map_err(|_| internal("the Moochy app is not running (start it with `moochy up`)"))?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.map_err(|e| internal(format!("gateway: {e}")))?;
        tokio::spawn(conn);
        let req = hyper::Request::get(path)
            .header(hyper::header::HOST, format!("127.0.0.1:{port}"))
            .header(RUN_KEY_HEADER, key.trim())
            .body(http_body_util::Empty::<Bytes>::new())
            .map_err(|e| internal(format!("request: {e}")))?;
        let resp = tokio::time::timeout(Duration::from_secs(10), send.send_request(req)).await.map_err(|_| internal("gateway timeout"))?.map_err(|e| internal(format!("gateway: {e}")))?;
        let status = resp.status().as_u16();
        let body = http_body_util::Limited::new(resp.into_body(), 1 << 20).collect().await.map_err(|_| internal("gateway answer too large"))?.to_bytes();
        Ok((status, body.to_vec()))
    })
}

/// POST /moochy/run → the run token, plus what keeps it alive (connection + body drain).
async fn mint(sock: &Path, port: u16, repo_token: &str, key: &str, platform: bool) -> Result<(String, tokio::task::JoinHandle<()>)> {
    use http_body_util::BodyExt as _;
    // Over the 0600 Unix socket: the gateway checks this process's credentials (A201).
    let tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::UnixStream::connect(sock))
        .await
        .map_err(|_| internal("gateway timeout"))?
        .map_err(|e| internal(format!("gateway socket: {e}")))?;
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.map_err(|e| internal(format!("gateway: {e}")))?;
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::post("/moochy/run")
        .header(hyper::header::HOST, format!("127.0.0.1:{port}"))
        .header(hyper::header::AUTHORIZATION, format!("Bearer {repo_token}"))
        .header(RUN_KEY_HEADER, key)
        .header(PLATFORM_HEADER, if platform { "1" } else { "0" })
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| internal(format!("request: {e}")))?;
    let resp = tokio::time::timeout(Duration::from_secs(10), send.send_request(req)).await.map_err(|_| internal("gateway timeout"))?.map_err(|e| internal(format!("gateway: {e}")))?;
    if resp.status() != 200 {
        let status = resp.status();
        let body = http_body_util::Limited::new(resp.into_body(), 4096).collect().await.map(http_body_util::Collected::to_bytes).unwrap_or_default();
        let code = serde_json::from_slice::<serde_json::Value>(&body).ok().and_then(|v| v.get("error").and_then(serde_json::Value::as_str).map(str::to_owned)).unwrap_or_default();
        return Err(internal(format!("the Moochy app refused a sandboxed session ({status} {})", crate::util::clean(&code))));
    }
    let mut body = resp.into_body();
    let mut line = Vec::new();
    while !line.contains(&b'\n') {
        let f = tokio::time::timeout(Duration::from_secs(10), body.frame()).await.map_err(|_| internal("gateway timeout"))?;
        let Some(Ok(f)) = f else { return Err(internal("gateway closed the session")) };
        if let Ok(d) = f.into_data() {
            line.extend_from_slice(&d);
        }
        if line.len() > 4096 {
            return Err(internal("bad run-token answer"));
        }
    }
    let v: serde_json::Value = serde_json::from_slice(line.split(|b| *b == b'\n').next().unwrap_or_default()).map_err(|_| internal("bad run-token answer"))?;
    let token = v.get("token").and_then(serde_json::Value::as_str).filter(|t| t.starts_with(TOKEN_PREFIX)).ok_or_else(|| internal("bad run-token answer"))?.to_owned();
    // Drain heartbeats until the run ends; aborting this task (or dying) closes the session.
    let hold = tokio::spawn(async move {
        while let Some(Ok(_)) = body.frame().await {}
        conn.abort();
        drop(send);
    });
    Ok((token, hold))
}

/// Variables a platform-sandboxed run keeps from the caller (§17.2 clean environment): no
/// credentials, no platform tokens; the gateway variables are added on top.
const PLATFORM_KEEP_ENV: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "NO_COLOR"];

/// `moochy run --box-is-sandbox -- <cmd…>` (CONTRACT §17.2): the maintainer declares this
/// single-purpose VM or container the sandbox. No kernel isolation here, so: a loud warning; a
/// clean environment with only the gateway variables; the secret masks enforced by refusing to run
/// while the worktree holds files the sandbox would hide (nothing can hide them here); a run token
/// marked platform-sandboxed (tool calls only if the project allows platform sandboxes).
/// Run tokens are honoured only on the gateway's Unix socket (A215), so this process bridges a
/// loopback port to it for the agent.
/// F08: the first variable (by name; its value is never read) that marks a box holding a
/// credential a donor's tool call could take outside a kernel sandbox: a GitHub Codespace, or a
/// GitHub token in the environment.
fn credential_platform(set: impl Fn(&str) -> bool) -> Option<&'static str> {
    ["CODESPACES", "GITHUB_TOKEN", "GH_TOKEN"].into_iter().find(|n| set(n))
}

pub fn run_platform(gw: &GatewayInfo, cmd: &[String], worktree: Option<std::path::PathBuf>) -> Result<i32> {
    let (prog, args) = cmd.split_first().ok_or_else(|| usage("moochy run --box-is-sandbox -- <command> [args…]"))?;
    let port: u16 = gw.anthropic.rsplit(':').next().and_then(|p| p.trim_end_matches('/').parse().ok()).ok_or_else(|| internal("gateway URL without a port"))?;
    let key = std::fs::read_to_string(gw.state_dir.join(RUN_KEY_FILE)).map_err(|_| internal("no run key: restart the Moochy app (`moochy down`, `moochy up`)"))?;
    let cwd = std::env::current_dir().map_err(|e| internal(format!("cwd: {e}")))?;
    let worktree = worktree.or_else(|| crate::files::git_root(&cwd)).unwrap_or_else(|| std::fs::canonicalize(&cwd).unwrap_or(cwd.clone()));
    guard_worktree(&worktree, gw.state_dir.parent().unwrap_or(&gw.state_dir))?;
    if let Some(name) = credential_platform(|n| std::env::var_os(n).is_some()) {
        return Err(usage(format!(
            "refusing --box-is-sandbox: {name} is set, so this box holds a credential (a codespace's GITHUB_TOKEN can push to the repository) that a donor's tool call could take. Use `moochy connect <agent>` or moochy_delegate (no donated tool calls), or a VM box where plain `moochy run` works"
        )));
    }
    let exposed = moochy_sandbox::mask::collect(&worktree).map_err(|e| usage(format!("cannot check the worktree for secrets: {e}")))?;
    if !exposed.is_empty() {
        let list: Vec<String> = exposed.iter().take(10).map(|p| crate::util::clean(&p.strip_prefix(&worktree).unwrap_or(p).to_string_lossy()).into_owned()).collect();
        return Err(usage(format!(
            "refusing --box-is-sandbox: without a kernel sandbox nothing hides these {} file(s) from the agent: {}{}. Move them out of the box (use the platform's secret store), then run again",
            exposed.len(),
            list.join(", "),
            if exposed.len() > 10 { ", …" } else { "" }
        )));
    }
    eprintln!(
        "\n!!! WARNING: --box-is-sandbox: `{}` runs WITHOUT moochy's sandbox.\n!!! This box is the only boundary: the agent can read and change everything this user can on it,\n!!! reach any network the box reaches, and read the Moochy keys stored here (this box's own, scoped to one project, capped and expiring).\n!!! Use it only in a single-purpose VM or container that holds nothing else. Tool calls from donated tokens reach it only if the project allows platform sandboxes.\n",
        crate::util::clean(prog)
    );
    let sock = gw.state_dir.join("gateway.sock");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| internal(format!("runtime: {e}")))?;
    rt.block_on(async {
        let (token, hold) = mint(&sock, port, &gw.repo_token, key.trim(), true).await?;
        let (local, bridge) = start_bridge(&sock, port).await?;
        let at = |url: &str| url.replacen(&format!(":{port}"), &format!(":{local}"), 1);
        let mut c = std::process::Command::new(prog);
        c.args(args).env_clear().current_dir(if cwd.starts_with(&worktree) { &cwd } else { &worktree });
        for k in PLATFORM_KEEP_ENV {
            if let Some(v) = std::env::var_os(k) {
                c.env(k, v);
            }
        }
        for (k, v) in gateway_env(&at(&gw.anthropic), &at(&gw.openai), &at(&gw.mcp), &token) {
            c.env(k, v);
        }
        c.env(moochy_sandbox::RUN_TOKEN_ENV, &token);
        let name = crate::util::clean(prog).into_owned();
        let st = tokio::task::spawn_blocking(move || c.status()).await.map_err(|_| internal("launcher failed"))?.map_err(|e| internal(format!("run {name}: {e}")))?;
        bridge.abort();
        drop(hold);
        Ok(st.code().unwrap_or(1))
    })
}

/// A loopback port bridged to the gateway socket by [`bridge`]: the port and the bridge task.
async fn start_bridge(sock: &Path, port: u16) -> Result<(u16, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| internal(format!("bridge: {e}")))?;
    let local = listener.local_addr().map_err(|e| internal(format!("bridge: {e}")))?.port();
    Ok((local, tokio::spawn(bridge(listener, sock.to_path_buf(), format!("127.0.0.1:{port}")))))
}

/// Loopback → gateway socket, request by request, with the gateway's own Host (DNS-rebinding
/// allowlist). Only reachable from this box; every request still needs the run token.
async fn bridge(listener: tokio::net::TcpListener, sock: std::path::PathBuf, authority: String) {
    let Ok(host) = hyper::header::HeaderValue::from_str(&authority) else { return };
    loop {
        let Ok((tcp, _)) = listener.accept().await else { continue };
        let _ = tcp.set_nodelay(true);
        let (sock, host) = (sock.clone(), host.clone());
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                let (sock, host) = (sock.clone(), host.clone());
                async move {
                    let unix = tokio::time::timeout(Duration::from_secs(5), tokio::net::UnixStream::connect(&sock)).await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
                    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(unix)).await.map_err(std::io::Error::other)?;
                    tokio::spawn(conn);
                    req.headers_mut().insert(hyper::header::HOST, host);
                    send.send_request(req).await.map_err(std::io::Error::other)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await;
        });
    }
}

/// A197: the worktree becomes read-write inside the sandbox, so it must not be `/`, contain the
/// home directory, or overlap the Moochy home (keystore, run key, state).
fn guard_worktree(wt: &Path, moochy_home: &Path) -> Result<()> {
    // Every side canonical (macOS: /var → /private/var, /tmp → /private/tmp), or a symlinked
    // spelling of the worktree would slip past the overlap checks.
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let wt = &canon(wt);
    let mh = canon(moochy_home);
    let home = std::env::var_os("HOME").map(|h| canon(Path::new(&h)));
    let why = if wt.parent().is_none() {
        Some("is /")
    } else if home.as_ref().is_some_and(|h| h.starts_with(wt)) {
        Some("contains your home directory")
    } else if mh.starts_with(wt) || wt.starts_with(&mh) {
        Some("overlaps the Moochy home (keys and state)")
    } else {
        None
    };
    match why {
        Some(w) => Err(usage(format!("refusing to run: the worktree {} {w}; run inside a project directory", crate::util::clean(&wt.to_string_lossy())))),
        None => Ok(()),
    }
}

/// The resolved install dir(s) of `prog` when it lives outside the default read-only system dirs.
fn install_dirs(prog: &str) -> Option<Vec<std::path::PathBuf>> {
    let found = if prog.contains('/') {
        std::path::PathBuf::from(prog)
    } else {
        std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(prog)).find(|p| p.is_file())?
    };
    let real = std::fs::canonicalize(&found).ok()?;
    let system = |p: &Path| ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"].iter().any(|s| p.starts_with(s));
    let mut dirs = vec![found.parent().map(Path::to_path_buf), real.parent().map(Path::to_path_buf)];
    // A script (`#!/usr/bin/env node`, nvm, Homebrew): its interpreter's dirs too.
    if let Some(interp) = shebang(&real).filter(|i| i != prog)
        && let Some(more) = install_dirs(&interp)
    {
        dirs.extend(more.into_iter().map(Some));
    }
    let mut out: Vec<std::path::PathBuf> = dirs.into_iter().flatten().filter(|d| !system(d)).collect();
    out.sort();
    out.dedup();
    Some(out)
}

/// The interpreter a script names (`#!/path/x` or `#!/usr/bin/env x`), if any.
fn shebang(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let mut head = [0u8; 256];
    let n = std::fs::File::open(path).ok()?.read(&mut head).ok()?;
    let line = head.get(..n)?.strip_prefix(b"#!")?.split(|b| *b == b'\n').next()?;
    let mut words = std::str::from_utf8(line).ok()?.split_whitespace();
    let first = words.next()?;
    let interp = if first.ends_with("/env") { words.find(|w| !w.starts_with('-'))? } else { first };
    Some(interp.to_owned())
}

/// `moochy run --unsafe-no-sandbox`: debugging only. Runs the command with the plain repo
/// token, so tool calls stay withheld (§15.4) and only text flows.
pub fn run_unsandboxed(env: &[(&'static str, String)], cmd: &[String]) -> Result<std::process::ExitStatus> {
    let (prog, args) = cmd.split_first().ok_or_else(|| usage("moochy run -- <command> [args…]"))?;
    eprintln!(
        "WARNING: --unsafe-no-sandbox: `{}` runs WITHOUT a sandbox, with full access to your files, keys and network.\nTool calls from donated tokens stay withheld in this mode; only text is returned.",
        crate::util::clean(prog)
    );
    let mut c = crate::util::command(prog);
    c.args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.status().map_err(|e| internal(format!("run {}: {e}", crate::util::clean(prog))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_is_sandbox_refuses_credential_platforms() {
        // F08: by name only; a codespace, or a GitHub token, refuses --box-is-sandbox.
        assert_eq!(credential_platform(|n| n == "CODESPACES"), Some("CODESPACES"));
        assert_eq!(credential_platform(|n| n == "GH_TOKEN"), Some("GH_TOKEN"));
        assert_eq!(credential_platform(|n| n == "GITHUB_TOKEN"), Some("GITHUB_TOKEN"));
        assert_eq!(credential_platform(|n| n == "MOOCHY_ENROLL"), None);
    }

    #[test]
    fn worktree_guard() {
        let base = std::env::temp_dir().join(format!("moochy-guard-{}", std::process::id()));
        let (proj, mh) = (base.join("proj"), base.join("mh"));
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(mh.join("state")).unwrap();
        assert!(guard_worktree(&proj, &mh).is_ok());
        assert!(guard_worktree(Path::new("/"), &mh).is_err());
        assert!(guard_worktree(&base, &mh).is_err(), "contains the Moochy home");
        assert!(guard_worktree(&mh.join("state"), &mh).is_err(), "inside the Moochy home");
        if let Some(h) = std::env::var_os("HOME").filter(|h| Path::new(h).is_dir()) {
            assert!(guard_worktree(Path::new(&h), &mh).is_err(), "the home directory, as spelled in $HOME");
        }
        // A symlinked spelling of the Moochy home's parent is caught too (macOS /var, /tmp).
        let link = std::env::temp_dir().join(format!("moochy-guard-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&base, &link).unwrap();
        assert!(guard_worktree(&link, &mh).is_err(), "symlinked spelling of a dir containing the home");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// G42: the loopback bridge a macOS `moochy run` points the agent at reaches the gateway's
    /// socket, with the gateway's own Host.
    #[test]
    fn bridge_reaches_the_gateway_socket() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let dir = std::env::temp_dir().join(format!("moochy-bridge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("gateway.sock");
        let _ = std::fs::remove_file(&sock);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let gw = tokio::net::UnixListener::bind(&sock).unwrap();
            let fake = tokio::spawn(async move {
                let (mut s, _) = gw.accept().await.unwrap();
                let mut req = Vec::new();
                while !req.ends_with(b"\r\n\r\n") {
                    let mut b = [0u8; 1];
                    s.read_exact(&mut b).await.unwrap();
                    req.push(b[0]);
                }
                s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
                String::from_utf8(req).unwrap()
            });
            let (local, task) = start_bridge(&sock, 4242).await.unwrap();
            let mut c = tokio::net::TcpStream::connect(("127.0.0.1", local)).await.unwrap();
            c.write_all(format!("GET /v1/models HTTP/1.1\r\nhost: 127.0.0.1:{local}\r\n\r\n").as_bytes()).await.unwrap();
            let mut resp = vec![0u8; 64];
            let n = c.read(&mut resp).await.unwrap();
            assert!(resp[..n].starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&resp[..n]));
            let req = fake.await.unwrap().to_ascii_lowercase();
            assert!(req.starts_with("get /v1/models") && req.contains("host: 127.0.0.1:4242"), "{req}");
            task.abort();
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_tokens_need_the_key_and_die_with_the_run() {
        let dir = std::env::temp_dir().join(format!("moochy-run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        init_key(&dir).unwrap();
        let key = std::fs::read_to_string(dir.join(RUN_KEY_FILE)).unwrap();
        let mine = Peer { uid: std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap()), pid: Some(i32::try_from(std::process::id()).unwrap()) };
        let me = Some(mine);
        assert_eq!(open("acme/widget".into(), false, None, me, &dir).status(), 403);
        assert_eq!(open("acme/widget".into(), false, Some("AAAA"), me, &dir).status(), 403);
        assert_eq!(open("acme/widget".into(), false, Some(key.trim()), None, &dir).status(), 403, "TCP (no peer) cannot mint");
        if cfg!(target_os = "linux") {
            let other = Some(Peer { pid: Some(1), ..mine });
            assert_eq!(open("acme/widget".into(), false, Some(key.trim()), other, &dir).status(), 403, "another program cannot mint");
        }
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let r = open("acme/widget".into(), false, Some(key.trim()), me, &dir);
            assert_eq!(r.status(), 200);
            let Body::Chan(mut rx) = r.into_body() else { panic!("streamed") };
            let line = rx.recv().await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
            let tok = v["token"].as_str().unwrap().to_owned();
            assert_eq!(check(&tok), Some(Run { slug: "acme/widget".into(), platform: false }));
            assert_eq!(check("mrun_forged"), None);
            drop(rx);
            for _ in 0..50 {
                if check(&tok).is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(check(&tok), None, "token revoked when the run ends");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
