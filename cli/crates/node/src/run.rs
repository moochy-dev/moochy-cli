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
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

pub const RUN_KEY_FILE: &str = "run.key";
pub const RUN_KEY_HEADER: &str = "x-moochy-run-key";
const TOKEN_PREFIX: &str = "mrun_";
const MAX_RUNS: usize = 256;
const HEARTBEAT: Duration = Duration::from_secs(5);

/// SHA-256(run token) → project slug. Looked up by digest so timing reveals nothing of the token.
static RUNS: LazyLock<Mutex<HashMap<[u8; 32], String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
/// The run key of this process (set at gateway start).
static RUN_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

fn runs() -> std::sync::MutexGuard<'static, HashMap<[u8; 32], String>> {
    RUNS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Gateway start: a fresh run key in `<state>/run.key` (0600). Old run tokens die with the old process.
pub fn init_key(state_dir: &Path) -> Result<()> {
    let key = crate::util::rand_bytes::<32>()?;
    crate::config::write_private(&state_dir.join(RUN_KEY_FILE), b64e(&key).as_bytes())?;
    *RUN_KEY.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(key);
    Ok(())
}

/// The slug a live run token belongs to.
pub fn check(token: &str) -> Option<String> {
    if !token.starts_with(TOKEN_PREFIX) {
        return None;
    }
    runs().get(&<[u8; 32]>::from(Sha256::digest(token.as_bytes()))).cloned()
}

fn key_ok(presented: Option<&str>) -> bool {
    let key = *RUN_KEY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    match (key, presented.and_then(crate::util::b64d32)) {
        (Some(k), Some(p)) => ct_eq(&k, &p),
        _ => false,
    }
}

/// Removes the token when the holding response ends.
struct Live([u8; 32]);
impl Drop for Live {
    fn drop(&mut self) {
        runs().remove(&self.0);
    }
}

/// `POST /moochy/run` for `slug` (already authenticated by its repo token).
pub fn open(slug: String, presented_key: Option<&str>) -> Resp {
    if !key_ok(presented_key) {
        return json_resp(403, &serde_json::json!({"error": "run_key_required"}));
    }
    let Ok(raw) = crate::util::rand_bytes::<32>() else { return json_resp(500, &serde_json::json!({"error": "internal"})) };
    let token = format!("{TOKEN_PREFIX}{}", b64e(&raw));
    let digest = <[u8; 32]>::from(Sha256::digest(token.as_bytes()));
    {
        let mut r = runs();
        if r.len() >= MAX_RUNS {
            return json_resp(429, &serde_json::json!({"error": "too_many_runs"}));
        }
        r.insert(digest, slug);
    }
    let live = Live(digest);
    let (tx, rx) = mpsc::channel::<Bytes>(2);
    let first = Bytes::from(format!("{}\n", serde_json::json!({"token": token, "sandboxed": true})));
    tokio::spawn(async move {
        let _live = live;
        if tx.send(first).await.is_err() {
            return;
        }
        loop {
            tokio::select! {
                () = tx.closed() => return,
                () = tokio::time::sleep(HEARTBEAT) => {
                    if tx.send(Bytes::from_static(b"\n")).await.is_err() {
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
}

/// `moochy run -- <cmd…>` (§15.1): mint a sandboxed run token, run the command in
/// `moochy-sandbox` with only the gateway reachable, revoke the token when it ends (also when
/// this process is killed: the minting response closes). Returns the command's exit code.
/// Fails closed: no sandbox, no run.
pub fn run_sandboxed(gw: &GatewayInfo, cmd: &[String]) -> Result<i32> {
    let (prog, args) = cmd.split_first().ok_or_else(|| usage("moochy run -- <command> [args…]"))?;
    let port: u16 = gw.anthropic.rsplit(':').next().and_then(|p| p.trim_end_matches('/').parse().ok()).ok_or_else(|| internal("gateway URL without a port"))?;
    let key = std::fs::read_to_string(gw.state_dir.join(RUN_KEY_FILE)).map_err(|_| internal("no run key: restart the Moochy app (`moochy down`, `moochy up`)"))?;
    let cwd = std::env::current_dir().map_err(|e| internal(format!("cwd: {e}")))?;
    let worktree = crate::files::git_root(&cwd).unwrap_or_else(|| std::fs::canonicalize(&cwd).unwrap_or(cwd.clone()));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| internal(format!("runtime: {e}")))?;
    rt.block_on(async {
        // The minting response stays open for the whole run: the token dies with it.
        let (token, hold) = mint(port, &gw.repo_token, key.trim()).await?;
        let mut spec = moochy_sandbox::Spec::new(worktree.clone());
        spec.cwd = cwd.starts_with(&worktree).then_some(cwd);
        spec.gateway_socket = Some(gw.state_dir.join("gateway.sock"));
        spec.gateway_loopback_port = Some(port);
        for (k, v) in gateway_env(&gw.anthropic, &gw.openai, &gw.mcp, &token) {
            spec.env.insert(k.into(), v.into());
        }
        spec.run_token = Some(token);
        // Agents installed outside the system dirs (e.g. ~/.local/bin): their install dir, ro.
        if let Some(dirs) = install_dirs(prog) {
            spec.ro_paths.extend(dirs);
        }
        let (prog, args): (std::ffi::OsString, Vec<std::ffi::OsString>) = (prog.into(), args.iter().map(Into::into).collect());
        let r = tokio::task::spawn_blocking(move || spec.run(&prog, &args)).await.map_err(|_| internal("sandbox launcher failed"))?;
        drop(hold);
        r.map_err(|e| usage(format!("the sandbox could not be set up, nothing ran: {e}")))
    })
}

/// POST /moochy/run → the run token, plus what keeps it alive (connection + body drain).
async fn mint(port: u16, repo_token: &str, key: &str) -> Result<(String, tokio::task::JoinHandle<()>)> {
    use http_body_util::BodyExt as _;
    let tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(("127.0.0.1", port)))
        .await
        .map_err(|_| internal("gateway timeout"))?
        .map_err(|e| internal(format!("gateway: {e}")))?;
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.map_err(|e| internal(format!("gateway: {e}")))?;
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::post("/moochy/run")
        .header(hyper::header::HOST, format!("127.0.0.1:{port}"))
        .header(hyper::header::AUTHORIZATION, format!("Bearer {repo_token}"))
        .header(RUN_KEY_HEADER, key)
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| internal(format!("request: {e}")))?;
    let resp = tokio::time::timeout(Duration::from_secs(10), send.send_request(req)).await.map_err(|_| internal("gateway timeout"))?.map_err(|e| internal(format!("gateway: {e}")))?;
    if resp.status() != 200 {
        return Err(internal(format!("the Moochy app refused a sandboxed session ({})", resp.status())));
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

/// The resolved install dir(s) of `prog` when it lives outside the default read-only system dirs.
fn install_dirs(prog: &str) -> Option<Vec<std::path::PathBuf>> {
    let found = if prog.contains('/') {
        std::path::PathBuf::from(prog)
    } else {
        std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(prog)).find(|p| p.is_file())?
    };
    let real = std::fs::canonicalize(&found).ok()?;
    let system = |p: &Path| ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"].iter().any(|s| p.starts_with(s));
    let mut out: Vec<std::path::PathBuf> = [found.parent(), real.parent()].into_iter().flatten().filter(|d| !system(d)).map(Path::to_path_buf).collect();
    out.dedup();
    Some(out)
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
    fn run_tokens_need_the_key_and_die_with_the_run() {
        let dir = std::env::temp_dir().join(format!("moochy-run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        init_key(&dir).unwrap();
        let key = std::fs::read_to_string(dir.join(RUN_KEY_FILE)).unwrap();
        assert_eq!(open("acme/widget".into(), None).status(), 403);
        assert_eq!(open("acme/widget".into(), Some("AAAA")).status(), 403);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let r = open("acme/widget".into(), Some(key.trim()));
            assert_eq!(r.status(), 200);
            let Body::Chan(mut rx) = r.into_body() else { panic!("streamed") };
            let line = rx.recv().await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
            let tok = v["token"].as_str().unwrap().to_owned();
            assert_eq!(check(&tok).as_deref(), Some("acme/widget"));
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
