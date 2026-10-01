//! `moochy run` (CONTRACT §15.1) and its sandboxed run tokens (§15.4).
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

/// `moochy run [--unsafe-no-sandbox] -- <cmd…>`. The sandbox crate (`moochy-sandbox`) is not in
/// this build yet, so without `--unsafe-no-sandbox` this fails closed (§15.1: never silently
/// unsandboxed). The unsafe mode runs the command with the plain repo token: tool calls stay
/// withheld (§15.4), only text flows.
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
