//! Command line (CONTRACT §6): tiny `lexopt` parser, JSON event lines on stdout, exit codes
//! 0 ok, 2 usage, 3 auth/approval refused, 4 network, 10 internal.

use crate::config::{Home, RepoEntry, valid_slug};
use crate::engine::StubExecutor;
use crate::keystore::{self, ProviderKey};
use crate::node::Node;
use crate::pb::local::{EnvRequest, JournalRequest, McpOpen, McpUp, PauseRequest, ShutdownRequest, StatusRequest, mcp_up};
use crate::util::{Ctx as _, Error, Result, auth, clean, emit, internal, log, net, usage};
use lexopt::prelude::*;
use serde_json::json;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const HELP: &str = "moochy — donate and use pooled LLM compute for open source (free, Apache-2.0 OR MIT)

USAGE: moochy [--home DIR] <COMMAND> [OPTIONS]

COMMANDS:
  login --relay https://HOST:PORT [--ca-file PEM] [--roles gateway,worker] [--name NAME] [--headless]
  logout                          Wipe this device's keys locally
  up [--foreground]               Start the node (gateway + MCP doors, relay link, worker)
  down                            Stop the running node
  status [--json]                 Node state
  pause | resume                  Local kill switch for the worker role
  journal [--follow]              Recent tasks (metadata only)
  env [--repo OWNER/NAME] [--json] [--rotate]
                                  Base URLs + repo-scoped local token for tools
  mcp [--repo OWNER/NAME]         stdio MCP server (shim to the running node)
  keys add <anthropic|openrouter|deepseek|openai> --key-stdin [--base-url URL]
  keys list | keys remove <provider>
  config set <device_monthly_cap_uusd|slots_max|gateway_addr> <VALUE> | config show
  approve <donor> --repo OWNER/NAME
  members <add|remove> <user> --repo OWNER/NAME [--cap UUSD]

ENV: MOOCHY_HOME, MOOCHY_PASSPHRASE (encrypted-file keystore), MOOCHY_INSECURE_DEV=1 (dev only)
";

pub fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            emit_err(&e);
            ExitCode::from(e.exit as u8)
        }
    }
}

fn emit_err(e: &Error) {
    let code = match e.exit {
        crate::util::Exit::Usage => "usage",
        crate::util::Exit::Auth => "auth",
        crate::util::Exit::Network => "network",
        crate::util::Exit::Internal => "internal",
    };
    eprintln!("{}", crate::util::clean_value(&json!({"event":"error","code":code,"message":e.msg})));
}

fn rt_small() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread().enable_all().build().ctx("runtime")
}

fn s(v: OsString) -> Result<String> {
    v.into_string().map_err(|_| usage("arguments must be UTF-8"))
}

fn dev_mode() -> bool {
    std::env::var("MOOCHY_INSECURE_DEV").as_deref() == Ok("1")
}

#[derive(Default)]
struct Opts {
    home: Option<PathBuf>,
    words: Vec<String>,
    relay: Option<String>,
    ca_file: Option<PathBuf>,
    roles: Option<String>,
    name: Option<String>,
    repo: Option<String>,
    base_url: Option<String>,
    cap: Option<i64>,
    flags: Vec<&'static str>,
}

impl Opts {
    fn has(&self, f: &str) -> bool {
        self.flags.contains(&f)
    }
}

fn parse() -> Result<Opts> {
    let mut o = Opts::default();
    let mut p = lexopt::Parser::from_env();
    let err = |e: lexopt::Error| usage(e.to_string());
    while let Some(arg) = p.next().map_err(err)? {
        match arg {
            Long("home") => o.home = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("relay") => o.relay = Some(s(p.value().map_err(err)?)?),
            Long("ca-file") => o.ca_file = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("roles") => o.roles = Some(s(p.value().map_err(err)?)?),
            Long("name") => o.name = Some(s(p.value().map_err(err)?)?),
            Long("repo") => o.repo = Some(s(p.value().map_err(err)?)?),
            Long("base-url") => o.base_url = Some(s(p.value().map_err(err)?)?),
            Long("cap") => o.cap = Some(s(p.value().map_err(err)?)?.parse().map_err(|_| usage("--cap must be an integer"))?),
            Long("help") | Short('h') => o.flags.push("help"),
            Long("version") | Short('V') => o.flags.push("version"),
            Long(f) => {
                let known = ["headless", "foreground", "offline", "json", "rotate", "follow", "key-stdin", "shell"];
                match known.iter().find(|k| **k == f) {
                    Some(k) => o.flags.push(k),
                    None => return Err(usage(format!("unknown option --{f}"))),
                }
            }
            Value(v) => o.words.push(s(v)?),
            Short(c) => return Err(usage(format!("unknown option -{c}"))),
        }
    }
    Ok(o)
}

fn run() -> Result<()> {
    let o = parse()?;
    if o.has("version") {
        println!("moochy {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if o.has("help") || o.words.is_empty() {
        print!("{HELP}");
        return if o.words.is_empty() && !o.has("help") { Err(usage("missing command")) } else { Ok(()) };
    }
    let home = Home::resolve(o.home.clone())?;
    let w: Vec<&str> = o.words.iter().map(String::as_str).collect();
    match w.as_slice() {
        ["login"] => {
            let relay = o.relay.as_deref().ok_or_else(|| usage("--relay is required"))?;
            let roles: Vec<String> = o.roles.as_deref().unwrap_or("gateway").split(',').map(|r| r.trim().to_owned()).collect();
            let name = o.name.clone().unwrap_or_else(crate::login::default_name);
            rt_small()?.block_on(crate::login::login(&home, relay, o.ca_file.clone(), roles, name))
        }
        ["logout"] => logout(&home),
        ["up"] => {
            if o.has("offline") && !dev_mode() {
                return Err(usage("--offline requires MOOCHY_INSECURE_DEV=1"));
            }
            if o.has("foreground") { up_foreground(home, o.has("offline")) } else { up_background(&home, &o) }
        }
        ["down"] => rt_small()?.block_on(async {
            crate::ctl::connect(&home.socket_path()).await?.shutdown(ShutdownRequest {}).await.map_err(|s| internal(s.message().to_owned()))?;
            emit(&json!({"event": "stopped"}));
            Ok(())
        }),
        ["status"] => status(&home, o.has("json")),
        ["pause" | "resume"] => rt_small()?.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            let r = if w == ["pause"] { c.pause(PauseRequest {}).await } else { c.resume(PauseRequest {}).await };
            let r = r.map_err(|s| internal(s.message().to_owned()))?.into_inner();
            emit(&json!({"event": "worker", "paused": r.paused}));
            Ok(())
        }),
        ["journal"] => journal(&home, o.has("follow")),
        ["env"] => env(&home, &o),
        ["mcp"] => mcp(&home, &o),
        ["keys", "add", provider] => keys_add(&home, provider, &o),
        ["keys", "list"] => {
            let cfg = home.load()?;
            let sec = keystore::load(&home, &cfg)?.unwrap_or_default();
            for p in &sec.providers {
                emit(&json!({"provider": p.provider, "base_url": p.base_url, "key": format!("…{}", p.key.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect::<String>())}));
            }
            Ok(())
        }
        ["keys", "remove", provider] => {
            let mut cfg = home.load()?;
            let mut sec = keystore::load_or_init(&home, &mut cfg)?;
            sec.providers.retain(|p| p.provider != *provider);
            keystore::save(&home, &cfg, &sec)?;
            emit(&json!({"event": "key_removed", "provider": provider}));
            Ok(())
        }
        ["config", "set", key, value] => {
            let mut cfg = home.load()?;
            cfg.set(key, value)?;
            home.save(&cfg)?;
            emit(&json!({"event": "config_set", "key": key}));
            Ok(())
        }
        ["config", "show"] => {
            let cfg = home.load()?;
            println!("{}", crate::util::clean_value(&serde_json::to_value(&cfg).ctx("config")?));
            Ok(())
        }
        ["approve", _] | ["members", "add" | "remove", _] => owner_ops(&home, &o, &w),
        _ => Err(usage(format!("unknown command `{}` (see --help)", clean(&o.words.join(" "))))),
    }
}

fn logout(home: &Home) -> Result<()> {
    let mut cfg = home.load()?;
    if let Some(mut sec) = keystore::load(home, &cfg)? {
        sec.device = None;
        keystore::save(home, &cfg, &sec)?;
    }
    cfg.device_id = None;
    home.save(&cfg)?;
    emit(&json!({"event": "logged_out"}));
    Ok(())
}

fn slug_or_detect(o: &Opts) -> Result<String> {
    let slug = match &o.repo {
        Some(r) => r.clone(),
        None => detect_repo().ok_or_else(|| usage("--repo owner/name is required (no git remote found)"))?,
    };
    if !valid_slug(&slug) {
        return Err(usage("--repo must be owner/name"));
    }
    Ok(slug)
}

/// `owner/name` from the `origin` remote of the current git repository.
fn detect_repo() -> Option<String> {
    let out = std::process::Command::new("git").args(["config", "--get", "remote.origin.url"]).stderr(std::process::Stdio::null()).output().ok()?;
    let url = String::from_utf8(out.stdout).ok()?;
    let url = url.trim().trim_end_matches('/').trim_end_matches(".git");
    let path = url.rsplit_once(':').map_or(url, |(_, p)| p);
    let mut parts = path.rsplit('/');
    let name = parts.next()?;
    let owner = parts.next()?;
    let slug = format!("{owner}/{name}");
    valid_slug(&slug).then_some(slug)
}

fn env(home: &Home, o: &Opts) -> Result<()> {
    let slug = slug_or_detect(o)?;
    // Record the workspace root for the MCP `files` rules (06 §13).
    let cwd = std::env::current_dir().ctx("cwd")?;
    if let Some(root) = crate::files::git_root(&cwd) {
        let mut cfg = home.load()?;
        if cfg.repos.get(&slug).and_then(|r| r.root.as_ref()) != Some(&root) {
            cfg.repos.insert(slug.clone(), RepoEntry { root: Some(root) });
            home.save(&cfg)?;
        }
    }
    let r = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.env(EnvRequest { repo: slug.clone(), rotate: o.has("rotate") }).await.map_err(|s| internal(s.message().to_owned()))
    })?;
    let r = r.into_inner();
    if o.has("json") {
        emit(&json!({"anthropic_base_url": r.anthropic_base_url, "openai_base_url": r.openai_base_url, "token": r.token}));
    } else {
        println!(
            "export ANTHROPIC_BASE_URL={}\nexport ANTHROPIC_AUTH_TOKEN={}\nexport OPENAI_BASE_URL={}\nexport OPENAI_API_KEY={}\nexport MOOCHY_MCP_URL={}",
            r.anthropic_base_url, r.token, r.openai_base_url, r.token, r.mcp_url
        );
    }
    Ok(())
}

fn status(home: &Home, as_json: bool) -> Result<()> {
    let r = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.status(StatusRequest {}).await.map_err(|s| internal(s.message().to_owned()))
    })?;
    let r = r.into_inner();
    let pools: Vec<_> = r.pools.iter().map(|p| json!({"repo_id": p.repo_id, "slug": p.slug, "workers": p.workers, "models": p.models})).collect();
    let v = json!({"version": r.version, "device_id": r.device_id, "roles": r.roles, "relay": r.relay, "link": r.link_state,
        "gateway_url": r.gateway_url, "mcp_url": r.mcp_url, "paused": r.paused, "slots_max": r.slots_max, "slots_busy": r.slots_busy,
        "gateway_tasks": r.gateway_tasks, "pools": pools, "pid": r.pid});
    if as_json {
        emit(&v);
    } else {
        println!(
            "device   {}\nrelay    {} ({})\ngateway  {}\nmcp      {}\nworker   {} slots busy of {}{}\ntasks    {} in flight",
            clean(&r.device_id),
            clean(&r.relay),
            clean(&r.link_state),
            r.gateway_url,
            r.mcp_url,
            r.slots_busy,
            r.slots_max,
            if r.paused { " (paused)" } else { "" },
            r.gateway_tasks
        );
        for p in &r.pools {
            println!("pool     {} {}: {} donors, models {}", clean(&p.slug), clean(&p.repo_id), p.workers, clean(&p.models.join(", ")));
        }
    }
    Ok(())
}

fn journal(home: &Home, follow: bool) -> Result<()> {
    rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let mut st = c.journal(JournalRequest { follow }).await.map_err(|s| internal(s.message().to_owned()))?.into_inner();
        while let Ok(Some(e)) = st.message().await {
            emit(&json!({"t_ms": e.t_ms, "role": e.role, "task": e.task, "repo": e.repo, "model": e.model, "status": e.status, "cost_uusd": e.cost_uusd, "ms": e.ms}));
        }
        Ok(())
    })
}

fn owner_ops(home: &Home, o: &Opts, w: &[&str]) -> Result<()> {
    let slug = slug_or_detect(o)?;
    rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let r = match w {
            ["approve", donor] => c.approve(crate::pb::local::ApproveRequest { repo: slug, donor: (*donor).into() }).await.map(|_| ()),
            ["members", op, user] => {
                let op = if *op == "add" { crate::pb::local::members_request::Op::Add } else { crate::pb::local::members_request::Op::Remove };
                c.members(crate::pb::local::MembersRequest { repo: slug, op: op as i32, user: (*user).into(), cap_uusd_month: o.cap.unwrap_or(0) }).await.map(|_| ())
            }
            _ => return Err(usage("bad owner command")),
        };
        r.map_err(|s| internal(clean(s.message()).into_owned()))?;
        emit(&json!({"event": "ok"}));
        Ok(())
    })
}

fn keys_add(home: &Home, provider: &str, o: &Opts) -> Result<()> {
    if !matches!(provider, "anthropic" | "openrouter" | "deepseek" | "openai") {
        return Err(usage("provider must be anthropic, openrouter, deepseek or openai"));
    }
    if !o.has("key-stdin") {
        return Err(usage("pass the key on stdin with --key-stdin (never as an argument)"));
    }
    if let Some(u) = &o.base_url {
        check_base_url(u)?;
    }
    let mut raw = zeroize::Zeroizing::new(Vec::new());
    std::io::Read::read_to_end(&mut std::io::Read::take(std::io::stdin(), 4097), &mut raw).ctx("read stdin")?;
    if raw.len() > 4096 {
        return Err(usage("key too long"));
    }
    let key = zeroize::Zeroizing::new(String::from_utf8(raw.to_vec()).map_err(|_| usage("key must be UTF-8"))?.trim().to_owned());
    if key.is_empty() || !key.bytes().all(|c| c.is_ascii_graphic()) {
        return Err(usage("key must be non-empty printable ASCII"));
    }
    let mut cfg = home.load()?;
    let mut sec = keystore::load_or_init(home, &mut cfg)?;
    sec.providers.retain(|p| p.provider != provider);
    sec.providers.push(ProviderKey { provider: provider.into(), key: key.to_string(), base_url: o.base_url.clone() });
    keystore::save(home, &cfg, &sec)?;
    emit(&json!({"event": "key_added", "provider": provider}));
    Ok(())
}

/// `--base-url` only for loopback hosts and only with `MOOCHY_INSECURE_DEV=1` (CONTRACT §6).
fn check_base_url(u: &str) -> Result<()> {
    if !dev_mode() {
        return Err(usage("--base-url is only accepted with MOOCHY_INSECURE_DEV=1"));
    }
    let rest = u.strip_prefix("http://").or_else(|| u.strip_prefix("https://")).ok_or_else(|| usage("--base-url must be http(s)://"))?;
    let auth_part = rest.split('/').next().unwrap_or("");
    if auth_part.contains('@') {
        return Err(usage("--base-url must not carry credentials"));
    }
    let host = if let Some(v6) = auth_part.strip_prefix('[') { v6.split(']').next().unwrap_or("") } else { auth_part.rsplit_once(':').map_or(auth_part, |(h, _)| h) };
    let loopback = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        return Err(usage("--base-url must point to a loopback host"));
    }
    Ok(())
}

fn up_background(home: &Home, o: &Opts) -> Result<()> {
    use std::io::BufRead as _;
    use std::os::unix::process::CommandExt as _;
    home.ensure()?;
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(home.state_dir().join("node.log")).ctx("open node.log")?;
    let exe = std::env::current_exe().ctx("current exe")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--home").arg(&home.dir).args(["up", "--foreground"]);
    if o.has("offline") {
        cmd.arg("--offline");
    }
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(log_file)
        .process_group(0)
        .spawn()
        .ctx("spawn node")?;
    let out = child.stdout.take().ok_or_else(|| internal("no child stdout"))?;
    let mut line = String::new();
    let _ = std::io::BufReader::new(out).read_line(&mut line);
    if line.contains("\"ready\"") {
        print!("{line}");
        return Ok(());
    }
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(10);
    Err(Error {
        exit: match code {
            2 => crate::util::Exit::Usage,
            3 => crate::util::Exit::Auth,
            4 => crate::util::Exit::Network,
            _ => crate::util::Exit::Internal,
        },
        msg: format!("node failed to start (see {})", home.state_dir().join("node.log").display()),
    })
}

fn up_foreground(home: Home, offline: bool) -> Result<()> {
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 4));
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all().build().ctx("runtime")?;
    rt.block_on(up(home, offline))
}

async fn up(home: Home, offline: bool) -> Result<()> {
    home.ensure()?;
    let mut cfg = home.load()?;
    let secrets = if offline {
        keystore::load_or_init(&home, &mut cfg)?
    } else {
        let s = keystore::load(&home, &cfg)?.ok_or_else(|| auth("no keystore: run `moochy login` first"))?;
        if cfg.device_id.is_none() || s.device.is_none() || cfg.relay.is_none() {
            return Err(auth("not logged in: run `moochy login` first"));
        }
        s
    };
    let addr = cfg.gateway_addr()?;
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| usage(format!("bind {addr}: {e}")))?;
    let port = listener.local_addr().ctx("local addr")?.port();
    let sock_path = home.socket_path();
    let sock = crate::ctl::bind(&sock_path).await?;
    // ponytail: StubExecutor until moochy-worker is wired; sealer None until moochy-proto is.
    let node = Node::new(home.clone(), cfg, secrets, Arc::new(StubExecutor::default()), None, offline);
    node.gateway_port.store(u32::from(port), Ordering::Relaxed);
    tokio::spawn(crate::gateway::serve(node.clone(), listener));
    tokio::spawn(crate::ctl::serve(node.clone(), sock, sock_path.clone()));
    if !offline {
        tokio::spawn(crate::link::run(node.clone()));
        match crate::link::wait_first(&node, Duration::from_secs(5)).await {
            Err(e) if e.exit == crate::util::Exit::Auth => return Err(e),
            Err(e) => log("warn", "starting without the relay link", &json!({"error": e.msg})),
            Ok(()) => {}
        }
    }
    let url = node.gateway_url();
    let ready = json!({"device_id": node.device_id(), "gateway_url": url, "mcp_url": format!("{url}/mcp"), "pid": std::process::id()});
    crate::config::write_private(&home.node_json(), ready.to_string().as_bytes())?;
    let mut ev = ready.clone();
    if let Some(o) = ev.as_object_mut() {
        o.insert("event".into(), json!("ready"));
    }
    emit(&ev);

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ctx("signal")?;
    let mut stop = node.shutdown.subscribe();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
        _ = stop.wait_for(|s| *s) => {}
    }
    node.shutdown.send_replace(true);
    let _ = std::fs::remove_file(home.node_json());
    let _ = std::fs::remove_file(&sock_path);
    Ok(())
}

fn mcp(home: &Home, o: &Opts) -> Result<()> {
    let slug = slug_or_detect(o)?;
    let cwd = std::env::current_dir().ctx("cwd")?.to_string_lossy().into_owned();
    rt_small()?.block_on(async move {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let (tx, rx) = tokio::sync::mpsc::channel::<McpUp>(32);
        let _ = tx.send(McpUp { msg: Some(mcp_up::Msg::Open(McpOpen { repo: slug, cwd })) }).await;
        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let data = buf.get(..n).unwrap_or_default().to_vec();
                        if tx.send(McpUp { msg: Some(mcp_up::Msg::Data(data)) }).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let mut down = c.mcp_pipe(tokio_stream::wrappers::ReceiverStream::new(rx)).await.map_err(|s| net(s.message().to_owned()))?.into_inner();
        let mut stdout = tokio::io::stdout();
        while let Ok(Some(m)) = down.message().await {
            stdout.write_all(&m.data).await.ctx("stdout")?;
            stdout.flush().await.ctx("stdout")?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn base_url_rules_without_dev() {
        // MOOCHY_INSECURE_DEV is not set in unit tests: everything is refused.
        assert!(super::check_base_url("http://127.0.0.1:9").is_err());
    }
}
