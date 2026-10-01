//! Command line (CONTRACT §6): tiny `lexopt` parser, JSON event lines on stdout, exit codes
//! 0 ok, 2 usage, 3 auth/approval refused, 4 network, 10 internal.

use crate::config::{Home, RepoEntry, valid_slug};
use crate::keystore::{self, ProviderKey};
use crate::node::{Keys, Node, WorkerParts};
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

pub(crate) const HELP: &str = "moochy: donate tokens to open source, and use tokens donated to your projects.
Open-source client (Apache-2.0) · 100% free

USAGE: moochy [--home DIR] <COMMAND> [OPTIONS]

COMMANDS:
  login [--relay URL] [--ca-file PEM] [--roles gateway,worker] [--name NAME] [--headless]
                                  Add this device to your account. Roles: gateway uses donated
                                  tokens, worker donates yours. Only the default server unless
                                  MOOCHY_INSECURE_DEV=1 (a separate keystore per server)
  logout                          Remove this device: revoke its keys, then delete them here
  up [--foreground]               Start the Moochy app on this machine
  down                            Stop it
  status [--json]                 Connection, slots in use, donations available to your projects
  pause | resume                  Stop or restart donating from this device (works offline)
  journal [--follow]              Recent requests (never prompts or outputs)
  env [--repo OWNER/NAME] [--json] [--rotate]
                                  Base URLs and a project token for your tools
  mcp [--repo OWNER/NAME]         MCP server on stdio (needs `moochy up`)
  keys add <anthropic|openai|openrouter|deepseek|xai> --key-stdin [--base-url URL]
                                  Add a provider API key (xai = Grok). It is checked with the
                                  provider's free models call and never leaves this machine
  keys list | keys remove <provider>
  config set <KEY> <VALUE> | config show
                                  monthly_limit (dollars, e.g. 20), slots_max (1-64),
                                  gateway_addr, journal_full_text, auto_cache,
                                  firewall_level (safety checks: strict or paranoid)
  connect <client> [--repo OWNER/NAME] [--write]
                                  Show the setup for a coding tool, or merge it into the
                                  tool's config with --write (`connect list` shows the tools)
  report <task> [--reason TEXT]   Save signed evidence about a bad response
  doctor                          Check the keystore, connection, clock, provider keys and socket
  update --from-file BINARY       Install a signed release (unsigned files are refused)
  pending                         Requests waiting for your signature (maintainers)
  approve <donor> --repo OWNER/NAME [--revoke] [--yes]
                                  Accept a donor for your project (--revoke removes them)
  members <add|remove> <user> --repo OWNER/NAME [--device] [--cap $N] [--yes]
                                  Let a person (or a CI device) use your project's donations,
                                  up to $N a month
  claim --repo OWNER/NAME [--yes] Confirm you maintain a project, signed by this device

ENV: MOOCHY_HOME, MOOCHY_PASSPHRASE (encrypted-file keystore), MOOCHY_INSECURE_DEV=1 (development only)
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
    out: Option<PathBuf>,
    reason: Option<String>,
    from_file: Option<PathBuf>,
    config: Option<PathBuf>,
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
            Long("out") => o.out = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("reason") => o.reason = Some(s(p.value().map_err(err)?)?),
            Long("from-file") => o.from_file = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("config") => o.config = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("cap") => o.cap = Some(crate::util::parse_limit(&s(p.value().map_err(err)?)?).and_then(|v| i64::try_from(v).ok()).ok_or_else(|| usage("--cap is a monthly amount in dollars, e.g. $20"))?),
            Long("help") | Short('h') => o.flags.push("help"),
            Long("version") | Short('V') => o.flags.push("version"),
            Long(f) => {
                let known = ["headless", "foreground", "offline", "json", "rotate", "follow", "key-stdin", "shell", "yes", "revoke", "device", "write"];
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
    if o.has("help") {
        print!("{HELP}");
        return Ok(());
    }
    if o.words.is_empty() {
        eprint!("{HELP}");
        return Err(usage("missing command"));
    }
    let home = Home::resolve(o.home.clone())?;
    let w: Vec<&str> = o.words.iter().map(String::as_str).collect();
    match w.as_slice() {
        ["login"] => {
            let relay = o.relay.as_deref().unwrap_or(crate::config::DEFAULT_RELAY);
            if crate::tls::Origin::parse(relay)?.url() != crate::config::DEFAULT_RELAY {
                // A135: a lookalike relay could harvest a login; only for development and tests.
                if !dev_mode() {
                    return Err(usage("another server than the default needs MOOCHY_INSECURE_DEV=1 (development and tests only)"));
                }
                eprintln!("Warning: signing in to a server that is not the default ({}). This device gets a separate keystore for it.", clean(relay));
            }
            let roles: Vec<String> = o.roles.as_deref().unwrap_or("gateway").split(',').map(|r| r.trim().to_owned()).collect();
            let name = o.name.clone().unwrap_or_else(crate::login::default_name);
            rt_small()?.block_on(crate::login::login(&home, relay, o.ca_file.clone(), roles, name))
        }
        ["logout"] => logout(&home, &o),
        ["report", task] => report(&home, &o, task),
        ["doctor"] => doctor(&home),
        ["update"] => update(&o),
        ["keys", "rotate"] => Err(internal(
            "key rotation is not available yet: the server cannot accept a rotation signed by the current device",
        )),
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
        ["keys", "list" | "remove", ..] => keys_cmd(&home, &w),
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
        ["approve", _] | ["members", "add" | "remove", _] | ["claim"] => owner_ops(&home, &o, &w),
        ["pending"] => rt_small()?.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            let r = c.pending(crate::pb::local::PendingRequest {}).await.map_err(|s| internal(clean(s.message()).into_owned()))?.into_inner();
            for q in r.requests {
                emit(&sign_json(&q));
            }
            Ok(())
        }),
        ["connect", "list"] => {
            println!("{}", crate::connect::CLIENTS.join("\n"));
            Ok(())
        }
        ["connect", client] => connect(&home, &o, client),
        _ => Err(usage(format!("unknown command `{}` (see --help)", clean(&o.words.join(" "))))),
    }
}

fn keys_cmd(home: &Home, w: &[&str]) -> Result<()> {
    match w {
        ["keys", "list"] => {
            let cfg = home.load()?;
            let sec = keystore::load(home, &cfg)?.unwrap_or_default();
            for p in &sec.providers {
                emit(&json!({"provider": p.provider, "base_url": p.base_url, "key": format!("…{}", p.key.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect::<String>())}));
            }
            Ok(())
        }
        ["keys", "remove", provider] => {
            let mut cfg = home.load()?;
            let mut sec = keystore::load_or_init(home, &mut cfg)?;
            sec.providers.retain(|p| p.provider != *provider);
            keystore::save(home, &cfg, &sec)?;
            emit(&json!({"event": "key_removed", "provider": provider}));
            Ok(())
        }
        _ => Err(usage("keys add|list|remove|rotate")),
    }
}

/// Ask the running node to request `KEY_REVOKED` and stop, then wipe the device keys locally.
fn logout(home: &Home, o: &Opts) -> Result<()> {
    let reason = o.reason.clone().unwrap_or_else(|| "logout".into());
    let told = rt_small()?.block_on(async {
        let Ok(mut c) = crate::ctl::connect(&home.socket_path()).await else { return None };
        let r = c.logout(crate::pb::local::LogoutRequest { reason }).await.ok()?.into_inner();
        // Wait (bounded) for the node to stop so it cannot reconnect with the old keys.
        for _ in 0..100 {
            if crate::ctl::connect(&home.socket_path()).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Some(r)
    });
    match &told {
        Some(r) if r.revoked => {}
        Some(r) => eprintln!("Warning: the server did not confirm that this device is revoked ({}). Remove it on the web as well.", clean(&r.detail)),
        None => eprintln!("Warning: the Moochy app is not running, so the server was not told. Remove this device on the web as well."),
    }
    let mut cfg = home.load()?;
    if let Some(mut sec) = keystore::load(home, &cfg)? {
        sec.device = None;
        keystore::save(home, &cfg, &sec)?;
    }
    cfg.device_id = None;
    home.save(&cfg)?;
    emit(&json!({"event": "logged_out", "revoked": told.is_some_and(|r| r.revoked)}));
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
            "device      {}\nserver      {} ({})\nlocal API   {}\nMCP         {}\ndonating    {} of {} slots in use{}\nusing       {} requests in progress",
            clean(&r.device_id),
            clean(&r.relay),
            clean(&r.link_state),
            r.gateway_url,
            r.mcp_url,
            r.slots_busy,
            r.slots_max,
            if r.paused { ", paused" } else { "" },
            r.gateway_tasks
        );
        for p in &r.pools {
            println!("project     {}: {} donor device(s), models {}", clean(&p.slug), p.workers, clean(&p.models.join(", ")));
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

fn sign_json(q: &crate::pb::local::SignResponse) -> serde_json::Value {
    json!({"request_id": q.request_id, "kind": q.kind, "repo": q.repo_slug, "repo_id": q.repo_id, "subject": q.subject,
        "subject_username": q.subject_username, "signer": q.signer, "issued_at_ms": q.issued_at_ms, "signed": q.signed, "log_index": q.log_index})
}

/// Owner signatures: show exactly what will be signed, then sign only on explicit consent.
fn owner_ops(home: &Home, o: &Opts, w: &[&str]) -> Result<()> {
    use crate::pb::local::{ApproveRequest, ClaimRequest, MembersRequest, members_request::Op};
    use std::io::IsTerminal as _;
    let slug = slug_or_detect(o)?;
    rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let call = |c: &mut crate::pb::local::local_control_client::LocalControlClient<tonic::transport::Channel>, dry_run: bool| {
            let mut c = c.clone();
            let (slug, w) = (slug.clone(), w.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
            let (revoke, device, cap) = (o.has("revoke"), o.has("device"), o.cap.unwrap_or(0));
            async move {
                let r = match w.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                    ["approve", donor] => c.approve(ApproveRequest { repo: slug, donor: (*donor).into(), dry_run, revoke }).await,
                    ["members", op, user] => {
                        let op = if *op == "add" { Op::Add } else { Op::Remove };
                        c.members(MembersRequest { repo: slug, op: op as i32, user: (*user).into(), cap_uusd_month: cap, device, dry_run }).await
                    }
                    _ => c.claim(ClaimRequest { repo: slug, dry_run }).await,
                };
                r.map(tonic::Response::into_inner).map_err(|s| match s.code() {
                    tonic::Code::NotFound | tonic::Code::FailedPrecondition | tonic::Code::InvalidArgument => usage(clean(s.message()).into_owned()),
                    _ => internal(clean(s.message()).into_owned()),
                })
            }
        };
        let preview = call(&mut c, true).await?;
        eprintln!(
            "You are about to sign {} for {} ({}):\n  for     {} ({})\n  signer  {} (this device)\n  issued  {} ms",
            preview.kind, preview.repo_slug, preview.repo_id, preview.subject, preview.subject_username, preview.signer, preview.issued_at_ms
        );
        if !o.has("yes") {
            if !std::io::stdin().is_terminal() {
                return Err(usage("pass --yes to sign non-interactively"));
            }
            eprint!("Sign it? [y/N] ");
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            if !matches!(line.trim(), "y" | "Y" | "yes") {
                return Err(usage("not signed"));
            }
        }
        let done = call(&mut c, false).await?;
        emit(&sign_json(&done));
        Ok(())
    })
}

/// `moochy report <task> [--out file] [--reason text]`: evidence bundle (06 §9).
fn report(home: &Home, o: &Opts, task: &str) -> Result<()> {
    let reason = o.reason.clone().unwrap_or_default();
    let r = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.report(crate::pb::local::ReportRequest { task: task.into(), reason }).await.map_err(|s| usage(clean(s.message()).into_owned()))
    })?;
    let bundle = r.into_inner().bundle;
    match &o.out {
        Some(p) => {
            crate::config::write_private(p, &bundle)?;
            emit(&json!({"event": "report", "task": task, "out": p.display().to_string()}));
        }
        None => println!("{}", String::from_utf8_lossy(&bundle)),
    }
    Ok(())
}

/// `moochy doctor`: keystore, relay, clock, provider keys, firewall, control socket.
fn doctor(home: &Home) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let cfg = home.load()?;
    let mut bad = 0u32;
    let mut line = |ok: bool, what: &str, detail: String| {
        if !ok {
            bad = bad.saturating_add(1);
        }
        println!("{} {what:<9} {}", if ok { "ok  " } else { "FAIL" }, clean(&detail));
    };
    match keystore::load(home, &cfg) {
        Ok(Some(s)) => line(true, "keystore", format!("opens ({}), device keys {}", cfg.keystore.as_deref().unwrap_or("file"), if s.device.is_some() { "present" } else { "absent" })),
        Ok(None) => line(false, "keystore", "no keystore: run `moochy login`".into()),
        Err(e) => line(false, "keystore", e.msg),
    }
    let st = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await.ok()?;
        c.status(StatusRequest {}).await.ok().map(tonic::Response::into_inner)
    });
    if let Some(s) = &st {
        line(s.link_state == "up" || s.link_state == "offline", "relay", format!("{} ({})", s.relay, s.link_state));
        let skew = s.clock_skew_ms.unsigned_abs();
        line(skew <= 300_000, "clock", format!("skew vs relay {} ms (limit ±5 min)", s.clock_skew_ms));
        line(true, "providers", format!("{} key(s), {} warm adapter(s), catalog v{}", s.provider_keys, s.warm_adapters, s.catalog_version));
    } else {
        line(false, "relay", "the Moochy app is not running (start it with `moochy up`)".into());
        line(false, "clock", "unknown: measured when the app connects".into());
    }
    line(true, "safety", format!("checks level {}, tables of moochy-worker {}", cfg.firewall_level.as_deref().unwrap_or("strict"), env!("CARGO_PKG_VERSION")));
    let me = std::fs::metadata(&home.dir).map(|m| m.uid()).ok();
    match std::fs::metadata(home.socket_path()) {
        Ok(m) => line(Some(m.uid()) == me && m.mode() & 0o777 == 0o600, "socket", format!("node.sock uid {} mode {:o}", m.uid(), m.mode() & 0o777)),
        Err(_) => line(st.is_none(), "socket", "no node.sock".into()),
    }
    if bad > 0 && st.is_some() {
        return Err(Error { exit: crate::util::Exit::Internal, msg: format!("{bad} check(s) failed") });
    }
    Ok(())
}

/// `moochy update --from-file <binary>`: replaces nothing unless the release signature verifies.
fn update(o: &Opts) -> Result<()> {
    let Some(f) = &o.from_file else {
        return Err(usage("update --from-file <binary>: a signed release (check where it came from with `gh attestation verify` or `cosign verify-blob`)"));
    };
    // ponytail: no release-signing key is pinned yet, so every candidate is refused (fail closed).
    Err(auth(format!("refusing {}: no valid release signature (unsigned or unknown key)", f.display())))
}

fn connect(home: &Home, o: &Opts, client: &str) -> Result<()> {
    let slug = slug_or_detect(o)?;
    let (url, models) = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let st = c.status(StatusRequest {}).await.map_err(|s| internal(s.message().to_owned()))?.into_inner();
        let models: Vec<String> = st.pools.iter().find(|p| p.slug.eq_ignore_ascii_case(&slug)).map(|p| p.models.clone()).unwrap_or_default();
        Ok::<_, Error>((st.gateway_url, models))
    })?;
    let main = clean(models.first().map_or("MODEL", String::as_str)).into_owned();
    let small = clean(models.get(1).map_or(main.as_str(), String::as_str)).into_owned();
    if !o.has("write") {
        let s = crate::connect::snippet(client, &url, &slug, &main, &small).ok_or_else(|| usage(format!("unknown client; one of: {}", crate::connect::CLIENTS.join(", "))))?;
        print!("{s}");
        return Ok(());
    }
    connect_write(o, client, &url, &slug, &main, &small)
}

/// `connect --write`: merge into the client's user-scoped config after showing a diff (06 §13:
/// never into a git-tracked file, never a token).
fn connect_write(o: &Opts, client: &str, url: &str, slug: &str, main: &str, small: &str) -> Result<()> {
    use std::io::IsTerminal as _;
    let user_home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| usage("HOME is not set"))?;
    let (default_path, plan) = crate::connect::write_plan(client, &user_home, slug, url, main, small)
        .ok_or_else(|| usage(format!("--write is not supported for {client} (YAML/env based): paste the snippet from `moochy connect {client}`")))?;
    let path = o.config.clone().unwrap_or(default_path);
    let path = std::path::absolute(&path).ctx("config path")?;
    if git_tracked(&path) {
        return Err(usage(format!("refusing to write {}: the file is tracked by git (tokens and machine paths do not belong in a repository)", path.display())));
    }
    let old = match std::fs::read(&path) {
        Ok(b) => String::from_utf8(b).map_err(|_| usage("config file is not UTF-8"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(internal(format!("read {}: {e}", path.display()))),
    };
    let mut v = if old.trim().is_empty() {
        json!({})
    } else {
        crate::json::parse(old.as_bytes()).map_err(|e| usage(format!("{} is not plain JSON ({e}); edit it by hand with the snippet", path.display())))?
    };
    if !crate::connect::merge(&mut v, &plan) {
        return Err(usage(format!("{} does not have the expected JSON shape", path.display())));
    }
    let new = serde_json::to_string_pretty(&v).ctx("encode config")?;
    let pretty_old = if old.trim().is_empty() { String::new() } else { serde_json::to_string_pretty(&crate::json::parse(old.as_bytes()).unwrap_or_default()).unwrap_or_default() };
    if pretty_old == new {
        emit(&json!({"event": "connect", "client": client, "path": path.display().to_string(), "changed": false}));
        return Ok(());
    }
    print!("--- {0}\n+++ {0}\n{1}", path.display(), crate::connect::diff(&pretty_old, &new));
    if !o.has("yes") {
        if std::io::stdin().is_terminal() {
            eprint!("Write these changes? [y/N] ");
        }
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            return Err(usage("not written"));
        }
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ctx("create config dir")?;
    }
    crate::config::write_private(&path, format!("{new}\n").as_bytes())?;
    emit(&json!({"event": "connect", "client": client, "path": path.display().to_string(), "changed": true}));
    Ok(())
}

/// Is `path` tracked by git (in whatever repository contains it)?
fn git_tracked(path: &std::path::Path) -> bool {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else { return false };
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn keys_add(home: &Home, provider: &str, o: &Opts) -> Result<()> {
    if !crate::keycheck::PROVIDERS.contains(&provider) {
        return Err(usage(format!("provider must be one of: {}", crate::keycheck::PROVIDERS.join(", "))));
    }
    if !o.has("key-stdin") {
        return Err(usage("pass the key on stdin with --key-stdin (never as an argument)"));
    }
    if let Some(u) = &o.base_url {
        crate::keycheck::check_base_url(u, dev_mode())?;
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
    crate::keycheck::refuse_consumer_credential(provider, &key)?;
    // Validated with a free models call before anything is stored (06 §4.2).
    rt_small()?.block_on(crate::keycheck::validate(provider, &key, o.base_url.as_deref()))?;
    let mut cfg = home.load()?;
    let mut sec = keystore::load_or_init(home, &mut cfg)?;
    sec.providers.retain(|p| p.provider != provider);
    sec.providers.push(ProviderKey { provider: provider.into(), key: key.to_string(), base_url: o.base_url.clone() });
    keystore::save(home, &cfg, &sec)?;
    emit(&json!({"event": "key_added", "provider": provider}));
    Ok(())
}

fn up_background(home: &Home, o: &Opts) -> Result<()> {
    let line = start_node(home, o.has("offline"))?;
    print!("{line}");
    Ok(())
}

/// Start `up --foreground` detached and wait for its ready line (returned, not printed).
fn start_node(home: &Home, offline: bool) -> Result<String> {
    use std::io::BufRead as _;
    use std::os::unix::process::CommandExt as _;
    home.ensure()?;
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(home.state_dir().join("node.log")).ctx("open node.log")?;
    let exe = std::env::current_exe().ctx("current exe")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--home").arg(&home.dir).args(["up", "--foreground"]);
    if offline {
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
        return Ok(line);
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

/// Provider adapters (one per stored key) and the outbox store.
fn worker_parts(home: &Home, secrets: &keystore::Secrets) -> Result<WorkerParts> {
    use moochy_worker::provider::{Adapter, AdapterConfig, Limits};
    let mut adapters = Vec::new();
    for p in &secrets.providers {
        let Some(provider) = moochy_worker::Provider::parse(&p.provider) else {
            log("warn", "this version cannot donate with this provider yet; update moochy", &json!({"provider": p.provider}));
            continue;
        };
        // `--base-url` replaces the provider origin only; moochy-worker owns the per-dialect paths.
        let base_url = p.base_url.clone();
        let cfg = AdapterConfig {
            provider,
            api_key: zeroize::Zeroizing::new(p.key.clone()),
            base_url,
            insecure_dev: dev_mode(),
            dev_root: None,
            limits: Limits::default(),
        };
        match Adapter::new(&cfg) {
            Ok(a) => adapters.push(Arc::new(a)),
            Err(e) => log("error", "provider key not usable", &json!({"provider": p.provider, "error": e.to_string()})),
        }
    }
    let store = moochy_worker::store::Store::open(&home.state_dir().join("worker.log"), crate::util::now_ms()).ctx("open worker store")?;
    Ok(WorkerParts { adapters, store: Some(Arc::new(std::sync::Mutex::new(store))) })
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
    if cfg.gateway_addr.is_none() {
        // First start: keep this port so clients keep a stable base URL (CONTRACT §6).
        cfg.gateway_addr = Some(format!("127.0.0.1:{port}"));
        home.save(&cfg)?;
    }
    let sock_path = home.socket_path();
    let sock = crate::ctl::bind(&sock_path).await?;
    let keys = match (&secrets.device, cfg.device_id.as_deref()) {
        (Some(d), Some(id)) => Some(Keys { sign: d.sign_key(), enc: d.enc_key()?, device_id: id.parse().map_err(|_| auth("stored device id is invalid"))? }),
        _ => None,
    };
    let parts = if cfg.has_role("worker") && keys.is_some() && !offline { worker_parts(&home, &secrets)? } else { WorkerParts::default() };
    let node = Node::new(home.clone(), cfg, secrets, keys, parts, offline);
    node.gateway_port.store(u32::from(port), Ordering::Relaxed);
    tokio::spawn(crate::gateway::serve(node.clone(), listener));
    tokio::spawn(crate::ctl::serve(node.clone(), sock, sock_path.clone()));
    if !node.adapters.is_empty() {
        tokio::spawn(crate::worker::warm_loop(node.clone()));
    }
    match (&node.keylog, node.cfg.log_anchor_url.clone()) {
        (Some(l), Some(u)) => {
            tokio::spawn(l.clone().anchor_loop(u, node.shutdown.subscribe()));
        }
        (None, _) if !offline => log("warn", "no key-log key pinned (log_key): approvals and memberships are relay-asserted", &json!({})),
        _ => {}
    }
    if !offline {
        tokio::spawn(crate::link::run(node.clone()));
        match crate::link::wait_first(&node, Duration::from_secs(5)).await {
            Err(e) if e.exit == crate::util::Exit::Auth => return Err(e),
            Err(e) => log("warn", "starting without the relay link", &json!({"error": e.msg})),
            Ok(()) => {
                // The relay sends the catalog right after Welcome; give it a moment.
                for _ in 0..100 {
                    if node.catalog().version > 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
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
    // The shim starts the node when none is running (07 §5); stdout stays the MCP channel.
    if rt_small()?.block_on(crate::ctl::connect(&home.socket_path())).is_err() {
        start_node(home, false)?;
    }
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

