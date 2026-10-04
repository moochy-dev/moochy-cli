//! Command line (CONTRACT §6): tiny `lexopt` parser, JSON event lines on stdout, exit codes
//! 0 ok, 2 usage, 3 auth/approval refused, 4 network, 10 internal.

use crate::config::{Home, RepoEntry};
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
PROJECT: owner/name or github/owner/name (GitHub), gitlab/group[/subgroup…]/name (GitLab);
         default: the github.com or gitlab.com `origin` remote of the current directory

COMMANDS:
  tui [--demo] [--snapshot COLSxROWS [--keys K] [--ansi]] [--theme light|dark] [--ascii]
                                  The dashboard in your terminal (also: `moochy` alone)
  login [--relay URL] [--ca-file PEM] [--log-key VKEY] [--roles gateway,worker] [--name NAME] [--headless] [--no-browser]
                                  Add this device to your account (opens the approval page). Roles: gateway uses donated
                                  tokens, worker donates yours. Only the default server unless
                                  MOOCHY_INSECURE_DEV=1 (a separate keystore per server)
  logout                          Remove this device: revoke its keys, then delete them here
  up [--foreground] [--headless] [--unsafe-no-lockdown]
                                  Start the Moochy app on this machine. It locks itself down
                                  (no commands, files limited to its state); the flag disables
                                  that for debugging only. In a cloud box, MOOCHY_ENROLL=<token>
                                  enrolls the box first (its own keys, one project, expiring)
  down                            Stop it
  status [--json]                 Connection, slots in use, donations available to your projects
  pause | resume                  Stop or restart donating from this device (works offline)
  journal [--follow]              Recent requests (never prompts or outputs)
  env [--repo PROJECT] [--json] [--rotate]
                                  Base URLs and a project token for your tools
  mcp [--repo PROJECT]            MCP server on stdio (needs `moochy up`)
  run [--repo PROJECT] [--worktree DIR] [--allow-host HOST]... [--git-writable]
      [--unsafe-no-sandbox | --box-is-sandbox] -- <cmd>
                                  Run your coding agent in a sandbox wired to Moochy: it sees only
                                  this repository (secrets hidden) and reaches only Moochy. Tool
                                  calls from donated tokens reach only sandboxed agents.
                                  --box-is-sandbox: in a single-purpose cloud box without user
                                  namespaces or Landlock, the box itself is the sandbox
  box token create [--repo PROJECT] [--ttl 24h] [--cap $20] [--max-boxes 1]
                                  A token that lets cloud boxes (boat.dev, E2B, Daytona, Modal,
                                  Codespaces) use this project's donations: each box gets its own
                                  keys, its own monthly limit and expires with the token. Shown once
  box token list [--repo P] | box token revoke <bt_…>
  box list [--repo P] | box revoke <d_…>
                                  Boxes enrolled for your projects; revoke one, or a token and all
                                  its boxes
  keys add <anthropic|openai|openrouter|deepseek|xai> --key-stdin [--base-url URL]
                                  Add a provider API key (xai = Grok). It is checked with the
                                  provider's free models call and never leaves this machine
  keys add local --base-url http://127.0.0.1:11434 --model local/<slug>=<server id> [--key-stdin]
                                  Donate your own GPU: an OpenAI-compatible server on this
                                  machine or your LAN (Ollama, LM Studio, vLLM, llama.cpp)
  service install [--system] [--print] | service uninstall [--system]
                                  Start Moochy at login (systemd user unit, launchd agent);
                                  --print shows the unit only
  button [--repo P] [--provider github|gitlab] [--style mascot|text|compact] [--theme light|dark|auto]
         [--size s|m|l] [--label TEXT] [--format markdown|html|rst]
                                  The README Donate tokens button for this repository
  button --chart [--repo P|--org ORG|--person PERSON] [--metric tokens|dollars] [--series both|donated|used]
         [--kind area|bars|line|sparkline] [--period 7d|30d|90d|12m] [--theme light|dark|auto]
         [--size s|m|l] [--label TEXT] [--goal] [--total] [--format markdown|html|rst|iframe]
                                  A live chart of the tokens donated to and used by the
                                  project or organisation (README image or website card)
  audit --provider [--from-file usage.csv]
                                  What this device served (90 days), checked against the
                                  provider's usage export (date,model,cost_usd)
  safety [--monthly-limit $N] [--accept-safety]
                                  The safety step before donating: a monthly limit for this
                                  machine, and a provider-side spend limit (required once)
  keys list | keys remove <provider> | keys rotate
                                  rotate = new device keys for this machine (the old ones stop
                                  working 24 h later)
  keys revoke <device id>         Remove another device from your account (e.g. one you did
                                  not add); this one: `moochy logout`
  config set <KEY> <VALUE> | config show
                                  monthly_limit (dollars, e.g. 20), slots_max (1-64),
                                  gateway_addr, journal_full_text, auto_cache,
                                  firewall_level (safety checks: strict or paranoid),
                                  allow_unsandboxed_tools (owner/name list: tool calls reach
                                  agents outside `moochy run`; warned at every start)
  connect <client> [--repo PROJECT] [--write]
                                  Show the setup for a coding tool, or merge it into the
                                  tool's config with --write (`connect list` shows the tools)
  report <task> [--reason TEXT]   Save signed evidence about a bad response
  verify <receipt_ref>            Check a public receipt of your request: donor signature,
                                  link to the signed receipt, public key log
  doctor                          Check the keystore, connection, clock, provider keys, socket
                                  and the sandbox support of this machine
  update --from-file BINARY       Install a signed release (unsigned files are refused)
  donate --repo PROJECT | --org ORG | --person PERSON --cap $N [--weekly-limit $N]
         [--daily-limit $N] [--yes]
                                  Donate tokens to a project, up to $N a month (it starts once
                                  the project owner accepts you); optional weekly (Monday 00:00
                                  UTC) and daily (00:00 UTC) limits, no higher than the monthly
                                  one; --org donates to an organisation
                                  (github/ORG or gitlab/GROUP[/SUB…]), shared by the projects its
                                  owner covers; --person sponsors a maintainer (github/LOGIN or
                                  gitlab/USERNAME): their own requests on the repos they cover
  donations [--json] | donations <pause|resume|stop> <id>
                                  Your donations: what each project or organisation used this month
  owner trust <ok_id>             Mark an owner key you created elsewhere (a passkey added on
                                  the web) as yours, so the key-log monitor stops alerting
  owner init | owner rotate       Create (or replace) your owner key: a separate key, encrypted
                                  with its own passphrase, that signs approvals, memberships and
                                  claims; only used by these commands, never by the app
  owner status                    Your owner key in the public key log and how it was bound
                                  (confirmed email, passkey, rotation, or before the email rule)
  pending                         Requests waiting for your signature (maintainers)
  decisions [--repo PROJECT | --org ORG | --person PERSON] [--json] | decisions refuse <id> [--reason TEXT] [--yes]
            | decisions accept <id>
                                  Donors asking to donate to your projects, and what was decided
                                  (who, when, how); accepting is signed with your passkey on the web
  accept <donor> --repo PROJECT | --org ORG | --person [PERSON] [--revoke] [--yes]
                                  Accept a donor for your project, or once for your organisation
                                  or your person profile
                                  (--revoke removes them); `approve` is the same command
  members <add|remove> <user> --repo PROJECT [--device] [--cap $N | --cap-uusd N] [--yes]
                                  Let a person (or a CI device) use your project's donations,
                                  up to $N a month
  claim <PROJECT> [--yes]         Confirm you maintain a project, signed by your owner key
                                  (also: claim --repo PROJECT)
  claim --org ORG [--yes]         Confirm you own an organisation (github/ORG: an admin;
                                  gitlab/GROUP[/SUB…]: an Owner)
  org <add|remove> <PROJECT> --org ORG [--yes] | org list --org ORG [--json]
                                  Which of your projects your organisation's donations fund
  claim --person [PERSON] [--yes] Confirm your own GitHub/GitLab profile (after signing in on
                                  the web: Claim your profile), so people can sponsor you
  person <add|remove> <PROJECT> [--person PERSON] [--yes] | person list [--person PERSON] [--json]
                                  Which public repos you maintain your sponsors' tokens serve
                                  (your own requests only)

ENV: MOOCHY_HOME, MOOCHY_PASSPHRASE (encrypted-file keystore), MOOCHY_ENROLL (cloud box enrollment token),
     MOOCHY_INSECURE_DEV=1 (development only)
";

pub fn main() -> ExitCode {
    // The validator zygote (CONTRACT §15.2): nothing else may run before it.
    if let Some(code) = crate::validator::zygote_entry() {
        return ExitCode::from(code);
    }
    // The keychain read helper (keystore::keychain::get_in_child): print one entry and exit.
    if let Some(code) = crate::keystore::keychain::helper_entry() {
        return ExitCode::from(code);
    }
    quiet_broken_pipe();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            emit_err(&e);
            ExitCode::from(e.exit as u8)
        }
    }
}

/// m3: `moochy donations | head -1`. Rust ignores SIGPIPE, so a closed stdout makes `println!`
/// panic, and `panic = "abort"` dumps core. A reader that stopped reading is not an error: exit 0
/// quietly. Installed after the validator zygote and the keychain helper (nothing may run before
/// them), and no signal disposition changes: the node's sockets keep reporting EPIPE as errors.
fn quiet_broken_pipe() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info.payload().downcast_ref::<String>().map_or("", String::as_str);
        if msg.starts_with("failed printing to stdout") && msg.contains("Broken pipe") {
            std::process::exit(0);
        }
        default(info);
    }));
}

fn emit_err(e: &Error) {
    let code = match e.exit {
        crate::util::Exit::Usage => "usage",
        crate::util::Exit::Auth => "auth",
        crate::util::Exit::Network => "network",
        crate::util::Exit::Internal => "internal",
    };
    let p = crate::style::err();
    if p.tty {
        eprintln!("{}{} {}", p.mark(false), p.bad(&format!("{code} error:")), crate::util::clean(&e.msg));
    } else {
        eprintln!("{}", crate::util::clean_value(&json!({"event":"error","code":code,"message":e.msg})));
    }
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
    /// `moochy button`: label, style, theme, size, format.
    button: crate::button::Options,
    monthly_limit: Option<u64>,
    words: Vec<String>,
    relay: Option<String>,
    ca_file: Option<PathBuf>,
    roles: Option<String>,
    name: Option<String>,
    repo: Option<String>,
    /// CONTRACT §19: an organisation (`github/acme`, `gitlab/group[/sub…]`), never with `--repo`.
    org: Option<String>,
    /// CONTRACT §24: a person profile (`github/LOGIN`, `gitlab/USERNAME`); `Some("")` = bare
    /// `--person` (your own profile, from the requests the app was pushed).
    person: Option<String>,
    base_url: Option<String>,
    cap: Option<i64>,
    /// `moochy donate`: optional weekly and daily limits (D19a), µ$.
    weekly_limit: Option<i64>,
    daily_limit: Option<i64>,
    out: Option<PathBuf>,
    reason: Option<String>,
    from_file: Option<PathBuf>,
    log_key: Option<String>,
    models: Vec<String>,
    cert_sha256: Option<String>,
    auth_header: Option<String>,
    confirm_host: Option<String>,
    worktree: Option<PathBuf>,
    allow_hosts: Vec<String>,
    /// `moochy box token create`: `--ttl`, `--max-boxes`.
    ttl: Option<String>,
    max_boxes: Option<u32>,
    config: Option<PathBuf>,
    flags: Vec<&'static str>,
}

impl Opts {
    fn has(&self, f: &str) -> bool {
        self.flags.contains(&f)
    }
}

/// `--person` takes a value only when one follows (`--person github/x`, `--person=github/x`): bare
/// `--person` names your own profile (`moochy claim --person`).
fn person_value(p: &mut lexopt::Parser) -> Result<String> {
    if let Some(v) = p.optional_value() {
        return s(v);
    }
    let Ok(mut raw) = p.raw_args() else { return Ok(String::new()) };
    match raw.peek().and_then(|a| a.to_str()) {
        Some(v) if v.contains('/') && !v.starts_with('-') => {
            let v = v.to_owned();
            raw.next();
            Ok(v)
        }
        _ => Ok(String::new()),
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
            Long("org") => o.org = Some(s(p.value().map_err(err)?)?),
            Long("person") => o.person = Some(person_value(&mut p)?),
            Long("base-url" | "url") => o.base_url = Some(s(p.value().map_err(err)?)?),
            Long("cert-sha256") => o.cert_sha256 = Some(s(p.value().map_err(err)?)?),
            Long("header-from-keystore") => o.auth_header = Some(s(p.value().map_err(err)?)?),
            Long("confirm-host") => o.confirm_host = Some(s(p.value().map_err(err)?)?),
            Long("out") => o.out = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("reason") => o.reason = Some(s(p.value().map_err(err)?)?),
            Long("label") => o.button.label = Some(s(p.value().map_err(err)?)?),
            Long("style") => o.button.style = Some(s(p.value().map_err(err)?)?),
            Long("theme") => o.button.theme = Some(s(p.value().map_err(err)?)?),
            Long("size") => o.button.size = Some(s(p.value().map_err(err)?)?),
            Long("format") => o.button.format = Some(s(p.value().map_err(err)?)?),
            Long("metric") => o.button.metric = Some(s(p.value().map_err(err)?)?),
            Long("series") => o.button.series = Some(s(p.value().map_err(err)?)?),
            Long("kind") => o.button.kind = Some(s(p.value().map_err(err)?)?),
            Long("period") => o.button.period = Some(s(p.value().map_err(err)?)?),
            Long("goal") => o.button.goal = true,
            Long("total") => o.button.total = true,
            Long("from-file") => o.from_file = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("allow-host") => o.allow_hosts.push(s(p.value().map_err(err)?)?),
            Long("worktree") => o.worktree = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("config") => o.config = Some(PathBuf::from(p.value().map_err(err)?)),
            Long("ttl") => o.ttl = Some(s(p.value().map_err(err)?)?),
            Long("max-boxes") => o.max_boxes = Some(s(p.value().map_err(err)?)?.parse().map_err(|_| usage("--max-boxes is a whole number"))?),
            Long("model") => o.models.push(s(p.value().map_err(err)?)?),
            Long("log-key") => o.log_key = Some(s(p.value().map_err(err)?)?),
            Long("budget-uusd") => o.cap = Some(s(p.value().map_err(err)?)?.parse().map_err(|_| usage("--budget-uusd is a whole number of millionths of a dollar"))?),
            Long("monthly-limit") => {
                o.monthly_limit = Some(crate::config::device_limit(&s(p.value().map_err(err)?)?)?);
            }
            Long("cap-uusd") => o.cap = Some(s(p.value().map_err(err)?)?.parse().map_err(|_| usage("--cap-uusd is a whole number of millionths of a dollar"))?),
            Long("cap") => {
                let v = crate::util::parse_amount(&s(p.value().map_err(err)?)?).map_err(|e| usage(format!("--cap (a monthly amount in dollars): {e}")))?;
                o.cap = Some(i64::try_from(v).map_err(|_| usage("--cap is too large"))?);
            }
            Long("weekly-limit") => o.weekly_limit = Some(window_amount(&s(p.value().map_err(err)?)?, "weekly")?),
            Long("daily-limit") => o.daily_limit = Some(window_amount(&s(p.value().map_err(err)?)?, "daily")?),
            Long("help") | Short('h') => o.flags.push("help"),
            Long("version") | Short('V') => o.flags.push("version"),
            Long(f) => {
                let known = ["headless", "no-browser", "foreground", "offline", "json", "rotate", "follow", "key-stdin", "shell", "yes", "revoke", "device", "write", "unsafe-no-lockdown", "unsafe-no-sandbox", "git-writable", "allow-unvetted-host", "accept-safety", "system", "print", "provider", "box-is-sandbox", "chart"];
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

/// `moochy [--home DIR] tui [TUI OPTIONS]`: the TUI's own flags (CONTRACT §20.4) go to
/// `moochy-tui` unparsed. `None` when the command is not `tui`.
fn tui_argv() -> Option<(Option<PathBuf>, Vec<String>)> {
    let mut a = std::env::args_os().skip(1);
    let mut home = None;
    loop {
        let w = a.next()?.into_string().ok()?;
        match w.as_str() {
            "--home" => home = Some(PathBuf::from(a.next()?)),
            "tui" => break,
            _ => return None,
        }
    }
    let mut rest = Vec::new();
    while let Some(w) = a.next() {
        let w = w.into_string().ok()?;
        if w == "--home" {
            home = Some(PathBuf::from(a.next()?));
        } else {
            rest.push(w);
        }
    }
    Some((home, rest))
}

/// CONTRACT §20: the dashboard, over `node.sock` (or the demo fixtures, which need no node).
fn tui(home: Option<PathBuf>, args: &[String]) -> Result<()> {
    let opts = moochy_tui::Options::parse(args).map_err(usage)?;
    if opts.demo || opts.hostile {
        let mut src = moochy_tui::fixture_source(&opts);
        if opts.snapshot.is_some() {
            print!("{}", moochy_tui::snapshot(&mut src, &opts).map_err(internal)?);
            return Ok(());
        }
        return moochy_tui::run(Box::new(src), None, &opts).map_err(internal);
    }
    let mut src = crate::tuisrc::NodeSource::new(Home::resolve(home)?).map_err(internal)?;
    if opts.snapshot.is_some() {
        print!("{}", moochy_tui::snapshot(&mut src, &opts).map_err(internal)?);
        return Ok(());
    }
    let events = src.events();
    moochy_tui::run(Box::new(src), Some(events), &opts).map_err(internal)
}

#[allow(clippy::too_many_lines, reason = "the command dispatch table")]
fn run() -> Result<()> {
    if let Some((home, args)) = tui_argv() {
        return tui(home, &args);
    }
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
        use std::io::IsTerminal as _;
        // CONTRACT §20.1: `moochy` alone on an interactive terminal opens the dashboard.
        if o.flags.is_empty() && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            return tui(o.home.clone(), &[]);
        }
        eprint!("{HELP}");
        return Err(usage("missing command"));
    }
    let home = Home::resolve(o.home.clone())?;
    let donor: String;
    let mut w: Vec<&str> = o.words.iter().map(String::as_str).collect();
    // M6: `accept p_…` names the donation request that `pending` and `decisions` print.
    if let ["approve" | "accept", d] = w.as_slice()
        && d.starts_with("p_")
    {
        donor = donor_of_request(&home, d)?;
        if let Some(x) = w.get_mut(1) {
            *x = donor.as_str();
        }
    }
    // A cloud box (§17.1) has no owner powers and no donor role.
    if let [cmd @ ("approve" | "accept" | "claim" | "members" | "owner" | "org" | "person" | "pending" | "decisions" | "box" | "donate" | "safety" | "audit"), ..] | [cmd @ "keys", "add" | "revoke", ..] = w.as_slice() {
        crate::boxes::refuse_on_box(&home.load()?, cmd)?;
    }
    match w.as_slice() {
        ["login"] => login_cmd(&home, &o),
        ["logout"] => logout(&home, &o),
        ["report", task] => report(&home, &o, task),
        ["doctor"] => doctor(&home),
        ["update"] => update(&o),
        ["keys", "rotate"] => crate::owner::rotate_device(&home),
        ["keys", "revoke", id] => crate::owner::revoke_device(&home, id),
        ["up"] => {
            if o.has("offline") && !dev_mode() {
                return Err(usage("--offline requires MOOCHY_INSECURE_DEV=1"));
            }
            // M4: a second `up` is not an error: say so and show the running app.
            if !o.has("foreground") && running(&home) {
                eprintln!("Moochy is already running for this --home (`moochy down` stops it).");
                return status(&home, o.has("json"));
            }
            box_enroll(&home, &o)?;
            if o.has("foreground") { up_foreground(home, o.has("offline"), o.has("unsafe-no-lockdown")) } else { up_background(&home, &o) }
        }
        ["down"] => down(&home),
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
        ["safety"] => {
            if safety(&home, &o, None)? {
                restart_note(&home, "settings");
            }
            Ok(())
        }
        ["button", rest @ ..] => button(&o, rest),
        ["audit"] if o.has("provider") => audit(&home, &o),
        ["service", "install"] => crate::service::install(&home, o.has("system"), o.has("print")),
        ["service", "uninstall"] => crate::service::uninstall(o.has("system")),
        ["run", cmd @ ..] => run_cmd(&home, &o, cmd),
        ["box", rest @ ..] => box_cmd(&home, &o, rest),
        ["mcp"] => mcp(&home, &o),
        ["keys", "add", provider] => {
            keys_add(&home, provider, &o)?;
            restart_note(&home, "key");
            Ok(())
        }
        ["keys", "remove", _] => {
            keys_cmd(&home, &w)?;
            restart_note(&home, "keys");
            Ok(())
        }
        ["keys", "list" | "remove", ..] => keys_cmd(&home, &w),
        ["config", "set", key, value] => {
            let mut cfg = home.load()?;
            cfg.set(key, value)?;
            home.save(&cfg)?;
            emit(&json!({"event": "config_set", "key": key}));
            restart_note(&home, "settings");
            Ok(())
        }
        ["config", "show"] => {
            let cfg = home.load()?;
            println!("{}", crate::util::clean_value(&serde_json::to_value(&cfg).ctx("config")?));
            Ok(())
        }
        ["claim"] | ["approve" | "accept", _] if o.person.is_some() => person_cmd(&home, &o, &w),
        ["person", ..] => person_cmd(&home, &o, &w),
        ["claim"] | ["approve" | "accept", _] if o.org.is_some() => org_cmd(&home, &o, &w),
        ["org", ..] => org_cmd(&home, &o, &w),
        ["approve" | "claim", _] | ["members", "add" | "remove", _] | ["claim"] => owner_ops(&home, &o, &w),
        ["verify", r] => rt_small()?.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            let v = c.verify(crate::pb::local::VerifyRequest { receipt_ref: (*r).into() }).await.map_err(|s| auth(format!("not verified: {}", clean(s.message()))))?;
            let mut v = crate::json::parse(v.into_inner().result_json.as_bytes()).map_err(|_| internal("malformed answer from the app"))?;
            // m13: the public page of the signed receipt (pages show `r_` + the reference).
            if let Some(o) = v.as_object_mut() {
                o.insert("receipt_url".into(), json!(format!("{}/r/r_{}", crate::decisions::web_origin(&home), crate::util::bare_receipt_ref(r))));
            }
            emit(&v);
            Ok(())
        }),
        ["donate"] => donate(&home, &o),
        // `pledges` is the internal name, kept as a hidden alias (VOICE.md shows "donations").
        ["donations" | "pledges"] => crate::donations::list(&home, o.has("json")),
        ["donations", act, id] => crate::donations::action(&home, act, id),
        ["decisions", rest @ ..] => decisions_cmd(&home, &o, rest),
        ["owner", "init"] => crate::owner::init(&home, false),
        ["owner", "status"] => crate::owner::show_status(&home),
        ["owner", "trust", id] => crate::owner::trust(&home, id, o.has("yes")),
        ["owner", "rotate"] => crate::owner::init(&home, true),
        // VOICE.md: "accept a donor".
        ["accept", donor] => owner_ops(&home, &o, &["approve", donor]),
        ["pending"] => rt_small()?.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            let r = c.pending(crate::pb::local::PendingRequest {}).await.map_err(|s| internal(clean(s.message()).into_owned()))?.into_inner();
            // Standing offers the relay pushes (members that can be removed, devices without a
            // cap, accepted donors, covered projects) are actions, not things waiting: `members remove` /
            // `members add --device` / `approve --revoke` / `org remove` use them.
            for q in r.requests.iter().filter(|q| !STANDING.iter().any(|p| q.request_id.starts_with(p))) {
                let mut v = sign_json(q);
                // A228: a REPO_CLAIMED signs within an hour of its code-host check; the relay
                // pushed this one more than an hour ago, so that check has expired.
                let pushed = u64::try_from(q.issued_at_ms).unwrap_or(0);
                if q.kind == "REPO_CLAIMED"
                    && crate::util::now_ms().saturating_sub(pushed) > 3_600_000
                    && let Some(o) = v.as_object_mut()
                {
                    o.insert("expired".into(), json!(true));
                    eprintln!("{}: this claim's code-host check expired (1 hour): do the web step again (Add a repository on moochy.dev), then run `moochy claim {}` within one hour", clean(&q.repo_slug), clean(&q.repo_slug));
                }
                emit(&v);
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
                let mut v = json!({"provider": p.provider, "base_url": p.base_url, "key": format!("…{}", p.key.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect::<String>())});
                // A remote GPU server (§17.3): vetted host and checks, never the header value.
                if let (Some(h), Some(o)) = (&p.remote_host, v.as_object_mut()) {
                    o.insert("remote".into(), json!(h));
                    o.insert("trust".into(), json!(crate::keycheck::trust_name(p)));
                    o.insert("auth_header".into(), json!(p.auth_header));
                    o.remove("key");
                }
                emit(&v);
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

/// The app answers on its control socket.
fn running(home: &Home) -> bool {
    rt_small().is_ok_and(|rt| rt.block_on(crate::ctl::connect(&home.socket_path())).is_ok())
}

/// M2: the running app read its keys and settings once, at start: the keychain is read by a child
/// process before the lockdown, which forbids starting one afterwards, and the lockdown fixed the
/// provider ports it may reach. A change applies at the next start: say so.
fn restart_note(home: &Home, what: &str) {
    if running(home) {
        eprintln!("The app is running: restart it with `moochy down && moochy up` to use the new {what}.");
    }
}

/// M6: the donor a pending donation request (`p_…`) asks to accept: their handle (then checked with
/// the server, A218), else their pseudonym.
fn donor_of_request(home: &Home, id: &str) -> Result<String> {
    let r = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.pending(crate::pb::local::PendingRequest {}).await.map(tonic::Response::into_inner).map_err(|s| internal(clean(s.message()).into_owned()))
    })?;
    let q = r
        .requests
        .iter()
        .find(|q| q.request_id == id && q.kind == "DONOR_APPROVED")
        .ok_or_else(|| usage(format!("no pending donation request {}: `moochy pending` lists them (or name the donor by handle or ps_ id)", clean(id))))?;
    Ok(if q.subject_username.is_empty() { q.subject.clone() } else { q.subject_username.clone() })
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

/// Request id prefixes of the standing offers the relay pushes (members that can be removed,
/// devices without a cap, accepted donors, covered projects and repos): actions, not things waiting.
pub(crate) const STANDING: [&str; 5] = ["remove:", "member-device:", "revoke:", "org-repo-remove:", "person-repo-remove:"];

/// `--weekly-limit` / `--daily-limit` (dollars) in µ$.
fn window_amount(v: &str, which: &str) -> Result<i64> {
    let v = crate::util::parse_amount(v).map_err(|e| usage(format!("--{which}-limit (dollars, e.g. 5): {e}")))?;
    i64::try_from(v).map_err(|_| usage(format!("--{which}-limit is too large")))
}

/// `moochy donate --repo PROJECT | --org ORG | --person PERSON --cap $N` (CONTRACT §19.6, §24.6).
fn donate(home: &Home, o: &Opts) -> Result<()> {
    use crate::donations::To;
    let (target, to) = match (org_arg(o)?, person_arg(o)?) {
        (_, Some(p)) if p.is_empty() => return Err(usage(format!("--person is {PERSON_FORMS}"))),
        (_, Some(p)) => (p, To::Person),
        (Some(org), None) => (org, To::Org),
        (None, None) => (slug_or_detect(o)?, To::Repo),
    };
    let limits = crate::donations::Limits { monthly: o.cap.unwrap_or(0), weekly: o.weekly_limit, daily: o.daily_limit };
    crate::donations::donate(home, &target, to, limits, o.has("yes"))?;
    share(home, &crate::button::page(to, &target)?);
    Ok(())
}

/// CONTRACT §22.3: the canonical page to share, after a donation or a claim.
fn share(home: &Home, page: &str) {
    let p = crate::style::err();
    eprintln!("{} {}", p.bold("Share:"), p.link(&clean(&format!("{}/{page}", crate::decisions::web_origin(home)))));
}

/// `moochy decisions …` (CONTRACT §16.6).
fn decisions_cmd(home: &Home, o: &Opts, w: &[&str]) -> Result<()> {
    match w {
        [] => {
            let org = org_arg(o)?.or(person_arg(o)?.filter(|p| !p.is_empty()));
            crate::decisions::list(home, repo_filter(o)?.as_deref(), org.as_deref(), o.has("json"))
        }
        ["refuse", id] => crate::decisions::refuse(home, id, o.reason.as_deref(), o.has("yes")),
        ["accept", id] => crate::decisions::accept_link(home, id),
        _ => Err(usage("decisions [--repo PROJECT | --org ORG] [--json] | decisions refuse <id> [--reason TEXT] | decisions accept <id>")),
    }
}

/// `moochy down`: ask the app to stop.
fn down(home: &Home) -> Result<()> {
    rt_small()?.block_on(async {
        if let Err(s) = crate::ctl::connect(&home.socket_path()).await?.shutdown(ShutdownRequest {}).await {
            // The app may exit before its answer is flushed: stopped means the socket is gone.
            let mut gone = false;
            for _ in 0..40 {
                if crate::ctl::connect(&home.socket_path()).await.is_err() {
                    gone = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if !gone {
                return Err(internal(s.message().to_owned()));
            }
        }
        emit(&json!({"event": "stopped"}));
        let p = crate::style::err();
        if p.tty {
            eprintln!("{}{}", p.mark(true), p.ok("Moochy stopped."));
        }
        Ok(())
    })
}

/// `moochy box …` (CONTRACT §17.1).
fn box_cmd(home: &Home, o: &Opts, w: &[&str]) -> Result<()> {
    match w {
        ["token", "create"] => crate::boxes::token_create(home, &slug_or_detect(o)?, o.ttl.as_deref(), o.cap, o.max_boxes),
        ["token", "list"] => crate::boxes::list(home, repo_filter(o)?.as_deref(), true),
        ["token", "revoke", id] => crate::boxes::revoke(home, id, "bt_"),
        ["list"] => crate::boxes::list(home, repo_filter(o)?.as_deref(), false),
        ["revoke", id] => crate::boxes::revoke(home, id, "d_"),
        _ => Err(usage("box token create|list|revoke, box list|revoke (see --help)")),
    }
}

/// `--repo` as a filter (optional, checked).
fn repo_filter(o: &Opts) -> Result<Option<String>> {
    o.repo.as_deref().map(canonical_repo).transpose()
}

const REPO_FORMS: &str = "owner/name, github/owner/name or gitlab/group[/subgroup…]/name";

const ORG_FORMS: &str = "github/ORG or gitlab/GROUP[/SUBGROUP…]";

const PERSON_FORMS: &str = "github/LOGIN or gitlab/USERNAME";

/// `--person` in canonical form (CONTRACT §24.1): one segment after the provider; `Some("")` =
/// bare `--person`. Never with `--repo` or `--org`.
fn person_arg(o: &Opts) -> Result<Option<String>> {
    let Some(p) = o.person.as_deref() else { return Ok(None) };
    if o.org.is_some() || o.repo.is_some() {
        return Err(usage("--person does not go with --repo or --org: name one project, organisation or person"));
    }
    if p.is_empty() {
        return Ok(Some(String::new()));
    }
    crate::config::canonical_org(p).filter(|c| c.matches('/').count() == 1).map(|c| Some(c.to_ascii_lowercase())).ok_or_else(|| usage(format!("--person is {PERSON_FORMS}")))
}

/// Your own person profile: `--person` when given, else the one the app's pushed requests name
/// (for `claim`: a waiting PERSON_CLAIMED, started on the web).
fn own_person(home: &Home, o: &Opts, claim: bool) -> Result<String> {
    if let Some(p) = person_arg(o)?.filter(|p| !p.is_empty()) {
        return Ok(p);
    }
    let r = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.pending(crate::pb::local::PendingRequest {}).await.map(tonic::Response::into_inner).map_err(|s| internal(clean(s.message()).into_owned()))
    })?;
    let mut found: Vec<String> = r.requests.iter().filter(|q| !q.person_path.is_empty() && (!claim || q.request_id.starts_with("person-claim:"))).map(|q| q.person_path.to_ascii_lowercase()).collect();
    found.sort_unstable();
    found.dedup();
    match found.as_slice() {
        [one] => crate::config::canonical_org(one).filter(|c| c.matches('/').count() == 1).ok_or_else(|| internal("the app named a malformed person profile")),
        [] if claim => Err(usage("no profile claim is waiting: sign in on the web and choose Claim your profile, then run this again (or pass --person github/LOGIN)")),
        [] => Err(usage(format!("no person profile of yours is known to the app: claim it first (moochy claim --person), or pass --person {PERSON_FORMS}"))),
        _ => Err(usage(format!("more than one profile: pass --person {PERSON_FORMS}"))),
    }
}

/// `moochy claim --person`, `moochy person add|remove|list`, `moochy accept <donor> --person`
/// (CONTRACT §24.2–24.4, §24.6): the org machinery on the person's `m_` id.
fn person_cmd(home: &Home, o: &Opts, w: &[&str]) -> Result<()> {
    use crate::org::{Group, Op, list, sign};
    let yes = o.has("yes");
    // Anyone may list a person's covered repos; everything else is your own profile.
    if let (["person", "list"], Some(p)) = (w, person_arg(o)?.filter(|p| !p.is_empty())) {
        return list(home, Group::Person, &p, o.has("json"));
    }
    let person = own_person(home, o, w == ["claim"])?;
    match w {
        ["claim"] => {
            sign(home, Group::Person, &person, Op::Claim, yes)?;
            share(home, &format!("people/{person}"));
            offers(home, &person);
            Ok(())
        }
        ["person", op @ ("add" | "remove"), repo] => sign(home, Group::Person, &person, Op::Repo { repo: &canonical_repo(repo)?.to_ascii_lowercase(), remove: *op == "remove" }, yes),
        ["person", "list"] => list(home, Group::Person, &person, o.has("json")),
        ["approve" | "accept", donor] if !donor.is_empty() => sign(home, Group::Person, &person, Op::Donor { donor, revoke: o.has("revoke") }, yes),
        _ => Err(usage(format!("person <add|remove> <PROJECT> | person list | claim --person | accept <donor> --person [PERSON]: PERSON is {PERSON_FORMS}"))),
    }
}

/// §24.3: after a person claim, the public repos you maintain that the server offers to cover.
/// ponytail: one `person add` each (one passphrase each); a batch signature needs KEYLOG support.
fn offers(home: &Home, person: &str) {
    let Ok(Ok(r)) = rt_small().map(|rt| {
        rt.block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            c.pending(crate::pb::local::PendingRequest {}).await.map(tonic::Response::into_inner).map_err(|s| internal(clean(s.message()).into_owned()))
        })
    }) else {
        return;
    };
    let repos: Vec<String> = r.requests.iter().filter(|q| q.request_id.starts_with("person-repo:") && q.person_path.eq_ignore_ascii_case(person)).filter_map(|q| crate::config::canonical_slug(&q.repo_slug)).collect();
    if !repos.is_empty() {
        eprintln!("Public repos you maintain; your sponsors' tokens serve your own requests there once you add them:");
        for r in repos {
            eprintln!("  moochy person add {r}");
        }
    }
}

/// `--org` in canonical form (CONTRACT §19.1). Never together with `--repo` (§19.6): a donation,
/// approval or filter targets a project or an organisation, never a guess between the two.
fn org_arg(o: &Opts) -> Result<Option<String>> {
    if o.org.is_some() && o.repo.is_some() {
        return Err(usage("--org and --repo do not go together: name a project or an organisation"));
    }
    o.org.as_deref().map(|r| crate::config::canonical_org(r).ok_or_else(|| usage(format!("--org is {ORG_FORMS}")))).transpose()
}

/// `moochy claim --org ORG`, `moochy org add|remove <PROJECT> --org ORG`, `moochy org list --org
/// ORG`, `moochy approve|accept <donor> --org ORG [--revoke]` (CONTRACT §19.2–19.4, §19.6).
fn org_cmd(home: &Home, o: &Opts, w: &[&str]) -> Result<()> {
    use crate::org::{Group, Op, sign};
    let org = org_arg(o)?.ok_or_else(|| usage(format!("--org is required: {ORG_FORMS}")))?.to_ascii_lowercase();
    let yes = o.has("yes");
    match w {
        ["claim"] => {
            sign(home, Group::Org, &org, Op::Claim, yes)?;
            share(home, &format!("org/{org}"));
            Ok(())
        }
        ["org", op @ ("add" | "remove"), repo] => sign(home, Group::Org, &org, Op::Repo { repo: &canonical_repo(repo)?.to_ascii_lowercase(), remove: *op == "remove" }, yes),
        ["org", "list"] => crate::org::list(home, Group::Org, &org, o.has("json")),
        ["approve" | "accept", donor] if !donor.is_empty() => sign(home, Group::Org, &org, Op::Donor { donor, revoke: o.has("revoke") }, yes),
        _ => Err(usage(format!("org <add|remove> <PROJECT> --org ORG | org list --org ORG | claim --org ORG | accept <donor> --org ORG: ORG is {ORG_FORMS}"))),
    }
}

/// A `--repo` value in the link's canonical form (`owner/name` = GitHub, `gitlab/…`).
fn canonical_repo(r: &str) -> Result<String> {
    crate::config::canonical_slug(r).ok_or_else(|| usage(format!("--repo is {REPO_FORMS}")))
}

/// `moochy up` on a cloud box (§17.1): enroll with `MOOCHY_ENROLL` when this machine has no device
/// yet (or its box expired); refuse to start an expired box; hint when the machine-id changed.
fn box_enroll(home: &Home, o: &Opts) -> Result<()> {
    let token = crate::boxes::enroll_token()?;
    let cfg = home.load()?;
    if token.is_none() && cfg.box_device.is_none() {
        return Ok(());
    }
    if crate::boxes::plan(&cfg, token.is_some(), crate::util::now_ms())? == crate::boxes::Start::Run {
        if let Some(h) = cfg.box_device.as_ref().and_then(|b| crate::boxes::machine_hint(b, crate::boxes::fingerprint().as_deref())) {
            eprintln!("moochy: note: {h}");
        }
        return Ok(());
    }
    let Some(token) = token else { return Err(internal("enrollment without a token")) };
    let relay = checked_relay(o, cfg.relay.as_deref())?;
    let name = o.name.clone().unwrap_or_else(crate::login::default_name);
    rt_small()?.block_on(crate::login::login(home, &relay, o.ca_file.clone(), vec!["gateway".into()], name, Some(token.as_str()), false))
}

/// The relay for `login`/enrollment: the default one, others only in development (A135, A175).
fn checked_relay(o: &Opts, saved: Option<&str>) -> Result<String> {
    if o.ca_file.is_some() && !dev_mode() {
        return Err(usage("--ca-file is only accepted with MOOCHY_INSECURE_DEV=1 (development and tests)"));
    }
    let relay = o.relay.as_deref().or(saved).unwrap_or(crate::config::DEFAULT_RELAY);
    if crate::tls::Origin::parse(relay)?.url() != crate::config::DEFAULT_RELAY {
        if !dev_mode() {
            return Err(usage("another server than the default needs MOOCHY_INSECURE_DEV=1 (development and tests only)"));
        }
        let p = crate::style::err();
        eprintln!("{} signing in to a server that is not the default ({}). This device gets a separate keystore for it.", p.hi("Warning:"), clean(&crate::tls::Origin::parse(relay)?.display()));
    }
    Ok(relay.to_owned())
}

fn slug_or_detect(o: &Opts) -> Result<String> {
    match &o.repo {
        Some(r) => canonical_repo(r),
        None => detect_repo().ok_or_else(|| usage(format!("--repo is required (no github.com or gitlab.com `origin` remote here): {REPO_FORMS}"))),
    }
}

/// The project of the `origin` remote of the current git repository: github.com and gitlab.com
/// (nested groups) exactly; any other remote (a mirror, a bundle) by its last two path segments,
/// as before (two segments = GitHub; the relay decides whether the project exists).
fn detect_repo() -> Option<String> {
    let out = crate::util::command("git").args(["config", "--get", "remote.origin.url"]).stderr(std::process::Stdio::null()).output().ok()?;
    let url = String::from_utf8(out.stdout).ok()?;
    if let Ok(p) = crate::button::parse_remote(&url) {
        return crate::config::canonical_slug(&if p.provider == "gitlab" { format!("gitlab/{}", p.path) } else { p.path });
    }
    let url = url.trim().trim_end_matches('/').trim_end_matches(".git");
    let path = url.rsplit_once(':').map_or(url, |(_, p)| p);
    let mut parts = path.rsplit('/');
    let (name, owner) = (parts.next()?, parts.next()?);
    crate::config::canonical_slug(&format!("{owner}/{name}"))
}

/// `moochy run -- <cmd…>` (CONTRACT §15.1). Fails closed until `moochy-sandbox` is in the build.
fn run_cmd(home: &Home, o: &Opts, cmd: &[&str]) -> Result<()> {
    let slug = slug_or_detect(o)?;
    let r = rt_small()?
        .block_on(async {
            let mut c = crate::ctl::connect(&home.socket_path()).await?;
            c.env(EnvRequest { repo: slug.clone(), rotate: false }).await.map_err(|s| internal(clean(s.message()).into_owned()))
        })?
        .into_inner();
    let cmd: Vec<String> = cmd.iter().map(|s| (*s).to_owned()).collect();
    if o.has("box-is-sandbox") && (o.has("unsafe-no-sandbox") || !o.allow_hosts.is_empty() || o.has("git-writable")) {
        return Err(usage("--box-is-sandbox runs without moochy's sandbox: --allow-host, --git-writable and --unsafe-no-sandbox do not apply"));
    }
    if o.has("unsafe-no-sandbox") {
        let env = crate::run::gateway_env(&r.anthropic_base_url, &r.openai_base_url, &r.mcp_url, &r.token);
        let st = crate::run::run_unsandboxed(&env, &cmd)?;
        std::process::exit(st.code().unwrap_or(1));
    }
    let gw = crate::run::GatewayInfo {
        anthropic: r.anthropic_base_url,
        openai: r.openai_base_url,
        mcp: r.mcp_url,
        repo_token: r.token,
        state_dir: home.state_dir(),
        allow_hosts: o.allow_hosts.clone(),
        git_writable: o.has("git-writable"),
    };
    let worktree = o.worktree.as_ref().map(|w| std::fs::canonicalize(w).map_err(|e| usage(format!("--worktree {}: {e}", w.display())))).transpose()?;
    let code = if o.has("box-is-sandbox") { crate::run::run_platform(&gw, &cmd, worktree)? } else { crate::run::run_sandboxed(&gw, &cmd, worktree)? };
    std::process::exit(code);
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
    let (r, st) = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let r = c.env(EnvRequest { repo: slug.clone(), rotate: o.has("rotate") }).await.map_err(|s| internal(s.message().to_owned()))?;
        Ok::<_, Error>((r.into_inner(), c.status(StatusRequest {}).await.ok().map(tonic::Response::into_inner)))
    })?;
    // m7: the token is local and works for any name; whether donations reach the project is the
    // server's to say. The app knows the projects it was pushed while connected: warn otherwise.
    if let Some(st) = st.filter(|st| st.link_state == "up")
        && !st.pools.iter().any(|p| p.slug.eq_ignore_ascii_case(&slug))
    {
        eprintln!("Warning: no donations reach {} for this account yet (an unknown project, one you are not a member of, or one no donor serves): requests with this token are refused until one does. `moochy status` lists your projects.", clean(&slug));
    }
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
        let p = crate::style::out();
        let relay = crate::tls::Origin::parse(&r.relay).map_or_else(|_| clean(&r.relay).into_owned(), |o| o.display());
        let link = clean(&r.link_state);
        let link = if r.link_state == "up" { p.ok(&link) } else { p.hi(&link) };
        let k = |s: &str| p.dim(&format!("{s:<11}"));
        println!(
            "{} {}\n{} {} ({link})\n{} {}\n{} {}\n{} {} of {} slots in use{}\n{} {} requests in progress",
            k("device"),
            p.bold(&clean(&r.device_id)),
            k("server"),
            clean(&relay),
            k("local API"),
            clean(&r.gateway_url),
            k("MCP"),
            clean(&r.mcp_url),
            k("donating"),
            r.slots_busy,
            r.slots_max,
            if r.paused { p.hi(", paused") } else { String::new() },
            k("using"),
            r.gateway_tasks
        );
        for pool in &r.pools {
            println!("{} {}: {} donor device(s), models {}", k("project"), p.bold(&clean(&pool.slug)), pool.workers, clean(&pool.models.join(", ")));
        }
    }
    Ok(())
}

fn journal(home: &Home, follow: bool) -> Result<()> {
    rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let mut st = c.journal(JournalRequest { follow }).await.map_err(|s| internal(format!("journal unreadable: {}", clean(s.message()))))?.into_inner();
        // A broken stream is an error, never an empty journal.
        loop {
            match st.message().await {
                Ok(Some(e)) => emit(&json!({"t_ms": e.t_ms, "role": e.role, "task": e.task, "repo": e.repo, "model": e.model, "status": e.status, "cost_uusd": e.cost_uusd, "ms": e.ms,
                    "tokens_in": e.tokens_in, "tokens_out": e.tokens_out})),
                Ok(None) => return Ok(()),
                Err(s) => return Err(internal(format!("journal unreadable: {:?}: {}", s.code(), clean(s.message())))),
            }
        }
    })
}

fn sign_json(q: &crate::pb::local::SignResponse) -> serde_json::Value {
    json!({"request_id": q.request_id, "kind": q.kind, "repo": q.repo_slug, "repo_id": q.repo_id, "subject": q.subject,
        "subject_username": q.subject_username, "signer": q.signer, "issued_at_ms": q.issued_at_ms, "signed": q.signed, "log_index": q.log_index})
}

/// Owner signatures (CONTRACT §15.4): previewed by the Node, signed here with the owner key.
fn owner_ops(home: &Home, o: &Opts, w: &[&str]) -> Result<()> {
    if o.org.is_some() || o.person.is_some() {
        return Err(usage("--org and --person are for claim, accept/approve, org/person, donate and decisions; members belong to a project (--repo)"));
    }
    // Plan 07 and the web claim page: `moochy claim <owner/repo>` (positional, E84).
    if let ["claim", repo] = w {
        let slug = crate::config::canonical_slug(repo).ok_or_else(|| usage(format!("claim <project>: {REPO_FORMS}")))?.to_ascii_lowercase();
        crate::owner::sign(home, &slug, &["claim"], o.has("yes"), false, false, 0)?;
        share(home, &crate::button::page(crate::donations::To::Repo, &slug)?);
        return Ok(());
    }
    let slug = slug_or_detect(o)?;
    crate::owner::sign(home, &slug, w, o.has("yes"), o.has("revoke"), o.has("device"), o.cap.unwrap_or(0))?;
    if w == ["claim"] {
        share(home, &crate::button::page(crate::donations::To::Repo, &slug)?);
    }
    // A member device's own monthly cap is a project setting, not signed (E32).
    if let (["members", "add", device], true, Some(cap)) = (w, o.has("device"), o.cap) {
        crate::boxes::set_device_cap(home, &slug, device, cap)?;
    }
    Ok(())
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
    let p = crate::style::out();
    // `ok  ` / `note` / `FAIL`, plain off a terminal; with colour a mint ● / dim · / coral ×.
    let tag = move |level: &str| match level {
        "ok  " => format!("{}{}", p.mark(true), p.ok(level)),
        "FAIL" => format!("{}{}", p.mark(false), p.bad(level)),
        _ if p.color => p.dim(&format!("· {level}")),
        _ => level.to_owned(),
    };
    let mut line = |ok: bool, what: &str, detail: String| {
        if !ok {
            bad = bad.saturating_add(1);
        }
        println!("{} {what:<9} {}", tag(if ok { "ok  " } else { "FAIL" }), clean(&detail));
    };
    let mut stored = None;
    match keystore::load(home, &cfg) {
        Ok(Some(s)) => {
            stored = Some(s.providers.len());
            for p in s.providers.iter().filter(|p| p.remote_host.is_some()) {
                println!("{} local     remote, vetted {}, trust: {}", tag("ok  "), clean(p.remote_host.as_deref().unwrap_or("")), crate::keycheck::trust_name(p));
            }
            line(true, "keystore", format!("opens ({}), device keys {}", cfg.keystore.as_deref().unwrap_or("file"), if s.device.is_some() { "present" } else { "absent" }));
            for p in &s.providers {
                println!("{} key       {}: stored in {}, never sent to Moochy", tag("ok  "), clean(&p.provider), clean(&key_store_place(home, &cfg)));
            }
        }
        Ok(None) => line(false, "keystore", "no keystore: run `moochy login`".into()),
        Err(e) => line(false, "keystore", e.msg),
    }
    let st = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await.ok()?;
        c.status(StatusRequest {}).await.ok().map(tonic::Response::into_inner)
    });
    if let Some(s) = &st {
        let relay = crate::tls::Origin::parse(&s.relay).map_or_else(|_| s.relay.clone(), |o| o.display());
        line(s.link_state == "up" || s.link_state == "offline", "relay", format!("{relay} ({})", s.link_state));
        let skew = s.clock_skew_ms.unsigned_abs();
        line(skew <= 300_000, "clock", format!("skew vs relay {} ms (limit ±5 min)", s.clock_skew_ms));
        // M2: the running app's own keys, read at its start; a key added since needs a restart.
        let n = usize::try_from(s.provider_keys).unwrap_or(usize::MAX);
        let restart = stored.filter(|m| *m != n).map(|m| format!("; {m} stored on this machine: restart it with `moochy down && moochy up` to use them")).unwrap_or_default();
        line(restart.is_empty(), "providers", format!("the running app uses {n} key(s), {} warm adapter(s), catalog v{}{restart}", s.warm_adapters, s.catalog_version));
    } else {
        line(false, "relay", "the Moochy app is not running (start it with `moochy up`)".into());
        line(false, "clock", "unknown: measured when the app connects".into());
    }
    line(true, "safety", format!("checks level {}, tables of moochy-worker {}", cfg.firewall_level.as_deref().unwrap_or("strict"), env!("CARGO_PKG_VERSION")));
    for (ok, what, detail) in crate::lockdown::doctor(home, st.is_some()) {
        line(ok, what, detail);
    }
    // `moochy run` (§15.1): moochy-sandbox's own checks (user namespaces, Landlock ABI, cgroup)
    // and what the agent will not see in this repo (A163). Informational.
    let root = std::env::current_dir().ok().and_then(|d| crate::files::git_root(&d));
    let sb = moochy_sandbox::doctor(root.as_deref());
    let sandbox_ok = !sb.iter().any(|l| l.level == moochy_sandbox::doctor::Level::Fail && matches!(l.topic, "sandbox" | "landlock"));
    let sandbox_failed = sb.iter().filter(|l| l.level == moochy_sandbox::doctor::Level::Fail).count();
    println!("{}     hidden    {}", if p.color { "  " } else { "" }, moochy_sandbox::mask::SECRET_PATTERNS.join(" "));
    for l in &sb {
        let level = match l.level {
            moochy_sandbox::doctor::Level::Ok => "ok  ",
            moochy_sandbox::doctor::Level::Note => "note",
            moochy_sandbox::doctor::Level::Fail => "FAIL",
        };
        for (i, text) in l.text.lines().enumerate() {
            if i == 0 { println!("{} {:<9} {}", tag(level), l.topic, clean(text)) } else { println!("{}               {}", if p.color { "  " } else { "" }, clean(text)) }
        }
    }
    // Cloud boxes (§17): the box binding, and what this runtime lacks.
    for (level, what, detail) in crate::boxes::doctor_lines(&cfg, sandbox_ok) {
        if level == "FAIL" {
            line(false, what, detail);
        } else {
            println!("{} {what:<9} {}", tag(level), clean(&detail));
        }
    }
    let me = std::fs::metadata(&home.dir).map(|m| m.uid()).ok();
    match std::fs::metadata(home.socket_path()) {
        Ok(m) => line(Some(m.uid()) == me && m.mode() & 0o777 == 0o600, "socket", format!("node.sock uid {} mode {:o}", m.uid(), m.mode() & 0o777)),
        Err(_) => line(st.is_none(), "socket", "no node.sock".into()),
    }
    // m1: any FAIL line is a failed check, whether the app runs or not (exit 10, CONTRACT §6).
    let bad = usize::try_from(bad).unwrap_or(usize::MAX).saturating_add(sandbox_failed);
    if bad > 0 {
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
    // m11: the tool first, before the project and the running app.
    if !crate::connect::CLIENTS.contains(&client) {
        return Err(usage(format!("unknown tool `{}`: `moochy connect list` shows the tools", clean(client))));
    }
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
        .ok_or_else(|| usage(format!("--write is not supported for {client} (its settings are environment variables or typed into the app): paste the snippet from `moochy connect {client}`")))?;
    // A248: the target is walked from a trusted base (home, XDG config dir, the repository root,
    // or an explicit --config's own parent outside them) without following any symbolic link
    // below it; project files (Trae) are relative to the repository root, not the cwd.
    let cwd = std::env::current_dir().ctx("cwd")?;
    let project = crate::files::git_root(&cwd).unwrap_or_else(|| cwd.clone());
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| user_home.join(".config"), PathBuf::from);
    let (path, explicit) = match &o.config {
        Some(p) => (std::path::absolute(p).ctx("config path")?, true),
        None if default_path.is_relative() => (project.join(&default_path), false),
        None => (default_path, false),
    };
    let target = crate::connect::split_target(&path, &[user_home.clone(), xdg, project], explicit).map_err(|e| usage(format!("refusing to write: {e}")))?;
    let opened = crate::connect::open_target(&target).map_err(|e| usage(format!("refusing to write: {e}")))?;
    let path = opened.shown.clone();
    // No symbolic link below the base, so git looks at this very file.
    if git_tracked(&path) {
        return Err(usage(format!("refusing to write {}: the file is tracked by git (tokens and machine paths do not belong in a repository)", path.display())));
    }
    let old = opened.read().map_err(|e| usage(format!("refusing to write: {e}")))?;
    // The file's format follows its extension (the agents' own files: TOML for Codex, YAML for
    // Hermes, JSON otherwise); TOML and YAML are edited in place, JSON merged and re-printed.
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
    let (pretty_old, new) = match ext.as_str() {
        "toml" | "yaml" | "yml" => {
            let edit = if ext == "toml" { crate::connect::toml_edit(&old, &plan) } else { crate::connect::yaml_edit(&old, &plan) };
            (old.clone(), edit.map_err(|e| usage(format!("{}: {e}; paste the snippet from `moochy connect {client}` instead", path.display())))?)
        }
        _ => {
            let mut v = if old.trim().is_empty() {
                json!({})
            } else {
                crate::json::parse(old.as_bytes()).map_err(|e| usage(format!("{} is not plain JSON ({e}); edit it by hand with the snippet", path.display())))?
            };
            if !crate::connect::merge(&mut v, &plan) {
                return Err(usage(format!("{} does not have the expected JSON shape", path.display())));
            }
            let pretty_old = if old.trim().is_empty() { String::new() } else { serde_json::to_string_pretty(&crate::json::parse(old.as_bytes()).unwrap_or_default()).unwrap_or_default() };
            (pretty_old, format!("{}\n", serde_json::to_string_pretty(&v).ctx("encode config")?))
        }
    };
    if pretty_old.trim_end() == new.trim_end() {
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
    // The previous file is kept next to it (0600) before anything changes; both writes are
    // atomic (temp file + rename in the same directory, never through a symbolic link).
    let backup = (!old.is_empty()).then(|| format!("{}.moochy-backup", opened.file()));
    if let Some(b) = &backup {
        opened.write(b, old.as_bytes()).map_err(|e| internal(format!("backup: {e}")))?;
    }
    opened.write(opened.file(), new.as_bytes()).map_err(internal)?;
    let backup = backup.map(|b| path.with_file_name(b));
    emit(&json!({"event": "connect", "client": client, "path": path.display().to_string(), "changed": true, "backup": backup.map(|b| b.display().to_string())}));
    Ok(())
}

/// Is `path` tracked by git (in whatever repository contains it)?
fn git_tracked(path: &std::path::Path) -> bool {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else { return false };
    crate::util::command("git")
        .arg("-C")
        .arg(dir)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn login_cmd(home: &Home, o: &Opts) -> Result<()> {
    // A175 (pinned CA) and A135 (lookalike relay): development and tests only.
    let relay = checked_relay(o, None)?;
    let relay = relay.as_str();
    let roles: Vec<String> = o.roles.as_deref().unwrap_or("gateway").split(',').map(|r| r.trim().to_owned()).collect();
    let name = o.name.clone().unwrap_or_else(crate::login::default_name);
    if let Some(k) = &o.log_key {
        moochy_keylog::NoteKey::parse(k).map_err(|e| usage(format!("--log-key: {e}")))?;
    }
    rt_small()?.block_on(crate::login::login(home, relay, o.ca_file.clone(), roles, name, None, !o.has("no-browser") && !o.has("headless")))?;
    if let Some(k) = &o.log_key {
        let mut cfg = home.load()?;
        cfg.log_key = Some(k.clone());
        home.save(&cfg)?;
    }
    Ok(())
}

fn keys_add(home: &Home, provider: &str, o: &Opts) -> Result<()> {
    if provider == "local" {
        let url = o.base_url.as_deref().ok_or_else(|| usage("keys add local needs --base-url http://127.0.0.1:PORT, or --url https://… for a remote GPU server"))?;
        // A remote GPU server over TLS (CONTRACT §17.3): vetted host, keystore header, pinned trust.
        // An https loopback/LAN server with a pinned certificate or a keystore header takes the
        // same path, minus the vetted list (it needs none).
        let pinned = url.starts_with("https://") && (o.ca_file.is_some() || o.cert_sha256.is_some() || o.auth_header.is_some() || o.confirm_host.is_some());
        let vetted = moochy_worker::provider::remote_host_key(url).ok();
        if let Some(host) = vetted.clone().or_else(|| pinned.then(|| crate::keycheck::origin_host(url)).flatten()) {
            let r = crate::keycheck::Remote { host, vetted: vetted.is_some(), ca_file: o.ca_file.clone(), cert_sha256: o.cert_sha256.clone(), auth_header: o.auth_header.clone(), confirm_host: o.confirm_host.clone() };
            crate::keycheck::add_remote(home, url, &r, o.has("key-stdin"), o.has("allow-unvetted-host"), &o.models)?;
            return stored_where(home);
        }
        crate::keycheck::add_local(home, o.base_url.as_deref(), o.has("key-stdin"), o.has("allow-unvetted-host"), &o.models)?;
        return stored_where(home);
    }
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
    // A190: borrow, never an un-zeroized intermediate copy of the key.
    let key = zeroize::Zeroizing::new(std::str::from_utf8(&raw).map_err(|_| usage("key must be UTF-8"))?.trim().to_owned());
    if key.is_empty() || !key.bytes().all(|c| c.is_ascii_graphic()) {
        return Err(usage("key must be non-empty printable ASCII"));
    }
    crate::keycheck::refuse_consumer_credential(provider, &key)?;
    // Validated with a free models call before anything is stored (06 §4.2).
    rt_small()?.block_on(crate::keycheck::validate(provider, &key, o.base_url.as_deref()))?;
    let mut cfg = home.load()?;
    let mut sec = keystore::load_or_init(home, &mut cfg)?;
    sec.providers.retain(|p| p.provider != provider);
    sec.providers.push(ProviderKey { provider: provider.into(), key: key.to_string(), base_url: o.base_url.clone(), allow_unvetted_host: false, models: std::collections::BTreeMap::new(), served_ids: Vec::new(), remote_host: None, trust: None, auth_header: None });
    keystore::save(home, &cfg, &sec)?;
    emit(&json!({"event": "key_added", "provider": provider}));
    stored_where(home)?;
    safety(home, o, Some(provider)).map(drop)
}

/// Where the keystore keeps provider keys on this machine (CONTRACT §23), for humans: never a value.
fn key_store_place(home: &Home, cfg: &crate::config::Config) -> String {
    if cfg.keystore.as_deref() == Some("keychain") {
        "your keychain on this machine".into()
    } else {
        format!("the encrypted key file {} on this machine", home.keystore_path(cfg.relay.as_deref()).display())
    }
}

/// The §23.1 line after `keys add`, on stderr: stdout keeps only the JSON event.
fn stored_where(home: &Home) -> Result<()> {
    let cfg = home.load()?;
    let p = crate::style::err();
    eprintln!("{}Stored in {}. {}", p.mark(true), clean(&key_store_place(home, &cfg)), p.ok("Never sent to Moochy."));
    Ok(())
}

/// Where each provider sets a spend limit (07 §8.1 step 4 deep links).
fn spend_limit_page(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "https://console.anthropic.com/settings/limits",
        "openai" => "https://platform.openai.com/settings/organization/limits",
        "openrouter" => "https://openrouter.ai/settings/keys",
        "deepseek" => "https://platform.deepseek.com/usage",
        "xai" => "https://console.x.ai",
        _ => "your provider's console",
    }
}

/// The donor safety step (07 §8.1 step 4, required): a monthly cap for this machine, and the
/// advice to use a dedicated key with a provider-side spend limit, acknowledged with a checkbox.
/// Interactive on the terminal; headless with `--monthly-limit $N --accept-safety`. Until it is
/// done this device does not donate (outside `MOOCHY_INSECURE_DEV`).
/// `moochy button [--repo P] [--provider github|gitlab] [--style …] [--theme …] [--size …]
/// [--label …] [--format markdown|html|rst]` (docs/guides/donate-button.md steps 1–3, offline).
fn button(o: &Opts, rest: &[&str]) -> Result<()> {
    // CONTRACT §21.3: an organisation's chart (no project to detect).
    if o.org.is_some() || o.person.is_some() {
        if !o.has("chart") || o.repo.is_some() || o.has("provider") || !rest.is_empty() {
            return Err(usage("button --chart --org github/ORG|gitlab/GROUP[/SUB…] | --person github/LOGIN|gitlab/USERNAME (not with --repo or --provider)"));
        }
        let (base, act) = match (&o.org, person_arg(o)?) {
            (_, Some(p)) => crate::button::group_base(crate::donations::To::Person, &p)?,
            (Some(org), None) => crate::button::group_base(crate::donations::To::Org, org)?,
            (None, None) => return Err(internal("unreachable")),
        };
        println!("{}", crate::button::chart(&base, act, &o.button)?);
        return Ok(());
    }
    let provider = match (o.has("provider"), rest) {
        (true, ["github"]) => Some("github"),
        (true, ["gitlab"]) => Some("gitlab"),
        (false, []) => None,
        _ => return Err(usage("button [--chart] [--repo PROJECT|--org ORG] [--provider github|gitlab] [--style …] [--theme …] [--size …] [--label …] [--format markdown|html|rst|iframe]")),
    };
    let project = if let Some(r) = &o.repo {
        // `--provider gitlab --repo group/name`, or a provider-qualified `--repo`.
        match provider {
            Some(p) if !r.starts_with("github/") && !r.starts_with("gitlab/") => crate::button::project(p, r)?,
            _ => {
                let pr = crate::button::from_slug(r)?;
                if provider.is_some_and(|x| x != pr.provider) {
                    return Err(usage(format!("--repo names a {} project, not {}", pr.provider, provider.unwrap_or_default())));
                }
                pr
            }
        }
    } else {
        {
            let out = crate::util::command("git").args(["remote", "get-url", "origin"]).stderr(std::process::Stdio::null()).output().map_err(|e| usage(format!("git: {e}")))?;
            if !out.status.success() {
                return Err(usage("no `origin` remote here: pass --repo owner/name (and --provider gitlab for GitLab)"));
            }
            let p = crate::button::parse_remote(&String::from_utf8_lossy(&out.stdout))?;
            if provider.is_some_and(|x| x != p.provider) {
                return Err(usage(format!("the origin remote is on {}, not {}", p.provider, provider.unwrap_or_default())));
            }
            p
        }
    };
    let out = if o.has("chart") { crate::button::project_chart(&project, &o.button)? } else { crate::button::snippet(&project, &o.button)? };
    println!("{out}");
    Ok(())
}

/// `moochy audit --provider [--from-file usage.csv]` (07 §2): the last 90 days of served work.
fn audit(home: &Home, o: &Opts) -> Result<()> {
    let since = crate::util::now_ms().saturating_sub(crate::journal::RETENTION_DAYS.saturating_mul(86_400_000));
    let entries = crate::journal::since(&home.state_dir(), since);
    let provider = match &o.from_file {
        Some(f) => {
            let md = std::fs::metadata(f).map_err(|e| usage(format!("{}: {e}", f.display())))?;
            if md.len() > 64 << 20 {
                return Err(usage("usage file larger than 64 MiB"));
            }
            Some(crate::audit::provider_csv(&std::fs::read_to_string(f).map_err(|e| usage(format!("{}: {e}", f.display())))?)?)
        }
        None => None,
    };
    let r = crate::audit::report(&entries, provider.as_ref());
    emit(&r);
    if r.get("flagged").and_then(serde_json::Value::as_array).is_some_and(|a| !a.is_empty()) {
        return Err(Error { exit: crate::util::Exit::Internal, msg: "some days show provider spend the journal does not account for".into() });
    }
    Ok(())
}

/// `Ok(true)`: the limit and the acknowledgement were saved.
fn safety(home: &Home, o: &Opts, provider: Option<&str>) -> Result<bool> {
    use std::io::{BufRead as _, Write as _};
    let mut cfg = home.load()?;
    if cfg.donor_safety_ack_ms.is_some() && cfg.device_monthly_cap_uusd.is_some() && o.monthly_limit.is_none() {
        return Ok(false);
    }
    let page = provider.map_or("your provider's console", spend_limit_page);
    eprintln!(
        "Safety step before donating:\n  1. A monthly limit for this machine: Moochy never spends more than this per month here.\n  2. Strongly recommended: a key made only for Moochy, with a monthly spend limit set at the provider ({page}).\n     Then the most it can ever cost you is that limit."
    );
    let (cap, accepted) = if o.has("accept-safety") {
        (o.monthly_limit.or(cfg.device_monthly_cap_uusd), true)
    } else if let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        let mut out = tty.try_clone().ctx("tty")?;
        let mut lines = std::io::BufReader::new(tty).lines();
        let mut ask = |q: &str| -> Option<String> {
            let _ = write!(out, "{q}");
            let _ = out.flush();
            lines.next()?.ok().map(|l| l.trim().to_owned())
        };
        let cap = match o.monthly_limit {
            Some(c) => Some(c),
            None => match ask("Monthly limit for this machine in dollars [25]: ") {
                Some(a) => Some(crate::config::device_limit(if a.is_empty() { "25" } else { &a })?),
                None => None,
            },
        };
        let ok = ask("[ ] I set a spend limit at my provider, or I accept the risk. Type yes to check this box: ").is_some_and(|a| a.eq_ignore_ascii_case("yes") || a.eq_ignore_ascii_case("y"));
        (cap, ok)
    } else {
        (None, false)
    };
    let Some(cap) = cap.filter(|_| accepted) else {
        eprintln!("Not donating yet. To finish: moochy safety --monthly-limit 25 --accept-safety");
        emit(&json!({"event": "safety_step_pending"}));
        return Ok(false);
    };
    cfg.device_monthly_cap_uusd = Some(cap);
    cfg.donor_safety_ack_ms = Some(crate::util::now_ms());
    home.save(&cfg)?;
    emit(&json!({"event": "safety_step_done", "monthly_limit": crate::util::fmt_dollars(cap)}));
    Ok(true)
}

fn up_background(home: &Home, o: &Opts) -> Result<()> {
    let line = start_node(home, o.has("offline"))?;
    print!("{line}");
    let p = crate::style::err();
    if p.tty {
        eprintln!("{}{} {}", p.mark(true), p.ok("Moochy is running."), p.dim("`moochy status` shows it, `moochy down` stops it."));
    }
    Ok(())
}

/// Start `up --foreground` detached and wait for its ready line (returned, not printed).
fn start_node(home: &Home, offline: bool) -> Result<String> {
    use std::io::BufRead as _;
    use std::os::unix::process::CommandExt as _;
    home.ensure()?;
    let log_path = home.state_dir().join("node.log");
    let log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).ctx("open node.log")?;
    let log_start = log_file.metadata().map_or(0, |m| m.len());
    let exe = std::env::current_exe().ctx("current exe")?;
    let mut cmd = std::process::Command::new(exe);
    // The background process never sees the owner passphrase (CONTRACT §15.4, A190).
    cmd.arg("--home").arg(&home.dir).args(["up", "--foreground"]).env_remove("MOOCHY_OWNER_PASSPHRASE").env_remove(crate::boxes::ENROLL_ENV).env_remove("MOOCHY_ENROLL_FILE");
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
    let st = child.wait().ok();
    let code = st.and_then(|s| s.code()).unwrap_or(10);
    // M4: killed before it could write its JSON error line (a crash, a blocked system call).
    let signal = st.and_then(|s| std::os::unix::process::ExitStatusExt::signal(&s)).map(|n| format!("the app stopped on signal {n} while starting (see {})", log_path.display()));
    Err(Error {
        exit: match code {
            2 => crate::util::Exit::Usage,
            3 => crate::util::Exit::Auth,
            4 => crate::util::Exit::Network,
            _ => crate::util::Exit::Internal,
        },
        msg: start_error(&log_path, log_start).or(signal).unwrap_or_else(|| format!("the app did not start (see {})", log_path.display())),
    })
}

/// The reason a background start failed: the `message` of the last JSON error line the node
/// wrote to `node.log` after `from` (e.g. "not logged in: run `moochy login` first"), with
/// control characters removed so a log line cannot steer the terminal.
fn start_error(log: &std::path::Path, from: u64) -> Option<String> {
    let bytes = std::fs::read(log).ok()?;
    let tail = String::from_utf8_lossy(bytes.get(usize::try_from(from).ok()?..)?).into_owned();
    let msg = tail.lines().rev().find_map(|l| crate::json::parse_object(l.as_bytes()).ok()?.get("message")?.as_str().map(str::to_owned))?;
    Some(msg.chars().filter(|c| !c.is_control()).collect())
}

fn up_foreground(home: Home, offline: bool, unsafe_no_lockdown: bool) -> Result<()> {
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 4));
    // CONTRACT §15.2: load, bind, lock down while single-threaded, then start the runtime.
    // A222: the debug escape hatch exists only in insecure dev mode.
    if unsafe_no_lockdown && !dev_mode() {
        return Err(usage("--unsafe-no-lockdown is only accepted with MOOCHY_INSECURE_DEV=1 (debugging)"));
    }
    let mut boot = crate::lockdown::Boot::load(&home, offline)?;
    crate::lockdown::apply(&home, &mut boot, unsafe_no_lockdown)?;
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all().build().ctx("runtime")?;
    rt.block_on(up(home, offline, boot))
}

/// Provider adapters (one per stored key) and the outbox store.
fn worker_parts(home: &Home, secrets: &keystore::Secrets) -> Result<WorkerParts> {
    use moochy_worker::provider::{Adapter, AdapterConfig, Limits};
    let mut adapters = Vec::new();
    let mut local_models = std::collections::HashMap::new();
    let mut local_served = std::collections::HashSet::new();
    for p in &secrets.providers {
        let Some(provider) = moochy_worker::Provider::parse(&p.provider) else {
            log("warn", "this version cannot donate with this provider yet; update moochy", &json!({"provider": p.provider}));
            continue;
        };
        // `--base-url` replaces the provider origin only; moochy-worker owns the per-dialect paths.
        let base_url = p.base_url.clone();
        let local = provider == moochy_worker::Provider::Local;
        let cfg = AdapterConfig {
            provider,
            api_key: zeroize::Zeroizing::new(p.key.clone()),
            base_url,
            // A local server is the donor's own: vetted by host (worker API.md), not dev mode.
            insecure_dev: dev_mode() && !local,
            dev_root: None,
            limits: if local { Limits::local() } else { Limits::default() },
        };
        if local {
            local_models.extend(p.models.iter().map(|(k, v)| (k.clone(), v.clone())));
            local_served.extend(p.served_ids.iter().cloned());
            if p.allow_unvetted_host {
                eprintln!("moochy: WARNING the local model server {} is not a loopback or private address (--allow-unvetted-host, development only)", clean(p.base_url.as_deref().unwrap_or("")));
            }
        }
        // A222: an unvetted local host is a development setting; outside dev mode it is refused.
        if p.allow_unvetted_host && !dev_mode() {
            log("error", "local model server refused: --allow-unvetted-host is development only (MOOCHY_INSECURE_DEV=1)", &json!({}));
            continue;
        }
        let built = if local {
            match crate::keycheck::local_options(p, dev_mode()) {
                Ok(opts) => {
                    if let Some(h) = &p.remote_host {
                        log("info", "remote model server", &json!({"host": clean(h), "trust": crate::keycheck::trust_name(p)}));
                    }
                    let cfg = AdapterConfig { api_key: zeroize::Zeroizing::new(if p.auth_header.is_some() { String::new() } else { p.key.clone() }), ..cfg };
                    Adapter::new_local_with(&cfg, &opts)
                }
                Err(e) => Err(moochy_worker::provider::ConfigError(e)),
            }
        } else {
            Adapter::new(&cfg)
        };
        match built {
            Ok(a) => adapters.push(Arc::new(a)),
            Err(e) => log("error", "provider key not usable", &json!({"provider": p.provider, "error": e.to_string()})),
        }
    }
    let store = moochy_worker::store::Store::open(&home.state_dir().join("worker.log"), crate::util::now_ms()).ctx("open worker store")?;
    Ok(WorkerParts { adapters, local_models, local_served, store: Some(Arc::new(std::sync::Mutex::new(store))), validator: None, locked: false })
}

async fn up(home: Home, offline: bool, boot: crate::lockdown::Boot) -> Result<()> {
    let port = boot.port();
    let crate::lockdown::Boot { cfg, secrets, listener, ctl, gateway_unix, validator, locked } = boot;
    let listener = tokio::net::TcpListener::from_std(listener).ctx("gateway listener")?;
    let sock_path = home.socket_path();
    let sock = tokio::net::UnixListener::from_std(ctl).ctx("control socket")?;
    let keys = match (&secrets.device, cfg.device_id.as_deref()) {
        (Some(d), Some(id)) => Some(Keys { sign: d.sign_key(), enc: d.enc_key()?, device_id: id.parse().map_err(|_| auth("stored device id is invalid"))? }),
        _ => None,
    };
    let mut parts = if cfg.has_role("worker") && keys.is_some() && !offline { worker_parts(&home, &secrets)? } else { WorkerParts::default() };
    parts.validator = validator;
    parts.locked = locked;
    let node = Node::new(home.clone(), cfg, secrets, keys, parts, offline);
    // Durable journal (E62): the writer thread, and the recent entries back in memory.
    crate::journal::start(&home.state_dir());
    crate::node::lock(&node.journal).extend(crate::journal::load_recent(&home.state_dir(), 512));
    node.gateway_port.store(u32::from(port), Ordering::Relaxed);
    tokio::spawn(crate::gateway::serve(node.clone(), listener, gateway_unix));
    if let Some(p) = node.cfg.allow_unsandboxed_tools.as_deref() {
        eprintln!("WARNING: tool calls from donated tokens reach agents outside `moochy run` for: {}. A donor's model can make such an agent run commands on this machine.", clean(p));
        log("warn", "allow_unsandboxed_tools is set: tool calls reach unsandboxed clients", &json!({"projects": p}));
    }
    tokio::spawn(crate::ctl::serve(node.clone(), sock, sock_path.clone()));
    if !node.adapters.is_empty() {
        tokio::spawn(crate::worker::warm_loop(node.clone()));
    }
    match &node.keylog {
        Some(l) => l.start(&node),
        None if offline => {}
        None if node.insecure_dev => log("warn", "no key-log key pinned (log_key): approvals and memberships are relay-asserted (MOOCHY_INSECURE_DEV)", &json!({})),
        None => log("error", "no key-log key pinned (log_key): this device seals to no donor and accepts no task until it is set", &json!({})),
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

/// `moochy mcp`: the stdio shim. It runs on the client side (inside the agent's sandbox) and is
/// the only place that reads repository files for `moochy_delegate` (CONTRACT §15.2).
fn mcp(home: &Home, o: &Opts) -> Result<()> {
    let slug = slug_or_detect(o)?;
    let cwd_path = std::env::current_dir().ctx("cwd")?;
    let cwd = cwd_path.to_string_lossy().into_owned();
    let mut scope = crate::files::Scope { root: crate::files::git_root(&cwd_path), client_roots: None };
    // The shim starts the node when none is running (07 §5); stdout stays the MCP channel.
    if rt_small()?.block_on(crate::ctl::connect(&home.socket_path())).is_err() {
        start_node(home, false)?;
    }
    rt_small()?.block_on(async move {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        let (tx, rx) = tokio::sync::mpsc::channel::<McpUp>(32);
        let _ = tx.send(McpUp { msg: Some(mcp_up::Msg::Open(McpOpen { repo: slug, cwd })) }).await;
        // Both directions write stdout: node messages and the shim's own refusals.
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let replies = out_tx.clone();
        tokio::spawn(async move {
            use crate::mcp::{MAX_LINE, ShimLine, shim_line};
            let mut stdin = tokio::io::stdin();
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                let n = match stdin.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                while let Some(pos) = buf.iter().position(|c| *c == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    let line = line.trim_ascii().to_vec();
                    if line.is_empty() {
                        continue;
                    }
                    // File reads (and `git check-ignore`) run off the async reader.
                    let (act, back) = tokio::task::spawn_blocking(move || {
                        let a = shim_line(&line, &mut scope);
                        (a, scope)
                    })
                    .await
                    .unwrap_or_else(|_| (ShimLine::Forward(Vec::new()), crate::files::Scope::default()));
                    scope = back;
                    let ok = match act {
                        ShimLine::Forward(l) => l.is_empty() || tx.send(McpUp { msg: Some(mcp_up::Msg::Data(l)) }).await.is_ok(),
                        ShimLine::Reply(l) => replies.send(l).await.is_ok(),
                    };
                    if !ok {
                        return;
                    }
                }
                if buf.len() > MAX_LINE {
                    // Oversized line: hand it over as is; the node refuses it.
                    if tx.send(McpUp { msg: Some(mcp_up::Msg::Data(std::mem::take(&mut buf))) }).await.is_err() {
                        return;
                    }
                }
            }
        });
        let mut down = c.mcp_pipe(tokio_stream::wrappers::ReceiverStream::new(rx)).await.map_err(|s| net(s.message().to_owned()))?.into_inner();
        tokio::spawn(async move {
            while let Ok(Some(m)) = down.message().await {
                if out_tx.send(m.data).await.is_err() {
                    return;
                }
            }
        });
        let mut stdout = tokio::io::stdout();
        while let Some(d) = out_rx.recv().await {
            stdout.write_all(&d).await.ctx("stdout")?;
            stdout.flush().await.ctx("stdout")?;
        }
        Ok(())
    })
}


#[cfg(test)]
mod start_error_tests {
    #[test]
    fn start_error_reads_this_runs_message_only() {
        let dir = std::env::temp_dir().join(format!("moochy-start-error-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("node.log");
        let old = "{\"code\":\"network\",\"event\":\"error\",\"message\":\"an older run\"}\n";
        std::fs::write(&log, old).unwrap();
        let from = old.len() as u64;
        // This run: a plain line, then the node's JSON error with a terminal escape in it.
        let now = "starting\n{\"code\":\"auth\",\"event\":\"error\",\"message\":\"not logged in: run `moochy login` first\\u001b[2J\"}\n";
        std::fs::write(&log, format!("{old}{now}")).unwrap();
        assert_eq!(super::start_error(&log, from).as_deref(), Some("not logged in: run `moochy login` first[2J"));
        // Nothing new after `from`: no message (the caller falls back to "see node.log").
        std::fs::write(&log, old).unwrap();
        assert_eq!(super::start_error(&log, from), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
