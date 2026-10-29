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

pub(crate) const HELP: &str = "moochy: give AI tokens from your own key or GPU, to open source or anyone, and use the tokens given to you.
Open-source client (Apache-2.0) · 100% free

USAGE: moochy [--home DIR] <COMMAND> [OPTIONS]
PROJECT: owner/name or github/owner/name (GitHub), gitlab/group[/subgroup…]/name (GitLab);
         default: the github.com or gitlab.com `origin` remote of the current directory

COMMANDS:
  start [<provider>] [--key-stdin] [--repo PROJECT] [--cap N] [--no-browser]
                                  Set up this machine and donate, step by step: sign in, add
                                  the provider key (hidden input), the safety step, start the
                                  app, donate. Done steps are skipped: safe to run again
  start --headless <provider> --key-file PATH | start --headless --local URL --model local/<slug>=<id>
                                  The same with no terminal (containers): MOOCHY_MONTHLY_LIMIT,
                                  optional MOOCHY_DONATE=PROJECT with MOOCHY_DONATE_CAP; prints
                                  the sign-in code when needed, then runs the app in the foreground
  help [all]                      The short list, or every command and option
  tui [--demo] [--snapshot COLSxROWS [--keys K] [--ansi]] [--theme light|dark] [--ascii]
                                  The dashboard in your terminal (also: `moochy` alone)
  login [--relay URL] [--ca-file PEM] [--log-key VKEY] [--roles gateway,worker] [--name NAME] [--headless] [--no-browser]
                                  Add this device to your account (opens the approval page). Roles: gateway uses donated
                                  tokens, worker donates yours (asked on a terminal; scripts:
                                  gateway). Only the default server unless
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
                                  --personal (also env, mcp, connect): use the donations made
                                  for your own use, on any repository (also used when the
                                  project is not on Moochy)
  box token create [--repo PROJECT] [--ttl 24h] [--cap 20] [--max-boxes 1]
                                  A token that lets cloud boxes (boat.dev, E2B, Daytona, Modal,
                                  Codespaces) use this project's donations: each box gets its own
                                  keys, its own monthly limit and expires with the token. Shown once
  box token list [--repo P] | box token revoke <bt_…>
  box list [--repo P] | box revoke <d_…>
                                  Boxes enrolled for your projects; revoke one, or a token and all
                                  its boxes
  keys add <anthropic|openai|openrouter|deepseek|xai> [--key-stdin] [--base-url URL]
                                  Add a provider API key (xai = Grok), read from stdin (asked
                                  with hidden input on a terminal), never from the command line. It is checked with the provider's free
                                  models call and never leaves this machine (`local`: below)
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
  button --qr [--repo P|--org ORG|--person PERSON]
                                  The QR code of the donate page (its qr.svg URL and Markdown)
  audit --provider [--from-file usage.csv]
                                  What this device served (90 days), checked against the
                                  provider's usage export (date,model,cost_usd)
  safety [--monthly-limit N] [--accept-safety]
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
                                  agents outside `moochy run` when the project allows it
                                  too; warned at every start)
  connect <client> [--repo PROJECT] [--write]
                                  Show the setup for a coding tool, or merge it into the
                                  tool's config with --write (`connect list` shows the tools)
  report <task> [--reason TEXT]   Save signed evidence about a bad response
  verify <receipt_ref>            Check a public receipt of your request: donor signature,
                                  link to the signed receipt, public key log
  doctor                          Check the keystore, connection, clock, provider keys, socket
                                  and the sandbox support of this machine
  update --from-file BINARY       Install a signed release (unsigned files are refused)
  donate --repo PROJECT | --org ORG | --person PERSON --cap N [--weekly-limit N]
         [--daily-limit N] [--yes]
                                  Donate tokens to a project, up to N dollars a month (it starts once
                                  the project owner accepts you); optional weekly (Monday 00:00
                                  UTC) and daily (00:00 UTC) limits, no higher than the monthly
                                  one; --org donates to an organisation
                                  (github/ORG or gitlab/GROUP[/SUB…]), shared by the projects its
                                  owner covers; --person sponsors a maintainer (github/LOGIN or
                                  gitlab/USERNAME): their own requests on the repos they cover
  donations [--json] | donations <pause|resume|stop> <id>
                                  Your donations: what each project or organisation used this month
  donate --credits N --repo PROJECT | --org ORG | --person PERSON [--yes]
                                  Give a one-off total from your Moochy Credits balance
  credits [--json] | credits add [N]
                                  Your Moochy Credits (balance, purchases, allocations); add
                                  opens the web page (cards are only ever entered there)
  gift create N [--credits] [--note TEXT] [--models a,b] [--effort E]
       [--visibility public|pseudonymous|anonymous] [--expires DAYS]
                                  A gift link for $1 to $1,000 of tokens, shown once: the first
                                  person to claim it gets it (30 days by default, 90 at most)
  gift list [--json] | gift revoke <gf_…> [--replace]
                                  Your gifts; revoke one, or replace its link
  gift claim <LINK> --repo PROJECT | --org ORG | --person PERSON | --personal [--yes]
                                  Claim a gift for your project, organisation, profile or own
                                  use; accepted at once with an owner key on this machine
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
  members <add|remove> <user> --repo PROJECT [--device] [--cap N | --cap-uusd N] [--yes]
                                  Let a person (or a CI device) use your project's donations,
                                  up to N dollars a month
  claim <PROJECT> [--yes]         Confirm you maintain a project, signed by your owner key
                                  (also: claim --repo PROJECT)
  claim --org ORG [--yes]         Confirm you own an organisation (github/ORG: an admin;
                                  gitlab/GROUP[/SUB…]: an Owner)
  org <add|remove> <PROJECT>… --org ORG [--yes] | org list --org ORG [--json]
                                  Which of your projects your organisation's donations fund
  claim --person [PERSON] [--yes] Confirm your own GitHub/GitLab profile (after signing in on
                                  the web: Claim your profile), so people can sponsor you
  person <add|remove> <PROJECT>… [--person PERSON] [--yes] | person list [--person PERSON] [--json]
                                  Which public repos you maintain your sponsors' tokens serve
                                  (your own requests only; several at once: one passphrase)

ENV: MOOCHY_HOME, MOOCHY_PASSPHRASE (encrypted-file keystore), MOOCHY_ENROLL (cloud box enrollment token),
     MOOCHY_INSECURE_DEV=1 (development only)
";

/// `moochy --help` (plan 14 §3): the commands people use. `moochy help all` prints [`HELP`].
pub(crate) const HELP_SHORT: &str = "moochy: give AI tokens from your own key or GPU, to open source or anyone, and use the tokens given to you.
Open-source client (Apache-2.0) · 100% free

USAGE: moochy [--home DIR] <COMMAND> [OPTIONS]
PROJECT: owner/name (GitHub) or gitlab/group/name; default: the `origin` remote here

Donate or gift tokens:
  start                           Set up this machine and donate, step by step (safe to repeat)
  donate --repo PROJECT --cap 20  Donate tokens to a project, up to $20 a month
  donations                       Your donations: what each project used this month
  gift create 20                  A single-use link and QR code worth $20 of your tokens
  gift claim <link>               Claim a gift for your project or your own use (--personal)
  pause | resume                  Stop or restart donating from this machine
  keys add <provider>             Add a provider API key (anthropic, openai, openrouter,
                                  deepseek, xai; local: your own GPU)

Use the tokens given to you:
  connect <client> [--repo PROJECT]
                                  Set up a coding tool (`moochy connect list` shows the tools)
  run [--repo PROJECT] -- <cmd>   Run your coding agent in a sandbox wired to Moochy

This machine:
  status                          Connection, slots in use, donations available
  tui                             The dashboard in your terminal (also: `moochy` alone)
  doctor                          Check the keystore, connection, clock and provider keys

More: moochy help all (every command and option)
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
    /// `moochy start --headless --key-file PATH`: the provider key from a file (a Docker secret).
    key_file: Option<PathBuf>,
    /// `moochy gift create` (plan 15 §3): `--note`, `--effort`, `--visibility`, `--expires`.
    gift: GiftOpts,
    flags: Vec<&'static str>,
}

#[derive(Default)]
struct GiftOpts {
    note: Option<String>,
    effort: Option<String>,
    visibility: Option<String>,
    expires: Option<u32>,
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
            Long("key-file") => o.key_file = Some(PathBuf::from(p.value().map_err(err)?)),
            // `moochy start --headless --local URL`: a model server, as `keys add local --base-url`.
            Long("local") => {
                o.base_url = Some(s(p.value().map_err(err)?)?);
                o.flags.push("local");
            }
            Long("ttl") => o.ttl = Some(s(p.value().map_err(err)?)?),
            Long("max-boxes") => o.max_boxes = Some(s(p.value().map_err(err)?)?.parse().map_err(|_| usage("--max-boxes is a whole number"))?),
            Long("model") => o.models.push(s(p.value().map_err(err)?)?),
            Long("models") => o.models.extend(s(p.value().map_err(err)?)?.split(',').map(str::trim).filter(|m| !m.is_empty()).map(str::to_owned)),
            Long("note") => o.gift.note = Some(s(p.value().map_err(err)?)?),
            Long("effort") => o.gift.effort = Some(s(p.value().map_err(err)?)?),
            Long("visibility") => o.gift.visibility = Some(s(p.value().map_err(err)?)?),
            Long("expires") => o.gift.expires = Some(s(p.value().map_err(err)?)?.parse().ok().filter(|d| *d > 0).ok_or_else(|| usage("--expires is a number of days (1 to 90)"))?),
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
                let known = ["headless", "no-browser", "foreground", "offline", "json", "rotate", "follow", "key-stdin", "shell", "yes", "revoke", "device", "write", "unsafe-no-lockdown", "unsafe-no-sandbox", "git-writable", "allow-unvetted-host", "accept-safety", "system", "print", "provider", "box-is-sandbox", "chart", "qr", "credits", "replace", "personal"];
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
    let mut o = parse()?;
    if o.has("version") {
        println!("moochy {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    match o.words.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["help", "all"] => {
            print!("{HELP}");
            return Ok(());
        }
        _ if o.has("help") => {
            print!("{HELP_SHORT}");
            return Ok(());
        }
        ["help"] => {
            print!("{HELP_SHORT}");
            return Ok(());
        }
        _ => {}
    }
    if o.words.is_empty() {
        use std::io::IsTerminal as _;
        // CONTRACT §20.1: `moochy` alone on an interactive terminal opens the dashboard.
        if o.flags.is_empty() && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            return tui(o.home.clone(), &[]);
        }
        eprint!("{HELP_SHORT}");
        return Err(usage("missing command"));
    }
    let home = Home::resolve(o.home.clone())?;
    // Bare `moochy approve` / `accept` (what the web pages and emails suggest): the donors waiting
    // for you. One: that donor, with its project, organisation or profile. Several: the commands.
    if matches!(o.words.as_slice(), [c] if c == "approve" || c == "accept") {
        let home = Home::resolve(o.home.clone())?;
        match waiting_donor(&home)? {
            Some((donor, flag, target)) => {
                o.words.push(donor);
                match flag {
                    "--org" => o.org = Some(target),
                    "--person" => o.person = Some(target),
                    _ => o.repo = Some(target),
                }
            }
            None => return Ok(()),
        }
    }
    if o.words.first().is_some_and(|c| c == "start") {
        return start(home, &mut o);
    }
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
    if let [cmd @ ("approve" | "accept" | "claim" | "members" | "owner" | "org" | "person" | "pending" | "decisions" | "box" | "donate" | "safety" | "audit" | "gift" | "credits"), ..] | [cmd @ "keys", "add" | "revoke", ..] = w.as_slice() {
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
        // Never echo the extra word: it is likely the key itself.
        ["keys", "add", _, _, ..] => Err(usage("the key is read from stdin, never from the command line (it would stay in your shell history and the process list): printf %s \"$KEY\" | moochy keys add <provider> --key-stdin")),
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
        ["donate"] if o.has("credits") => Err(usage("donate --credits AMOUNT --repo PROJECT | --org ORG | --person PERSON")),
        ["donate"] => donate(&home, &o, None),
        ["donate", amount] if o.has("credits") => donate(&home, &o, Some(amount)),
        ["gift", rest @ ..] => gift_cmd(&home, &o, rest),
        ["credits"] => crate::gift::show(&home, o.has("json")),
        ["credits", "add"] => crate::gift::add(&home, None),
        ["credits", "add", amount] => crate::gift::add(&home, Some(amount)),
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
/// provider ports it may reach. A change applies at the next start. Plan 14 §3: for a person at a
/// terminal, restart it (through the service when one is installed) and say so; scripts and test
/// harnesses run their own `up --foreground`, so they only get the note.
fn restart_note(home: &Home, what: &str) {
    if !running(home) {
        return;
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        eprintln!("The app is running: restart it with `moochy down && moochy up` to use the new {what}.");
        return;
    }
    let r = if crate::service::installed() { crate::service::restart() } else { stop(home).and_then(|()| start_node(home, false).map(drop)) };
    match r {
        Ok(()) => eprintln!("Restarted the app to use the new {what}."),
        Err(e) => eprintln!("Could not restart the app ({}): run `moochy down && moochy up`.", clean(&e.msg)),
    }
}

/// Bare `moochy approve`: the one donor waiting for your signature as (donor, flag, target), or
/// `None` after printing that nobody waits or the command for each of several.
fn waiting_donor(home: &Home) -> Result<Option<(String, &'static str, String)>> {
    let r = rt_small()?.block_on(async {
        let mut c = crate::ctl::connect(&home.socket_path()).await?;
        c.pending(crate::pb::local::PendingRequest {}).await.map(tonic::Response::into_inner).map_err(|s| internal(clean(s.message()).into_owned()))
    })?;
    let waiting = waiting_of(&r.requests);
    match waiting.as_slice() {
        [] => {
            eprintln!("No donor is waiting for your approval (`moochy pending` shows every request).");
            Ok(None)
        }
        [one] => Ok(Some(one.clone())),
        many => {
            eprintln!("{} donors are waiting for your approval. Accept each one:", many.len());
            for (d, flag, t) in many {
                eprintln!("  moochy approve {} {flag} {}", clean(d), clean(t));
            }
            Ok(None)
        }
    }
}

/// The unsigned donor requests as (donor, flag, target): handle else pseudonym; `--org`,
/// `--person` or `--repo` with the request's own target.
fn waiting_of(reqs: &[crate::pb::local::SignResponse]) -> Vec<(String, &'static str, String)> {
    reqs.iter()
        .filter(|q| q.kind == "DONOR_APPROVED" && !q.signed)
        .map(|q| {
            let donor = if q.subject_username.is_empty() { q.subject.clone() } else { q.subject_username.clone() };
            let (flag, target) = if !q.org_path.is_empty() {
                ("--org", q.org_path.clone())
            } else if !q.person_path.is_empty() {
                ("--person", q.person_path.clone())
            } else {
                ("--repo", q.repo_slug.clone())
            };
            (donor, flag, target)
        })
        .filter(|(d, _, t)| !d.is_empty() && !t.is_empty())
        .collect()
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
fn donate(home: &Home, o: &Opts, credits: Option<&str>) -> Result<()> {
    use crate::donations::To;
    let (target, to) = match (org_arg(o)?, person_arg(o)?) {
        (_, Some(p)) if p.is_empty() => return Err(usage(format!("--person is {PERSON_FORMS}"))),
        (_, Some(p)) => (p, To::Person),
        (Some(org), None) => (org, To::Org),
        (None, None) => (slug_or_detect(o)?, To::Repo),
    };
    let limits = crate::donations::Limits { monthly: o.cap.unwrap_or(0), weekly: o.weekly_limit, daily: o.daily_limit };
    // Plan 15 §5.2: credits pay a one-off total, without a schedule or windows.
    if credits.is_some() && (o.cap.is_some() || o.weekly_limit.is_some() || o.daily_limit.is_some()) {
        return Err(usage("--credits gives a one-off total: no --cap, --weekly-limit or --daily-limit"));
    }
    if credits.is_none() {
        limits.check()?;
    }
    // Plan 14 §3: the donation goes through the app; start it rather than fail.
    if !running(home) {
        start_node(home, false)?;
        eprintln!("Started the Moochy app (`moochy down` stops it).");
    }
    match credits {
        Some(amount) => crate::gift::donate(home, &target, to, amount, o.has("yes"))?,
        None => crate::donations::donate(home, &target, to, limits, o.has("yes"))?,
    }
    share(home, &crate::button::page(to, &target)?);
    Ok(())
}

/// Plan 14 §3: what `moochy start` still has to do on this machine, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Login,
    Key,
    Safety,
    Up,
    Donate,
}

/// What is already done here (read from the config, the keystore and the socket).
#[derive(Clone, Copy, Debug, Default)]
#[allow(clippy::struct_excessive_bools, reason = "one flag per start step")]
struct Done {
    login: bool,
    key: bool,
    safety: bool,
    running: bool,
}

/// The steps left; donating is checked with the app (it knows the account's donations).
fn todo(d: Done) -> Vec<Step> {
    [(Step::Login, d.login), (Step::Key, d.key), (Step::Safety, d.safety), (Step::Up, d.running), (Step::Donate, false)].into_iter().filter(|(_, done)| !done).map(|(s, _)| s).collect()
}

fn safety_done(cfg: &crate::config::Config) -> bool {
    cfg.donor_safety_ack_ms.is_some() && cfg.device_monthly_cap_uusd.is_some()
}

fn done(home: &Home) -> Result<Done> {
    let cfg = home.load()?;
    let login = cfg.device_id.is_some();
    if login && !cfg.roles.iter().any(|r| r == "worker") {
        return Err(usage("this device is signed in to use donated tokens only: to donate from this machine, use another --home, or `moochy logout` and run `moochy start` again"));
    }
    let key = login && keystore::load(home, &cfg)?.is_some_and(|s| !s.providers.is_empty());
    Ok(Done { login, key, safety: safety_done(&cfg), running: running(home) })
}

/// `moochy start` (plan 14 §3): the first run in a terminal. `--headless`: [`start_headless`].
fn start(home: Home, o: &mut Opts) -> Result<()> {
    use std::io::IsTerminal as _;
    crate::boxes::refuse_on_box(&home.load()?, "start")?;
    let provider = match o.words.as_slice() {
        [_] => None,
        [_, p] => Some(p.clone()),
        _ => return Err(usage("moochy start [<provider>] (the key is asked, or read with --key-stdin)")),
    };
    if o.has("headless") {
        return start_headless(home, o, provider.as_deref());
    }
    if !std::io::stdin().is_terminal() {
        return Err(usage("moochy start asks questions: run it in a terminal (containers and scripts: moochy start --headless)"));
    }
    let p = crate::style::err();
    let mut offered_safety = false;
    for step in todo(done(&home)?) {
        match step {
            Step::Login => {
                let relay = checked_relay(o, None)?;
                let name = o.name.clone().unwrap_or_else(crate::login::default_name);
                rt_small()?.block_on(crate::login::login(&home, &relay, o.ca_file.clone(), vec!["gateway".into(), "worker".into()], name, None, !o.has("no-browser")))?;
            }
            Step::Key => {
                let provider = if let Some(p) = &provider {
                    p.clone()
                } else {
                    let a = crate::owner::ask(&format!("Provider ({}) [anthropic]: ", crate::keycheck::PROVIDERS.join(", ")), false)?;
                    if a.trim().is_empty() { "anthropic".into() } else { a.trim().to_ascii_lowercase() }
                };
                keys_add(&home, &provider, o)?;
                offered_safety = provider != "local";
            }
            Step::Safety => {
                if !offered_safety {
                    safety(&home, o, provider.as_deref())?;
                }
                if !safety_done(&home.load()?) {
                    return Ok(());
                }
            }
            Step::Up => {
                let service = !crate::service::installed() && crate::owner::ask("Start Moochy when you log in? [Y/n] ", false).is_ok_and(|a| !a.trim().eq_ignore_ascii_case("n") && !a.trim().eq_ignore_ascii_case("no"));
                if service {
                    crate::service::install(&home, false, false)?;
                    if !(0..60).any(|_| {
                        std::thread::sleep(Duration::from_millis(250));
                        running(&home)
                    }) {
                        return Err(internal("the service did not start the app: `moochy up` starts it without the service (log: journalctl --user -u moochy)"));
                    }
                } else {
                    start_node(&home, false)?;
                }
                eprintln!("{}{}", p.mark(true), p.ok("Moochy is running."));
            }
            Step::Donate => start_donate(&home, o)?,
        }
    }
    eprintln!(
        "{}\n  The maintainer accepts you first; then requests use your key, up to your limits. Your key never leaves this machine.\n  `moochy donations` shows what each project used. `moochy pause` stops donating from this machine.",
        p.bold("What happens next:")
    );
    Ok(())
}

/// The donation step of `moochy start`: skipped when this account already donates.
fn start_donate(home: &Home, o: &Opts) -> Result<()> {
    let n = crate::donations::mine(home)?.len();
    if n > 0 {
        eprintln!("You already donate tokens ({n} donation{}): `moochy donations` shows them.", if n == 1 { "" } else { "s" });
        return Ok(());
    }
    let detected = o.repo.as_deref().map(canonical_repo).transpose()?.or_else(detect_repo);
    let a = crate::owner::ask(&format!("Project to donate tokens to (owner/name){}: ", detected.as_deref().map(|d| format!(" [{d}]")).unwrap_or_default()), false)?;
    let Some(slug) = (if a.trim().is_empty() { detected } else { Some(canonical_repo(a.trim())?) }) else {
        eprintln!("Not donating yet. Later: moochy donate --repo OWNER/NAME --cap 20");
        return Ok(());
    };
    let monthly = if let Some(c) = o.cap {
        c
    } else {
        let a = crate::owner::ask("Monthly amount in dollars [20]: ", false)?;
        let v = crate::util::parse_amount(if a.trim().is_empty() { "20" } else { a.trim() }).map_err(|e| usage(format!("the monthly amount (dollars, e.g. 20): {e}")))?;
        i64::try_from(v).map_err(|_| usage("the monthly amount is too large"))?
    };
    crate::donations::donate(home, &slug, crate::donations::To::Repo, crate::donations::Limits { monthly, weekly: o.weekly_limit, daily: o.daily_limit }, true)?;
    share(home, &crate::button::page(crate::donations::To::Repo, &slug)?);
    Ok(())
}

/// `moochy start --headless` settings from the environment (plan 14 §5).
#[derive(Debug, PartialEq, Eq)]
struct Headless {
    /// `MOOCHY_MONTHLY_LIMIT` (µ$): the safety step; setting it accepts the spend-limit advice.
    monthly_limit: Option<u64>,
    /// `MOOCHY_DONATE` (a project) and `MOOCHY_DONATE_CAP` (dollars a month, µ$ here).
    donate: Option<(String, i64)>,
}

fn headless_env(get: impl Fn(&str) -> Option<String>) -> Result<Headless> {
    let get = |k: &str| get(k).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
    let monthly_limit = get("MOOCHY_MONTHLY_LIMIT").map(|v| crate::config::device_limit(&v)).transpose()?;
    let donate = match (get("MOOCHY_DONATE"), get("MOOCHY_DONATE_CAP")) {
        (None, None) => None,
        (Some(p), Some(c)) => {
            let cap = crate::util::parse_amount(&c).map_err(|e| usage(format!("MOOCHY_DONATE_CAP (dollars a month, e.g. 20): {e}")))?;
            Some((canonical_repo(&p)?, i64::try_from(cap).map_err(|_| usage("MOOCHY_DONATE_CAP is too large"))?))
        }
        (Some(_), None) => return Err(usage("MOOCHY_DONATE needs MOOCHY_DONATE_CAP (dollars a month, e.g. 20)")),
        (None, Some(_)) => return Err(usage("MOOCHY_DONATE_CAP needs MOOCHY_DONATE (the project, owner/name)")),
    };
    Ok(Headless { monthly_limit, donate })
}

/// `moochy start --headless` (plan 14 §5): the same steps with no terminal, each one skipped when
/// done, so a container can run it at every start. Ends as `up --foreground` in this process.
fn start_headless(home: Home, o: &mut Opts, provider: Option<&str>) -> Result<()> {
    let env = headless_env(|k| std::env::var(k).ok())?;
    let local = o.has("local");
    let provider = if local { "local" } else { provider.ok_or_else(|| usage("start --headless needs <provider> --key-file PATH, or --local URL --model local/<slug>=<id>"))? };
    if !local && o.key_file.is_none() {
        return Err(usage("start --headless <provider> needs --key-file PATH (a file with the key, e.g. a Docker secret)"));
    }
    let cfg = home.load()?;
    if env.monthly_limit.is_none() && !safety_done(&cfg) {
        return Err(usage("set MOOCHY_MONTHLY_LIMIT (dollars a month for this machine, e.g. 25): the safety step before donating"));
    }
    if let Some(l) = env.monthly_limit {
        o.monthly_limit = Some(l);
        o.flags.push("accept-safety");
    }
    if cfg.device_id.is_none() {
        let relay = checked_relay(o, None)?;
        let name = o.name.clone().unwrap_or_else(crate::login::default_name);
        let roles = o.roles.as_deref().unwrap_or("gateway,worker").split(',').map(|r| r.trim().to_owned()).collect();
        rt_small()?.block_on(crate::login::login(&home, &relay, o.ca_file.clone(), roles, name, None, false))?;
    }
    let cfg = home.load()?;
    if local {
        // Re-read at every start: the server's model list may have changed.
        crate::keycheck::add_local(&home, o.base_url.as_deref(), false, false, &o.models)?;
    } else {
        let sec = keystore::load(&home, &cfg)?.unwrap_or_default();
        let key = provider_key(provider, o)?;
        if !sec.providers.iter().any(|p| p.provider == provider && p.key == *key) {
            keys_add(&home, provider, o)?;
        }
    }
    let cfg = home.load()?;
    if !safety_done(&cfg) || env.monthly_limit.is_some_and(|l| Some(l) != cfg.device_monthly_cap_uusd) {
        safety(&home, o, Some(provider))?;
    }
    if let Some((slug, monthly)) = env.donate {
        start_node(&home, false)?;
        let r = (|| {
            if crate::donations::mine(&home)?.iter().any(|d| d.repo_slug.eq_ignore_ascii_case(&slug)) {
                return Ok(());
            }
            crate::donations::donate(&home, &slug, crate::donations::To::Repo, crate::donations::Limits { monthly, weekly: None, daily: None }, true)
        })();
        stop(&home)?;
        r?;
    }
    up_foreground(home, false, false)
}

/// `moochy gift …` (plan 15 §3.2).
fn gift_cmd(home: &Home, o: &Opts, w: &[&str]) -> Result<()> {
    match w {
        ["create", amount] => {
            let q = crate::pb::link::CreateGiftRequest {
                source: if o.has("credits") { "credits" } else { "tokens" }.into(),
                amount_uusd: crate::gift::amount(amount)?,
                models: o.models.clone(),
                max_effort: o.gift.effort.clone().unwrap_or_default(),
                visibility: o.gift.visibility.clone().unwrap_or_else(|| "public".into()),
                note: o.gift.note.clone().unwrap_or_default(),
                expires_days: o.gift.expires.unwrap_or(0),
                ..crate::pb::link::CreateGiftRequest::default()
            };
            crate::gift::create(home, q, o.has("json"))
        }
        ["list"] => crate::gift::list(home, o.has("json")),
        ["revoke", id] => crate::gift::revoke(home, id, o.has("replace"), o.has("json")),
        ["claim", link] => {
            let mut q = crate::pb::link::ClaimGiftRequest::default();
            match (o.has("personal"), org_arg(o)?, person_arg(o)?) {
                (true, None, None) if o.repo.is_none() => q.personal = true,
                (true, ..) => return Err(usage("--personal goes alone: the gift is for your own use")),
                (false, _, Some(p)) => q.person = if p.is_empty() { own_person(home, o, false)? } else { p },
                (false, Some(org), None) => q.org = org.to_ascii_lowercase(),
                (false, None, None) => q.repo_slug = o.repo.as_deref().map(canonical_repo).transpose()?.ok_or_else(|| usage("gift claim <link> --repo PROJECT | --org ORG | --person PERSON | --personal"))?.to_ascii_lowercase(),
            }
            let d = crate::gift::claim(home, link, q.clone())?;
            accept_gift(home, o, &q, &d)
        }
        _ => Err(usage("gift create AMOUNT [--credits] … | gift list | gift revoke <gf_…> [--replace] | gift claim <link> --repo PROJECT | --org ORG | --person PERSON | --personal")),
    }
}

/// Plan 15 §3.2: a claimed gift waits for the claimer's acceptance. With an owner key here, accept
/// it now through the `moochy accept` path (decoded body, Lookup A217/A218, one passphrase);
/// otherwise say how.
fn accept_gift(home: &Home, o: &Opts, q: &crate::pb::link::ClaimGiftRequest, d: &crate::pb::link::Donation) -> Result<()> {
    use crate::org::{Group, Op, sign};
    if d.status != "pending" {
        return Ok(());
    }
    let cfg = home.load()?;
    let id = clean(&d.pledge_id).into_owned();
    if !crate::owner::key_path(home, cfg.relay.as_deref()).exists() {
        eprintln!("Accept it with your passkey: {}/decide/{id}", crate::decisions::web_origin(home));
        let flag = if q.personal {
            "--personal".to_owned()
        } else if !q.person.is_empty() {
            format!("--person {}", q.person)
        } else if q.org.is_empty() {
            format!("--repo {}", q.repo_slug)
        } else {
            format!("--org {}", q.org)
        };
        eprintln!("(or with an owner key on this machine: moochy accept {id} {})", clean(&flag));
        return Ok(());
    }
    // The donor's handle: in the answer, else from the signature request the relay pushes.
    let mut donor = d.donor.clone();
    for _ in 0..20 {
        if !donor.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
        donor = donor_of_request(home, &d.pledge_id).unwrap_or_default();
    }
    if donor.is_empty() {
        donor = donor_of_request(home, &d.pledge_id)?;
    }
    let yes = o.has("yes");
    if !q.person.is_empty() {
        sign(home, Group::Person, &q.person, &[Op::Donor { donor: &donor, revoke: false }], yes)
    } else if !q.org.is_empty() {
        sign(home, Group::Org, &q.org, &[Op::Donor { donor: &donor, revoke: false }], yes)
    } else if q.personal {
        crate::owner::sign(home, crate::node::PERSONAL_SLUG, &["approve", &donor], yes, false, false, 0)
    } else {
        crate::owner::sign(home, &q.repo_slug, &["approve", &donor], yes, false, false, 0)
    }
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
    stop(home)?;
    emit(&json!({"event": "stopped"}));
    let p = crate::style::err();
    if p.tty {
        eprintln!("{}{}", p.mark(true), p.ok("Moochy stopped."));
    }
    Ok(())
}

/// Ask the app to stop and wait (bounded) until its socket is gone.
fn stop(home: &Home) -> Result<()> {
    rt_small()?.block_on(async {
        let r = crate::ctl::connect(&home.socket_path()).await?.shutdown(ShutdownRequest {}).await;
        // The app may exit before its answer is flushed: stopped means the socket is gone.
        for _ in 0..if r.is_ok() { 200 } else { 40 } {
            if crate::ctl::connect(&home.socket_path()).await.is_err() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        r.map(drop).map_err(|s| internal(s.message().to_owned()))
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
/// (for `claim`: a waiting PERSON_CLAIMED, started on the web), else your code-host handle's
/// profile when the key log says you claimed it.
fn own_person(home: &Home, o: &Opts, claim: bool) -> Result<String> {
    if let Some(p) = person_arg(o)?.filter(|p| !p.is_empty()) {
        remember_handle(home, &p);
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
        [] => crate::org::own_profile(home).ok_or_else(|| {
            if home.load().is_ok_and(|c| c.handle.as_deref().is_none_or(str::is_empty)) {
                // Signed in before 0.1.4: the handle was not stored then (m9).
                usage(format!("this app does not know your handle yet (you signed in before moochy 0.1.4): pass --person {PERSON_FORMS} once and it is remembered"))
            } else {
                usage(format!("no person profile of yours is known to the app: claim it first (moochy claim --person), or pass --person {PERSON_FORMS}"))
            }
        }),
        _ => Err(usage(format!("more than one profile: pass --person {PERSON_FORMS}"))),
    }
}

/// A login from before 0.1.4 stored no handle: when `--person` names a profile that the verified
/// key log says this account owns, keep its login as the handle (display and inference only,
/// never signed). Best effort: any failure leaves the config as it was.
fn remember_handle(home: &Home, path: &str) {
    let Ok(mut cfg) = home.load() else { return };
    if cfg.handle.as_deref().is_some_and(|h| !h.is_empty()) {
        return;
    }
    let Some(owned) = crate::org::owned_profile(home, &[path.to_owned()]) else { return };
    let login = owned.split_once('/').map_or("", |(_, l)| l);
    if crate::config::plain_handle(login) {
        cfg.handle = Some(login.to_owned());
        let _ = home.save(&cfg);
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
            sign(home, Group::Person, &person, &[Op::Claim], yes)?;
            share(home, &format!("people/{person}"));
            // §24.3: nothing is proposed for every repo you maintain; you pick them.
            eprintln!("Choose the public repos your sponsors' tokens serve: moochy person add <PROJECT>… (one passphrase for all), or tick them in your profile settings: {}/people/{person}/settings", clean(&crate::decisions::web_origin(home)));
            Ok(())
        }
        ["person", op @ ("add" | "remove"), repos @ ..] if !repos.is_empty() => {
            let repos = canonical_repos(repos)?;
            sign(home, Group::Person, &person, &repos.iter().map(|repo| Op::Repo { repo, remove: *op == "remove" }).collect::<Vec<_>>(), yes)
        }
        ["person", "list"] => list(home, Group::Person, &person, o.has("json")),
        ["approve" | "accept", donor] if !donor.is_empty() => sign(home, Group::Person, &person, &[Op::Donor { donor, revoke: o.has("revoke") }], yes),
        _ => Err(usage(format!("person <add|remove> <PROJECT>… | person list | claim --person | accept <donor> --person [PERSON]: PERSON is {PERSON_FORMS}"))),
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
            sign(home, Group::Org, &org, &[Op::Claim], yes)?;
            share(home, &format!("org/{org}"));
            Ok(())
        }
        ["org", op @ ("add" | "remove"), repos @ ..] if !repos.is_empty() => {
            let repos = canonical_repos(repos)?;
            sign(home, Group::Org, &org, &repos.iter().map(|repo| Op::Repo { repo, remove: *op == "remove" }).collect::<Vec<_>>(), yes)
        }
        ["org", "list"] => crate::org::list(home, Group::Org, &org, o.has("json")),
        ["approve" | "accept", donor] if !donor.is_empty() => sign(home, Group::Org, &org, &[Op::Donor { donor, revoke: o.has("revoke") }], yes),
        _ => Err(usage(format!("org <add|remove> <PROJECT>… --org ORG | org list --org ORG | claim --org ORG | accept <donor> --org ORG: ORG is {ORG_FORMS}"))),
    }
}

/// A `--repo` value in the link's canonical form (`owner/name` = GitHub, `gitlab/…`).
fn canonical_repo(r: &str) -> Result<String> {
    crate::config::canonical_slug(r).ok_or_else(|| usage(format!("--repo is {REPO_FORMS}")))
}

/// `org|person add|remove A B …`: each project in canonical lower case, once, in order.
fn canonical_repos(rs: &[&str]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(rs.len());
    for r in rs {
        let c = canonical_repo(r)?.to_ascii_lowercase();
        if !out.contains(&c) {
            out.push(c);
        }
    }
    Ok(out)
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
        // Plan 15: the donations made for this account's own use (the relay's personal pool).
        None if o.has("personal") => Ok(crate::node::PERSONAL_SLUG.into()),
        Some(_) if o.has("personal") => Err(usage("--personal and --repo exclude each other")),
        Some(r) => canonical_repo(r),
        None => detect_repo().ok_or_else(|| usage(format!("--repo is required (no github.com or gitlab.com `origin` remote here, or --personal): {REPO_FORMS}"))),
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
    // F05: split-view protection (A204): a public anchor, and whether the last check read it.
    match crate::keylog::effective_anchor(&cfg) {
        None if crate::keylog::effective_log_key(&cfg).is_none() => {}
        None if dev_mode() => println!("{} anchor    no public key-log anchor: split-view protection is off (MOOCHY_INSECURE_DEV)", tag("note")),
        None => line(false, "anchor", "no public key-log anchor and no witnesses: split-view protection is off (`moochy config set log_anchor_url https://…`)".into()),
        Some(u) if st.as_ref().is_some_and(|s| s.alerts.iter().any(|a| a.contains("anchor_unreadable"))) => {
            println!("{} anchor    {} could not be read at the last check: split-view protection is off until it can", tag("note"), clean(&u));
        }
        Some(u) => line(true, "anchor", format!("key log checked hourly against {u}")),
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
        // Cheapest first; only the models this tool's API door speaks (an older app sends no dialects).
        let dialect = crate::connect::dialect(client);
        let models: Vec<String> = st
            .pools
            .iter()
            .find(|p| p.slug.eq_ignore_ascii_case(&slug))
            .map(|p| p.models.iter().enumerate().filter(|(i, _)| p.model_dialects.get(*i).is_none_or(|ds| ds.split(',').any(|d| d == dialect))).map(|(_, m)| m.clone()).collect())
            .unwrap_or_default();
        Ok::<_, Error>((st.gateway_url, models))
    })?;
    // Plan 14 §4.1: small = the cheapest model, main = the next price tier (the project sets no
    // model preference and the catalog marks no model "small", so price rank is the signal).
    let small = clean(models.first().map_or("MODEL", String::as_str)).into_owned();
    let main = clean(models.get(1).map_or(small.as_str(), String::as_str)).into_owned();
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
    let roles = match &o.roles {
        Some(r) => r.clone(),
        // Plan 14 §3: a person at a terminal chooses; scripts keep the old default.
        None if !o.has("headless") && std::io::IsTerminal::is_terminal(&std::io::stdin()) => {
            let a = crate::owner::ask("Use donated tokens, donate yours, or both? [use/donate/both] (both): ", false)?;
            role_choice(&a).ok_or_else(|| usage("answer use, donate or both (or pass --roles gateway,worker)"))?.to_owned()
        }
        None => "gateway".into(),
    };
    let roles: Vec<String> = roles.split(',').map(|r| r.trim().to_owned()).collect();
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

/// `moochy login` on a terminal: the answer to "use, donate or both" as `--roles`.
fn role_choice(answer: &str) -> Option<&'static str> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "" | "both" | "b" => Some("gateway,worker"),
        "use" | "u" => Some("gateway"),
        "donate" | "d" => Some("worker"),
        _ => None,
    }
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
        return Err(usage(format!("provider must be one of: {}, local (your own model server: see --help)", crate::keycheck::PROVIDERS.join(", "))));
    }
    if let Some(u) = &o.base_url {
        crate::keycheck::check_base_url(u, dev_mode())?;
    }
    let key = provider_key(provider, o)?;
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

/// The provider key: stdin (`--key-stdin`), a file (`--key-file`, `start --headless`), or asked with
/// echo off on a terminal. Never from argv. Trimmed; empty or non-printable keys are refused later.
fn provider_key(provider: &str, o: &Opts) -> Result<zeroize::Zeroizing<String>> {
    use std::io::IsTerminal as _;
    let raw = if o.has("key-stdin") {
        let mut raw = zeroize::Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut std::io::Read::take(std::io::stdin(), 4097), &mut raw).ctx("read stdin")?;
        if raw.len() > 4096 {
            return Err(usage("key too long"));
        }
        // A190: borrow, never an un-zeroized intermediate copy of the key.
        zeroize::Zeroizing::new(std::str::from_utf8(&raw).map_err(|_| usage("key must be UTF-8"))?.to_owned())
    } else if let Some(p) = &o.key_file {
        keystore::read_secret(p, false, "provider key")?.ok_or_else(|| usage(format!("--key-file {}: no readable, non-empty file", p.display())))?
    } else if std::io::stdin().is_terminal() {
        crate::owner::ask(&format!("{provider} API key (hidden): "), true)?
    } else {
        return Err(usage("pass the key on stdin with --key-stdin (never as an argument)"));
    };
    Ok(zeroize::Zeroizing::new(raw.trim().to_owned()))
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
        if o.has("chart") == o.has("qr") || o.repo.is_some() || o.has("provider") || !rest.is_empty() {
            return Err(usage("button --chart|--qr --org github/ORG|gitlab/GROUP[/SUB…] | --person github/LOGIN|gitlab/USERNAME (not with --repo or --provider)"));
        }
        let (base, act) = match (&o.org, person_arg(o)?) {
            (_, Some(p)) => crate::button::group_base(crate::donations::To::Person, &p)?,
            (Some(org), None) => crate::button::group_base(crate::donations::To::Org, org)?,
            (None, None) => return Err(internal("unreachable")),
        };
        if o.has("qr") {
            let name = base.rsplit_once("/github/").or_else(|| base.rsplit_once("/gitlab/")).map_or("", |(_, n)| n);
            println!("{}", crate::button::qr(&base, act, name, &o.button)?);
            return Ok(());
        }
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
    let out = match (o.has("chart"), o.has("qr")) {
        (true, true) => return Err(usage("--chart or --qr, not both")),
        (true, false) => crate::button::project_chart(&project, &o.button)?,
        (false, true) => crate::button::project_qr(&project, &o.button)?,
        (false, false) => crate::button::snippet(&project, &o.button)?,
    };
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
    // F05: no anchor (and no witnesses): a relay could show this machine a key log nobody
    // else sees. Said at every start, not only in the log.
    if node.keylog.is_some() && crate::keylog::effective_anchor(&node.cfg).is_none() {
        eprintln!("WARNING: split-view protection is off: no public key-log anchor (`moochy config set log_anchor_url https://…`) and no witnesses, so the server could show this machine a key log nobody else sees (A204).");
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

#[cfg(test)]
mod waiting_tests {
    use crate::pb::local::SignResponse;

    #[test]
    fn bare_approve_targets() {
        let q = |kind: &str, signed: bool, user: &str, repo: &str, org: &str, person: &str| SignResponse {
            kind: kind.into(),
            signed,
            subject: "ps_aaaaaaaaaaaaaaaa".into(),
            subject_username: user.into(),
            repo_slug: repo.into(),
            org_path: org.into(),
            person_path: person.into(),
            ..Default::default()
        };
        let w = super::waiting_of(&[
            q("DONOR_APPROVED", false, "alice", "acme/api", "", ""),
            q("DONOR_APPROVED", false, "", "", "github/acme", ""),
            q("DONOR_APPROVED", false, "bob", "", "", "github/carol"),
            q("DONOR_APPROVED", true, "done", "acme/api", "", ""),
            q("REPO_CLAIMED", false, "me", "acme/api", "", ""),
        ]);
        assert_eq!(
            w,
            vec![
                ("alice".into(), "--repo", "acme/api".into()),
                ("ps_aaaaaaaaaaaaaaaa".into(), "--org", "github/acme".into()),
                ("bob".into(), "--person", "github/carol".into()),
            ]
        );
    }
}

#[cfg(test)]
mod start_tests {
    use super::{Done, HELP_SHORT, Headless, Step, headless_env, role_choice, todo};

    #[test]
    fn login_role_answers() {
        for (a, r) in [("", "gateway,worker"), ("both", "gateway,worker"), (" Donate\n", "worker"), ("use", "gateway"), ("u", "gateway")] {
            assert_eq!(role_choice(a), Some(r), "{a:?}");
        }
        assert_eq!(role_choice("all"), None);
    }

    #[test]
    fn start_skips_done_steps() {
        assert_eq!(todo(Done::default()), [Step::Login, Step::Key, Step::Safety, Step::Up, Step::Donate]);
        assert_eq!(todo(Done { login: true, key: true, safety: true, running: true }), [Step::Donate]);
        assert_eq!(todo(Done { login: true, key: false, safety: true, running: true }), [Step::Key, Step::Donate]);
    }

    #[test]
    fn headless_env_parsing() {
        let env = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned());
        assert_eq!(headless_env(env(&[])).unwrap(), Headless { monthly_limit: None, donate: None });
        assert_eq!(headless_env(env(&[("MOOCHY_MONTHLY_LIMIT", "$25"), ("MOOCHY_DONATE", "github/acme/widget"), ("MOOCHY_DONATE_CAP", "20.50")])).unwrap(), Headless { monthly_limit: Some(25_000_000), donate: Some(("acme/widget".into(), 20_500_000)) });
        assert_eq!(headless_env(env(&[("MOOCHY_MONTHLY_LIMIT", " "), ("MOOCHY_DONATE", "")])).unwrap().monthly_limit, None, "blank means unset");
        assert!(headless_env(env(&[("MOOCHY_DONATE", "acme/widget")])).is_err(), "a donation needs its cap");
        assert!(headless_env(env(&[("MOOCHY_DONATE_CAP", "20")])).is_err(), "a cap needs a project");
        assert!(headless_env(env(&[("MOOCHY_DONATE", "not a project"), ("MOOCHY_DONATE_CAP", "20")])).is_err());
        assert!(headless_env(env(&[("MOOCHY_MONTHLY_LIMIT", "0")])).is_err());
    }

    #[test]
    fn short_help_is_short_and_lists_start() {
        assert!(HELP_SHORT.lines().count() <= 30, "{}", HELP_SHORT.lines().count());
        for c in ["  start", "  donate", "  donations", "  pause | resume", "  status", "  keys add", "  connect", "  run", "  tui", "  doctor", "help all"] {
            assert!(HELP_SHORT.contains(c), "{c}");
        }
        assert!(!HELP_SHORT.contains("$N") && !super::HELP.contains("$N"), "amounts are plain numbers");
    }
}
