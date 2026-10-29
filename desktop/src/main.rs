//! Moochy desktop (moochy-docs plan 14 §2): a small window over the `moochy` binary. It is a remote
//! control, never a second node. State, live updates and the TUI's actions go over the node's
//! control socket through `NodeSource`; every other step runs `moochy --home H <command>` as a
//! child and reads its JSON event lines. The app commands below are the whole IPC surface.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing))]

mod check;

use moochy_node::config::Home;
use moochy_node::tuisrc::NodeSource;
use moochy_tui::sanitize::clean;
use moochy_tui::source::{Action, ActionResult, Source as _, SourceEvent};
use serde_json::{Value, json};
use std::io::{BufRead as _, Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tauri::{Emitter as _, Manager as _, State};
use zeroize::Zeroizing;

/// Longest a child may run (provider key check, donate, up); `login` waits on the person instead.
const CHILD: Duration = Duration::from_secs(120);
/// Most output read from a child, per stream.
const MAX_OUT: u64 = 1 << 20;

struct Ctx {
    /// The `moochy` binary: the bundled sidecar next to this executable, else `moochy` on PATH.
    bin: PathBuf,
    home: Home,
    source: Mutex<NodeSource>,
    /// The web origin of the last snapshot (`Me.web`): links may open there too.
    web: Mutex<String>,
    /// The running `moochy login` and its generation (a cancelled one must not report).
    login: Mutex<(u64, Option<Child>)>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a finished child left: exit code, stdout, and its error message (cleaned).
struct Out {
    ok: bool,
    stdout: String,
    error: String,
}

impl Out {
    fn into_result(self) -> Result<String, String> {
        if self.ok { Ok(self.stdout) } else { Err(self.error) }
    }
}

fn read_all(r: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = r.take(MAX_OUT).read_to_string(&mut s);
        s
    })
}

/// The error a child printed: its last `{"event":"error"}` line (CONTRACT §6), else its last line.
fn child_error(stderr: &str, code: Option<i32>) -> String {
    let lines = || stderr.lines().rev().map(str::trim).filter(|l| !l.is_empty());
    let json = lines().find_map(|l| {
        let v = moochy_node::json::parse_object(l.as_bytes()).ok()?;
        (v.get("event")?.as_str()? == "error").then(|| v.get("message")?.as_str().map(str::to_owned)).flatten()
    });
    let msg = json.or_else(|| lines().next().map(str::to_owned)).unwrap_or_else(|| match code {
        Some(c) => format!("moochy stopped with code {c}"),
        None => "moochy was stopped".into(),
    });
    clean(&msg)
}

/// JSON event lines a child printed on stdout.
fn events(stdout: &str) -> Vec<Value> {
    stdout.lines().filter_map(|l| moochy_node::json::parse_object(l.as_bytes()).ok()).map(Value::Object).map(cleaned).collect()
}

/// Every string in a value through the TUI's sanitizer: server and peer text is shown as text only.
fn cleaned(mut v: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::String(s) => *s = clean(s),
            Value::Array(a) => a.iter_mut().for_each(walk),
            Value::Object(m) => m.values_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut v);
    v
}

impl Ctx {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(&self.bin);
        c.arg("--home").arg(&self.home.dir).args(args);
        c
    }

    /// Runs `moochy --home H args…` to the end (bounded by [`CHILD`]). `key` goes to its stdin
    /// only, then is wiped.
    fn run(&self, args: &[&str], key: Option<Zeroizing<String>>) -> Out {
        let spawned = self.command(args).stdin(if key.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => return Out { ok: false, stdout: String::new(), error: format!("Could not start moochy ({e}). Reinstall the app.") },
        };
        if let (Some(k), Some(mut stdin)) = (key, child.stdin.take()) {
            let _ = stdin.write_all(k.as_bytes());
            // Dropping both closes the pipe and zeroizes the key.
        }
        let (out, err) = match (child.stdout.take(), child.stderr.take()) {
            (Some(o), Some(e)) => (read_all(o), read_all(e)),
            _ => return Out { ok: false, stdout: String::new(), error: "moochy: no output".into() },
        };
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if start.elapsed() < CHILD => std::thread::sleep(Duration::from_millis(40)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let (stdout, stderr) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
        match status {
            Some(s) if s.success() => Out { ok: true, stdout, error: String::new() },
            Some(s) => Out { ok: false, stdout, error: child_error(&stderr, s.code()) },
            None => Out { ok: false, stdout, error: "moochy did not finish in time. Check your connection and try again.".into() },
        }
    }

    fn set_web(&self, web: &str) {
        web.clone_into(&mut lock(&self.web));
    }

    fn snapshot_json(&self, s: &moochy_tui::model::Snapshot) -> Value {
        self.set_web(&s.me.web);
        cleaned(serde_json::to_value(s).unwrap_or(Value::Null))
    }

    /// The window's whole state: setup progress from the config file, and the node's snapshot
    /// when it answers (else why not, and the providers with a key, from `moochy keys list`).
    fn state(&self) -> Value {
        let cfg = self.home.load().ok().unwrap_or_default();
        let setup = json!({
            "logged_in": cfg.device_id.is_some(),
            "worker": cfg.roles.iter().any(|r| r == "worker"),
            "handle": clean(cfg.handle.as_deref().unwrap_or_default()),
            "limit_uusd": cfg.donor_safety_ack_ms.and(cfg.device_monthly_cap_uusd),
        });
        let snap = lock(&self.source).snapshot();
        match snap {
            Ok(s) => json!({"setup": setup, "snapshot": self.snapshot_json(&s), "version": env!("CARGO_PKG_VERSION")}),
            Err(e) => {
                // Never the key: `keys list` prints its last characters, only the provider is kept.
                let keys: Vec<Value> = if cfg.device_id.is_some() { events(&self.run(&["keys", "list"], None).stdout).iter().filter_map(|k| k.get("provider").cloned()).collect() } else { Vec::new() };
                json!({"setup": setup, "snapshot": null, "offline": clean(&e), "keys": keys, "version": env!("CARGO_PKG_VERSION")})
            }
        }
    }
}

type Shared<'a> = State<'a, Arc<Ctx>>;

/// Runs `f` off the async runtime: children and socket calls block (bounded).
async fn blocking<T: Send + 'static>(ctx: &Arc<Ctx>, f: impl FnOnce(&Ctx) -> Result<T, String> + Send + 'static) -> Result<T, String> {
    let c = Arc::clone(ctx);
    tauri::async_runtime::spawn_blocking(move || f(&c)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn state(ctx: Shared<'_>) -> Result<Value, String> {
    blocking(&ctx, |c| Ok(c.state())).await
}

/// The TUI's actions over the socket. Accepting a donor and organisation changes need the owner's
/// passkey: the window opens the moochy.dev page for them instead.
#[tauri::command]
async fn act(ctx: Shared<'_>, action: Action) -> Result<String, String> {
    match &action {
        Action::Accept { .. } | Action::OrgAdd { .. } | Action::OrgRemove { .. } => return Err("This needs your passkey: open it on moochy.dev.".into()),
        Action::PauseDonation(id) | Action::ResumeDonation(id) | Action::StopDonation(id) | Action::LowerDonation { id, .. } | Action::RevokeBox(id) | Action::RevokeBoxToken(id) | Action::Refuse { request_id: id, .. } => check::id(id)?,
        Action::Refresh => {}
    }
    blocking(&ctx, move |c| match lock(&c.source).act(action) {
        ActionResult::Done(m) => Ok(clean(&m)),
        ActionResult::Refused(m) => Err(clean(&m)),
        ActionResult::Terminal(_) => Err("Run this in a terminal.".into()),
    })
    .await
}

/// `moochy login --roles gateway,worker --no-browser`, streamed as `login` events: `device_code`
/// (the code and the approval link), then `logged_in`, or `error`.
#[tauri::command]
async fn login_start(app: tauri::AppHandle, ctx: Shared<'_>) -> Result<(), String> {
    let mut child = ctx.command(&["login", "--roles", "gateway,worker", "--no-browser"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("Could not start moochy ({e})."))?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else { return Err("moochy: no output".into()) };
    let generation = {
        let mut g = lock(&ctx.login);
        if let Some(mut old) = g.1.take() {
            let _ = old.kill();
            let _ = old.wait();
        }
        g.0 = g.0.wrapping_add(1);
        g.1 = Some(child);
        g.0
    };
    let ctx = Arc::clone(&ctx);
    let stderr = read_all(err);
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(out.take(MAX_OUT)).lines().map_while(Result::ok) {
            let Ok(v) = moochy_node::json::parse_object(line.as_bytes()) else { continue };
            if let Some(e @ ("device_code" | "logged_in")) = v.get("event").and_then(Value::as_str) {
                let s = |k: &str| clean(v.get(k).and_then(Value::as_str).unwrap_or_default());
                let _ = app.emit("login", json!({"event": e, "user_code": s("user_code"), "verification_url": s("verification_url")}));
            }
        }
        let child = {
            let mut g = lock(&ctx.login);
            if g.0 != generation {
                return;
            }
            g.1.take()
        };
        // None: cancelled.
        let Some(mut child) = child else { return };
        match child.wait() {
            Ok(s) if s.success() => {}
            s => {
                let msg = child_error(&stderr.join().unwrap_or_default(), s.ok().and_then(|s| s.code()));
                let _ = app.emit("login", json!({"event": "error", "message": msg}));
            }
        }
    });
    Ok(())
}

#[tauri::command]
fn login_cancel(ctx: Shared<'_>) {
    let mut g = lock(&ctx.login);
    if let Some(mut c) = g.1.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// `keys add <provider> --key-stdin`: the CLI checks the key with the provider's free models call.
#[tauri::command]
async fn add_key(ctx: Shared<'_>, provider: String, key: String) -> Result<Vec<Value>, String> {
    let key = Zeroizing::new(key);
    let p = check::provider(&provider)?;
    let k = Zeroizing::new(key.trim().to_owned());
    drop(key);
    check::key(p, &k)?;
    blocking(&ctx, move |c| c.run(&["keys", "add", p, "--key-stdin"], Some(k)).into_result().map(|o| events(&o))).await
}

/// The safety step with this computer's monthly limit, then `up`, then the login service.
#[tauri::command]
async fn set_limit(ctx: Shared<'_>, dollars: u32, start_at_login: bool) -> Result<(), String> {
    let d = check::dollars(dollars)?.to_string();
    blocking(&ctx, move |c| {
        c.run(&["safety", "--monthly-limit", &d, "--accept-safety"], None).into_result()?;
        c.run(&["up"], None).into_result()?;
        if start_at_login {
            c.run(&["service", "install"], None).into_result()?;
        } else {
            // Not installed is fine.
            let _ = c.run(&["service", "uninstall"], None);
        }
        Ok(())
    })
    .await
}

/// `donate --repo|--org|--person T --cap N --yes`.
#[tauri::command]
async fn donate(ctx: Shared<'_>, target: String, dollars: u32, kind: String) -> Result<Value, String> {
    let (flag, t) = check::target(&kind, &target)?;
    let d = check::dollars(dollars)?.to_string();
    blocking(&ctx, move |c| c.run(&["donate", flag, &t, "--cap", &d, "--yes"], None).into_result().map(|o| json!({"target": t, "events": events(&o)}))).await
}

/// `donations pause|resume|stop <id>`.
#[tauri::command]
async fn donation(ctx: Shared<'_>, op: String, id: String) -> Result<(), String> {
    let op = ["pause", "resume", "stop"].into_iter().find(|o| *o == op).ok_or("unknown donation action")?;
    check::id(&id)?;
    blocking(&ctx, move |c| c.run(&["donations", op, &id], None).into_result().map(drop)).await
}

/// Device-wide pause (`moochy pause|resume`, works offline): the Home switch.
#[tauri::command]
async fn set_paused(ctx: Shared<'_>, paused: bool) -> Result<(), String> {
    blocking(&ctx, move |c| c.run(&[if paused { "pause" } else { "resume" }], None).into_result().map(drop)).await
}

/// `connect <client> --repo P`: the setup snippet, or `--write --yes` merges it into the tool's
/// own config (never a git-tracked file).
#[tauri::command]
async fn connect(ctx: Shared<'_>, client: String, repo: String, write: bool) -> Result<String, String> {
    check::client(&client)?;
    let repo = check::project(&repo).ok_or("not a project")?;
    blocking(&ctx, move |c| {
        let mut args = vec!["connect", client.as_str(), "--repo", repo.as_str()];
        if write {
            args.extend(["--write", "--yes"]);
        }
        let o = c.run(&args, None).into_result()?;
        Ok(if write { events(&o).last().and_then(|e| e.get("path")).and_then(Value::as_str).map_or_else(|| "Already set up.".to_owned(), |p| format!("Set up in {p}")) } else { clean(&o) })
    })
    .await
}

#[tauri::command]
fn clients() -> &'static [&'static str] {
    moochy_node::connect::CLIENTS
}

/// `moochy doctor`, one line per check, failed checks included.
#[tauri::command]
async fn doctor(ctx: Shared<'_>) -> Result<Vec<check::DoctorLine>, String> {
    blocking(&ctx, |c| {
        let o = c.run(&["doctor"], None);
        let lines = check::doctor(&clean(&o.stdout));
        if lines.is_empty() { Err(o.error) } else { Ok(lines) }
    })
    .await
}

#[tauri::command]
async fn remove_key(ctx: Shared<'_>, provider: String) -> Result<(), String> {
    let p = check::provider(&provider)?;
    blocking(&ctx, move |c| c.run(&["keys", "remove", p], None).into_result().map(drop)).await
}

#[tauri::command]
async fn logout(ctx: Shared<'_>) -> Result<(), String> {
    blocking(&ctx, |c| c.run(&["logout"], None).into_result().map(drop)).await
}

/// A gift link a child printed (`gift create` or `gift revoke --replace`), with its QR code. The
/// link is shown once: it goes to the window and nowhere else (no log, no file, no event).
fn shown_once(stdout: &str, web: &str) -> Result<Value, String> {
    let g = events(stdout).into_iter().find(|e| e.get("url").is_some()).ok_or("The gift was made, but its link did not come back. Use Replace link in Your gifts.")?;
    let url = g.get("url").and_then(Value::as_str).filter(|u| check::gift_url(u, web)).ok_or("The server sent a gift link that is not on moochy.dev.")?;
    let pick = |k: &str| g.get(k).cloned().unwrap_or_default();
    Ok(json!({"gift_id": pick("gift_id"), "amount_uusd": pick("amount_uusd"), "expires_at_ms": pick("expires_at_ms"), "url": url, "svg": check::qr_svg(url)?}))
}

/// `gift create N --expires D [--note=T] --json` (plan 15 §3.2).
#[tauri::command]
async fn gift_create(ctx: Shared<'_>, dollars: u32, note: String, days: u32) -> Result<Value, String> {
    let d = check::gift_dollars(dollars)?.to_string();
    let note = check::note(&note)?;
    let days = check::days(days)?.to_string();
    blocking(&ctx, move |c| {
        let note = format!("--note={note}");
        let mut args = vec!["gift", "create", d.as_str(), "--expires", days.as_str(), "--json"];
        if note.len() > "--note=".len() {
            args.push(note.as_str());
        }
        let o = c.run(&args, None).into_result()?;
        shown_once(&o, &lock(&c.web))
    })
    .await
}

/// `gift list --json`: status, claimer and target per gift (never a link).
#[tauri::command]
async fn gift_list(ctx: Shared<'_>) -> Result<Vec<Value>, String> {
    blocking(&ctx, |c| {
        let mut v = events(&c.run(&["gift", "list", "--json"], None).into_result()?);
        v.iter_mut().filter_map(Value::as_object_mut).for_each(|g| {
            g.remove("url");
        });
        Ok(v)
    })
    .await
}

/// `gift revoke <gf_…> [--replace] --json`: with `replace`, the new link and its QR code.
#[tauri::command]
async fn gift_revoke(ctx: Shared<'_>, id: String, replace: bool) -> Result<Value, String> {
    check::gift_id(&id)?;
    blocking(&ctx, move |c| {
        let mut args = vec!["gift", "revoke", id.as_str(), "--json"];
        if replace {
            args.push("--replace");
        }
        let o = c.run(&args, None).into_result()?;
        if replace { shown_once(&o, &lock(&c.web)) } else { Ok(Value::Null) }
    })
    .await
}

/// `credits --json`, or null when credits are off on the relay (or anything else fails): the
/// window then shows nothing about credits.
#[tauri::command]
async fn credits(ctx: Shared<'_>) -> Result<Value, String> {
    blocking(&ctx, |c| Ok(c.run(&["credits", "--json"], None).into_result().ok().and_then(|o| events(&o).into_iter().next()).unwrap_or(Value::Null))).await
}

/// `button --qr --repo P`: the project's donate page and its QR code.
#[tauri::command]
async fn project_qr(ctx: Shared<'_>, repo: String) -> Result<Value, String> {
    let repo = check::project(&repo).ok_or("not a project")?;
    blocking(&ctx, move |c| {
        let o = c.run(&["button", "--qr", "--repo", &repo], None).into_result()?;
        let url = o.lines().next().and_then(|l| l.trim().strip_suffix("qr.svg")).map(|b| format!("{b}donate")).filter(|u| check::donate_url(u).is_some()).ok_or("moochy printed no donate link")?;
        Ok(json!({"svg": check::qr_svg(&url)?, "url": url}))
    })
    .await
}

/// Saves the QR code of a gift link or a donate page as an SVG file in Downloads (never over an
/// existing file) and returns where. The window cannot pick a folder: no dialog plugin (§2.2).
#[tauri::command]
fn save_qr(app: tauri::AppHandle, ctx: Shared<'_>, url: String) -> Result<String, String> {
    let name = if check::gift_url(&url, &lock(&ctx.web)) {
        "gift".to_owned()
    } else {
        check::donate_url(&url).ok_or("not a Moochy link")?.trim_end_matches("/-").replace('/', "-")
    };
    let svg = check::qr_svg(&url)?;
    let dir = app.path().download_dir().map_err(|_| "No Downloads folder on this computer.".to_owned())?;
    for n in 1..100 {
        let path = dir.join(if n == 1 { format!("moochy-{name}.svg") } else { format!("moochy-{name}-{n}.svg") });
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => return f.write_all(svg.as_bytes()).map(|()| path.display().to_string()).map_err(|e| format!("Could not save the file ({e}).")),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("Could not save the file ({e}).")),
        }
    }
    Err("Downloads has too many Moochy QR files: remove some first.".into())
}

/// Opens `url` in the system browser, only on moochy.dev (or the snapshot's web origin).
#[tauri::command]
fn open_web(ctx: Shared<'_>, url: String) -> Result<(), String> {
    check::web_url(&url, &lock(&ctx.web))?;
    let prog = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    let mut child = Command::new(prog).arg(&url).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|_| "Could not open the browser.".to_owned())?;
    std::thread::spawn(move || child.wait());
    Ok(())
}

/// `--home DIR` (or `--home=DIR`) as the CLI takes it; else `MOOCHY_HOME`, else the default.
fn home_flag() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        if a == "--home" {
            return args.next().map(PathBuf::from);
        }
        if let Some(d) = a.to_str().and_then(|s| s.strip_prefix("--home=")) {
            return Some(PathBuf::from(d));
        }
    }
    None
}

/// The `moochy` bundled beside the app (`exe`). A release build refuses to run without it: a
/// `moochy` found on PATH is whatever anyone who can write a PATH directory put there. Only a
/// debug build (`debug`) falls back to PATH, for development.
fn sidecar(exe: Option<PathBuf>, debug: bool) -> Option<PathBuf> {
    exe.and_then(|e| Some(e.parent()?.join("moochy"))).filter(|p| p.is_file()).or_else(|| debug.then(|| PathBuf::from("moochy")))
}

fn window_file(home: &Home) -> PathBuf {
    home.dir.join("desktop-window")
}

fn main() {
    let home = match Home::resolve(home_flag()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("moochy-desktop: {}", clean(&e.msg));
            std::process::exit(2);
        }
    };
    let source = match NodeSource::new(home.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("moochy-desktop: {}", clean(&e));
            std::process::exit(10);
        }
    };
    let Some(bin) = sidecar(std::env::current_exe().ok(), cfg!(debug_assertions)) else {
        eprintln!("moochy-desktop: the bundled moochy binary is missing; reinstall the app.");
        std::process::exit(10);
    };
    let live = source.events();
    let ctx = Arc::new(Ctx { bin, home, source: Mutex::new(source), web: Mutex::new(String::new()), login: Mutex::new((0, None)) });
    let built = tauri::Builder::default()
        .manage(Arc::clone(&ctx))
        .setup(move |app| {
            // Live updates: one event per snapshot, toast or lost connection.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                for ev in live {
                    let _ = match ev {
                        SourceEvent::Snapshot(s) => handle.emit("snapshot", ctx.snapshot_json(&s)),
                        SourceEvent::Toast(t) => handle.emit("toast", clean(&t)),
                        SourceEvent::Disconnected(e) => handle.emit("offline", clean(&e)),
                    };
                }
            });
            // The size the window had when it was last closed.
            if let Some(w) = app.get_webview_window("main")
                && let Some((width, height)) = std::fs::read_to_string(window_file(&app.state::<Arc<Ctx>>().home)).ok().and_then(|s| {
                    let (a, b) = s.trim().split_once(' ')?;
                    Some((a.parse::<f64>().ok()?, b.parse::<f64>().ok()?))
                })
                && (360.0..=4000.0).contains(&width)
                && (520.0..=4000.0).contains(&height)
            {
                let _ = w.set_size(tauri::LogicalSize::new(width, height));
            }
            Ok(())
        })
        .on_window_event(|w, e| {
            if let tauri::WindowEvent::CloseRequested { .. } = e
                && let (Ok(size), Ok(scale)) = (w.inner_size(), w.scale_factor())
            {
                let s = size.to_logical::<f64>(scale);
                let _ = std::fs::write(window_file(&w.state::<Arc<Ctx>>().home), format!("{:.0} {:.0}\n", s.width, s.height));
            }
        })
        .invoke_handler(tauri::generate_handler![state, act, login_start, login_cancel, add_key, set_limit, donate, donation, set_paused, connect, clients, doctor, remove_key, logout, open_web, gift_create, gift_list, gift_revoke, credits, project_qr, save_qr])
        .run(tauri::generate_context!());
    if let Err(e) = built {
        eprintln!("moochy-desktop: {e}");
        std::process::exit(10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_json_shape() {
        let mut src = moochy_tui::demo_source();
        let v = cleaned(serde_json::to_value(src.snapshot().unwrap()).unwrap());
        // The fields app.js reads.
        assert!(v["me"]["handle"].is_string() && v["me"]["web"].is_string());
        assert_eq!(v["me"]["paused"], false);
        assert_eq!(v["me"]["lockdown"]["state"], "enforced");
        let d = &v["donations"][0];
        for k in ["id", "target", "status", "budget_uusd", "spent_uusd", "models", "renews_at_ms"] {
            assert!(!d[k].is_null(), "donation.{k}");
        }
        assert!(d["budget_uusd"].is_u64());
        let s = &v["served"][0];
        for k in ["at_ms", "direction", "project", "model", "tokens_in", "tokens_out", "cost_uusd"] {
            assert!(!s[k].is_null(), "served.{k}");
        }
        for k in ["projects", "pending", "keys", "alerts", "devices"] {
            assert!(v[k].is_array(), "{k}");
        }
        assert!(v["config"][0].as_array().is_some_and(|p| p.len() == 2), "config is [key, value] pairs");
    }

    #[test]
    fn hostile_strings_are_inert() {
        let mut src = moochy_tui::fixtures::hostile();
        let text = serde_json::to_string(&cleaned(serde_json::to_value(src.snapshot().unwrap()).unwrap())).unwrap();
        assert!(!text.contains('\u{1b}') && !text.contains('\u{202E}'), "escape sequences and bidi overrides are gone");
    }

    #[test]
    fn gift_link_once() {
        let url = "https://moochy.dev/g/AbCdEfGhIjKlMnOpQrSt_-";
        let v = shown_once(&format!("{{\"gift_id\":\"gf_1\",\"amount_uusd\":20000000,\"expires_at_ms\":1,\"url\":\"{url}\"}}\n"), "").unwrap();
        assert_eq!(v["url"], url);
        assert_eq!(v["amount_uusd"], 20_000_000);
        assert!(v["svg"].as_str().unwrap().contains("<svg"));
        assert!(shown_once("{\"url\":\"https://evil.com/g/AbCdEfGhIjKlMnOpQrSt_-\"}", "").is_err());
        assert!(shown_once("{\"gift_id\":\"gf_1\"}", "").is_err());
    }

    #[test]
    fn sidecar_never_from_path_in_release() {
        let dir = std::env::temp_dir().join(format!("moochy-desktop-sidecar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("moochy-desktop");
        assert_eq!(sidecar(Some(exe.clone()), false), None, "release: no bundled moochy, no fallback");
        assert_eq!(sidecar(Some(exe.clone()), true), Some(PathBuf::from("moochy")), "debug: PATH");
        std::fs::write(dir.join("moochy"), "").unwrap();
        assert_eq!(sidecar(Some(exe), false), Some(dir.join("moochy")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn child_errors() {
        assert_eq!(child_error("Warning: x\n{\"event\":\"error\",\"code\":\"auth\",\"message\":\"the key was refused\"}\n", Some(3)), "the key was refused");
        assert_eq!(child_error("plain words\n", Some(2)), "plain words");
        assert_eq!(child_error("", Some(4)), "moochy stopped with code 4");
        assert_eq!(child_error("", None), "moochy was stopped");
        assert_eq!(events("{\"event\":\"key_added\",\"provider\":\"xai\"}\nnot json\n").len(), 1);
    }
}
