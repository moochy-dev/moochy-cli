//! Background-process lockdown (CONTRACT §15.2) on `moochy-sandbox`.
//!
//! `moochy up --foreground` loads its config and keystore and binds the gateway port on the main
//! thread, locks itself down (`lockdown_self`: no exec, no ptrace/mount/bpf/…, filesystem limited
//! to the state dir plus a few read-only files, TCP connect limited to 443 and the relay port),
//! and only then starts the async runtime. Locking while still single-threaded covers every later
//! thread on any Landlock ABI (TSYNC needs ABI ≥ 8). Fails closed: if the lockdown cannot be
//! applied the node refuses to start, unless `--unsafe-no-lockdown` (loud, debugging only).

use crate::config::{Config, Home};
use crate::keystore::{self, Secrets};
use crate::util::{Ctx as _, Result, auth, internal, log, usage};
use serde_json::json;
use std::path::PathBuf;

/// Everything `up` needs from the filesystem and the network setup, loaded before the lockdown.
pub struct Boot {
    pub cfg: Config,
    pub secrets: Secrets,
    pub listener: std::net::TcpListener,
    /// Worker role: the key-less validator zygote, exec'd before the lockdown (§15.2).
    pub validator: Option<std::sync::Arc<crate::validator::Pool>>,
    /// Set by [`apply`]: the process is locked down.
    pub locked: bool,
}

impl Boot {
    pub fn load(home: &Home, offline: bool) -> Result<Self> {
        home.ensure()?;
        let mut cfg = home.load()?;
        let secrets = if offline {
            keystore::load_or_init(home, &mut cfg)?
        } else {
            let s = keystore::load(home, &cfg)?.ok_or_else(|| auth("no keystore: run `moochy login` first"))?;
            if cfg.device_id.is_none() || s.device.is_none() || cfg.relay.is_none() {
                return Err(auth("not logged in: run `moochy login` first"));
            }
            s
        };
        // CONTRACT §6: trust comes from the key log, never from the relay's word. Without a key
        // (compiled in for the default relay, or `--log-key`) only insecure dev mode may start.
        if !offline && crate::keylog::effective_log_key(&cfg).is_none() && std::env::var("MOOCHY_INSECURE_DEV").as_deref() != Ok("1") {
            return Err(usage("no key-log key for this server: `moochy login --log-key <vkey>` or `moochy config set log_key <vkey>`"));
        }
        let addr = cfg.gateway_addr()?;
        let listener = std::net::TcpListener::bind(addr).map_err(|e| usage(format!("bind {addr}: {e}")))?;
        listener.set_nonblocking(true).ctx("gateway listener")?;
        let port = listener.local_addr().ctx("local addr")?.port();
        if cfg.gateway_addr.is_none() {
            // First start: keep this port so clients keep a stable base URL (CONTRACT §6).
            cfg.gateway_addr = Some(format!("127.0.0.1:{port}"));
            home.save(&cfg)?;
        }
        let validator = if cfg.has_role("worker") && !offline && secrets.device.is_some() {
            let v = crate::validator::Pool::spawn().ctx("start the request validator")?;
            v.fill();
            Some(std::sync::Arc::new(v))
        } else {
            None
        };
        Ok(Self { cfg, secrets, listener, validator, locked: false })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().map_or(0, |a| a.port())
    }
}

/// Read-only after the lockdown: the binary, config + keystore (re-read by nothing hot, kept
/// for diagnostics), the relay CA file (read at every reconnect), name resolution (glibc NSS
/// reads `/etc` files and loads its modules lazily) and the CA roots `moochy-sandbox` adds.
fn ro_paths(home: &Home, cfg: &Config) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/host.conf", "/etc/gai.conf", "/lib", "/lib64", "/usr/lib", "/usr/lib64", "/run/systemd/resolve"]
        .iter()
        .map(PathBuf::from)
        .collect();
    v.extend(std::env::current_exe().ok());
    v.push(home.config_path());
    v.push(home.keystore_path(cfg.relay.as_deref()));
    v.extend(cfg.ca_file.clone());
    v.retain(|p| p.exists());
    v
}

/// TCP ports the provider origins need besides 443 (a local model server, a dev override):
/// the explicit port, else the scheme's default (80 for `http://`). A222: `http://host` without
/// a port is port 80, not "no port".
fn provider_ports(secrets: &Secrets) -> Vec<u16> {
    secrets.providers.iter().filter_map(|p| p.base_url.as_deref()).filter_map(origin_port).filter(|p| *p != 443).collect()
}

fn origin_port(url: &str) -> Option<u16> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // `[v6]:port`, `host:port`, or no port.
    let port = match host_port.rsplit_once(']') {
        Some((_, tail)) => tail.strip_prefix(':'),
        None => host_port.rsplit_once(':').map(|(_, p)| p),
    };
    match port {
        Some(p) => p.parse().ok(),
        None => match scheme {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        },
    }
}

pub fn apply(home: &Home, boot: &mut Boot, unsafe_no_lockdown: bool) -> Result<()> {
    let relay_port = match boot.cfg.relay.as_deref() {
        Some(r) => crate::tls::Origin::parse(r)?.port,
        None => 0,
    };
    let mut p = moochy_sandbox::DonorPolicy::new(home.state_dir(), relay_port);
    p.ro_paths.extend(ro_paths(home, &boot.cfg));
    p.gateway_port = Some(boot.port());
    p.unsafe_no_lockdown = unsafe_no_lockdown;
    // Provider origins on other ports than 443: a local model server (`keys add local`) and
    // development overrides (`keys add --base-url`, MOOCHY_INSECURE_DEV only).
    p.connect_ports = provider_ports(&boot.secrets);
    let r = lockdown_self(&p).map_err(|e| internal(format!("cannot lock the background process down ({e}); run `moochy doctor`, or `moochy up --unsafe-no-lockdown` for debugging only")))?;
    boot.locked = !unsafe_no_lockdown;
    // A223: Landlock network rules exist from ABI 4, socket/signal scoping from ABI 6; read the
    // ABI rather than "fully enforced" (never true below the newest ABI, which made every
    // current kernel look unprotected and hid real losses).
    let landlock_net = r.landlock_fs && r.abi >= 4;
    let landlock_scope = r.landlock_fs && r.abi >= 6;
    let rep = json!({
        "locked": !unsafe_no_lockdown,
        "landlock_scope": landlock_scope,
        "no_new_privs": r.no_new_privs,
        "seccomp": r.seccomp,
        "landlock_fs": r.landlock_fs,
        "landlock_net": landlock_net,
        "landlock_abi": r.abi,
        "all_threads": r.all_threads,
    });
    log(if unsafe_no_lockdown { "error" } else { "info" }, if unsafe_no_lockdown { "UNSAFE: background process NOT locked down (--unsafe-no-lockdown)" } else { "background process locked down" }, &rep);
    if !unsafe_no_lockdown && !landlock_net {
        log("warn", "kernel without Landlock network rules (ABI < 4): outbound connections are not limited by moochy; use the systemd unit's RestrictAddressFamilies", &json!({"landlock_abi": r.abi}));
    }
    if !unsafe_no_lockdown && !landlock_scope {
        log("warn", "kernel without Landlock scoping (ABI < 6): abstract Unix sockets and signals are not confined by moochy", &json!({"landlock_abi": r.abi}));
    }
    record(home, &rep);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lockdown_self(p: &moochy_sandbox::DonorPolicy) -> std::result::Result<moochy_sandbox::LockdownReport, moochy_sandbox::Error> {
    moochy_sandbox::lockdown_self(p)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn lockdown_self(p: &moochy_sandbox::DonorPolicy) -> std::result::Result<moochy_sandbox::LockdownReport, moochy_sandbox::Error> {
    if p.unsafe_no_lockdown {
        return Ok(moochy_sandbox::LockdownReport::default());
    }
    Err(moochy_sandbox::Error::Unsupported("no process lockdown on this OS yet"))
}

/// `<state>/lockdown.json`: what the running node achieved, for `moochy doctor`.
fn record(home: &Home, v: &serde_json::Value) {
    let _ = crate::config::write_private(&home.state_dir().join("lockdown.json"), v.to_string().as_bytes());
}

/// `moochy doctor` lines: `(ok, what, detail)`.
pub fn doctor(home: &Home, running: bool) -> Vec<(bool, &'static str, String)> {
    let mut out = Vec::new();
    let rec = std::fs::read(home.state_dir().join("lockdown.json")).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let f = |r: &serde_json::Value, k: &str| r.get(k).cloned().unwrap_or(serde_json::Value::Null);
    match rec.filter(|_| running) {
        Some(r) if f(&r, "locked") == true => out.push((
            true,
            "lockdown",
            format!(
                "background process locked: seccomp {}, no_new_privs {}, Landlock fs {}, net {}, ABI {}",
                f(&r, "seccomp"),
                f(&r, "no_new_privs"),
                f(&r, "landlock_fs"),
                f(&r, "landlock_net"),
                f(&r, "landlock_abi")
            ),
        )),
        Some(r) => {
            let reason = f(&r, "reason").as_str().unwrap_or("--unsafe-no-lockdown").to_owned();
            // Only the debug flag is a failure; the other skips are known, logged gaps.
            out.push((reason != "--unsafe-no-lockdown", "lockdown", format!("background process not locked down ({reason})")));
        }
        None => out.push((true, "lockdown", "checked when the app starts (`moochy up` refuses to serve without it)".into())),
    }
    host_support(&mut out);
    out
}

#[cfg(target_os = "linux")]
fn host_support(out: &mut Vec<(bool, &'static str, String)>) {
    let read = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_owned());
    let lsm = read("/sys/kernel/security/lsm").unwrap_or_default();
    out.push((lsm.split(',').any(|l| l == "landlock"), "landlock", if lsm.is_empty() { "unknown (no /sys/kernel/security/lsm)".into() } else { format!("active LSMs: {lsm}") }));
    let seccomp = read("/proc/self/status").is_some_and(|s| s.lines().any(|l| l.starts_with("Seccomp:")));
    out.push((seccomp, "seccomp", if seccomp { "available".into() } else { "not available in this kernel".into() }));
}

#[cfg(target_os = "macos")]
fn host_support(out: &mut Vec<(bool, &'static str, String)>) {
    out.push((true, "seatbelt", "sandbox_init (Seatbelt) is built into macOS".into()));
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn host_support(out: &mut Vec<(bool, &'static str, String)>) {
    out.push((false, "sandbox", "no process lockdown on this OS yet".into()));
}

#[cfg(test)]
mod tests {
    #[test]
    fn origin_ports() {
        use super::origin_port;
        assert_eq!(origin_port("http://127.0.0.1:11434"), Some(11434));
        assert_eq!(origin_port("http://192.168.1.5"), Some(80));
        assert_eq!(origin_port("http://192.168.1.5/"), Some(80));
        assert_eq!(origin_port("https://gpu.lan"), Some(443));
        assert_eq!(origin_port("http://[::1]:8080"), Some(8080));
        assert_eq!(origin_port("http://[fd00::1]"), Some(80));
        assert_eq!(origin_port("ftp://x"), None);
    }
}
