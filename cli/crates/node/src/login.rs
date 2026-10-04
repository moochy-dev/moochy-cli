//! Device login (06 §4.1) over the `DeviceStart` / `DevicePoll` RPCs.

use crate::config::Home;
use crate::keystore::{self, DeviceKeys};
use crate::link;
use crate::pb::link::{DevicePollRequest, DeviceStartRequest, DeviceState};
use crate::tls::Origin;
use crate::util::{Result, auth, clean, emit, net, now_ms, usage};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use tonic::Code;

pub const SUITE: &str = "moochy.v1.hpke.x25519-sha256-chacha20poly1305";
const MAX_WAIT_MS: u64 = 15 * 60 * 1000;

fn status_err(s: &tonic::Status) -> crate::util::Error {
    let m = format!("relay: {:?}: {}", s.code(), clean(s.message()));
    match s.code() {
        Code::Unauthenticated | Code::PermissionDenied => auth(m),
        Code::InvalidArgument | Code::FailedPrecondition => usage(m),
        _ => net(m),
    }
}

/// Default device name: hostname, reduced to `[a-z0-9-]`, ≤ 32 chars.
pub fn default_name() -> String {
    let h = std::env::var("MOOCHY_DEVICE_NAME").ok().or_else(|| std::fs::read_to_string("/etc/hostname").ok()).unwrap_or_default();
    let n: String = h.trim().to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).take(32).collect();
    let n = n.trim_matches('-').to_owned();
    if n.is_empty() { "moochy-node".into() } else { n }
}

/// `enroll`: a cloud-box enrollment token (CONTRACT §17.1, `MOOCHY_ENROLL`): the relay approves
/// without a browser and the device is saved as a box bound to this machine.
/// `browse`: try to open the approval page in a browser (`--no-browser` / `--headless` turn it off).
pub async fn login(home: &Home, relay: &str, ca_file: Option<PathBuf>, roles: Vec<String>, name: String, enroll: Option<&str>, browse: bool) -> Result<()> {
    let origin = Origin::parse(relay)?;
    // Box: gateway only; the machine-id hint is recorded with it.
    let box_fp = enroll.map(|_| crate::boxes::fingerprint());
    if enroll.is_some() && roles != ["gateway"] {
        return Err(usage("a box enrolls as a gateway device only"));
    }
    if roles.is_empty() || roles.iter().any(|r| r != "gateway" && r != "worker") {
        return Err(usage("--roles must be gateway, worker or gateway,worker"));
    }
    let ca_file = ca_file.map(|p| std::fs::canonicalize(&p).map_err(|e| usage(format!("--ca-file {}: {e}", p.display())))).transpose()?;
    let mut cfg = home.load()?;
    // Per-origin keystore (A135): select it before touching any secret.
    cfg.relay = Some(origin.url());
    let mut secrets = keystore::load_or_init(home, &mut cfg)?;
    let keys = DeviceKeys::generate()?;
    let (sign_pub, enc_pub) = (keys.sign_pub(), keys.enc_pub()?);
    let roles_csv = roles.join(",");
    let msg = moochy_proto::crypto::device_start_msg(&sign_pub, &enc_pub, &roles_csv, &name, SUITE).map_err(|_| usage("device start message"))?;
    let sig = keys.sign(&msg);

    let (ch, _) = link::dial(ca_file.as_deref(), &origin).await?;
    let mut client = link::client(ch);
    let start = DeviceStartRequest {
        sign_pub: bytes::Bytes::copy_from_slice(&sign_pub),
        enc_pub: bytes::Bytes::copy_from_slice(&enc_pub),
        roles: link::roles(&roles),
        name,
        suite: SUITE.into(),
        sig: bytes::Bytes::copy_from_slice(&sig),
        // Key-log proof of possession that goes into KEY_ADDED (CONTRACT R8, spec/KEYLOG.md).
        pop_sig: bytes::Bytes::copy_from_slice(&keys.sign(&moochy_keylog::entry::pop_message(&sign_pub, &enc_pub, SUITE))),
        enroll_token: enroll.unwrap_or_default().to_owned(),
    };
    let r = tokio::time::timeout(crate::tls::IO_TIMEOUT, client.device_start(start))
        .await
        .map_err(|_| net("relay timeout"))?
        .map_err(|s| status_err(&s))?
        .into_inner();
    let code_ok = (enroll.is_some() || !r.user_code.is_empty()) && r.user_code.len() <= 16 && r.user_code.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-');
    if !code_ok || r.device_code.is_empty() || r.device_code.len() > 256 {
        return Err(net("relay sent a malformed device code"));
    }
    if enroll.is_none() {
        show_code(&origin, &r.user_code, browse);
    }

    let interval = Duration::from_millis(u64::from(r.poll_interval_ms).clamp(200, 5000));
    let deadline = u64::try_from(r.expires_at_ms).ok().filter(|t| *t > now_ms()).unwrap_or_else(|| now_ms().saturating_add(MAX_WAIT_MS)).min(now_ms().saturating_add(MAX_WAIT_MS));
    let mut failures = 0u32;
    let device_id = loop {
        tokio::time::sleep(interval).await;
        if now_ms() > deadline {
            return Err(auth("device code expired before approval"));
        }
        let req = DevicePollRequest { device_code: r.device_code.clone() };
        let res = tokio::time::timeout(crate::tls::IO_TIMEOUT, client.device_poll(req)).await;
        let p = match res {
            Ok(Ok(p)) => p.into_inner(),
            Ok(Err(s)) if matches!(s.code(), Code::Unauthenticated | Code::PermissionDenied | Code::InvalidArgument) => return Err(status_err(&s)),
            _ => {
                // Transient: redial (the channel is single-use) and retry a few times.
                failures = failures.saturating_add(1);
                if failures > 5 {
                    return Err(net("relay unreachable while waiting for approval"));
                }
                if let Ok((ch, _)) = link::dial(ca_file.as_deref(), &origin).await {
                    client = link::client(ch);
                }
                continue;
            }
        };
        match DeviceState::try_from(p.state) {
            Ok(DeviceState::Approved) => {
                if moochy_keylog::entry::is_pseudonym(&p.user_pseudonym) {
                    cfg.pseudonym = Some(p.user_pseudonym.clone());
                }
                cfg.box_device = box_fp.map(|fp| crate::boxes::bind(&p, fp)).transpose()?;
                break p.device_id;
            }
            Ok(DeviceState::Denied) => return Err(auth("device approval denied")),
            Ok(DeviceState::Expired) => return Err(auth("device code expired")),
            _ => {}
        }
    };
    let id_ok = device_id.starts_with("d_") && crate::util::ulid_bytes(device_id.get(2..).unwrap_or("")).is_some();
    if !id_ok {
        return Err(net("relay sent a malformed device id"));
    }
    secrets.device = Some(keys);
    keystore::save(home, &cfg, &secrets)?;
    cfg.relay = Some(origin.url());
    cfg.ca_file = ca_file;
    cfg.roles = roles;
    cfg.device_id = Some(device_id.clone());
    home.save(&cfg)?;
    match &cfg.box_device {
        Some(b) => emit(&json!({"event": "box_enrolled", "device_id": device_id, "repo": b.repo, "expires_at_ms": b.expires_at_ms, "monthly_limit": crate::util::fmt_dollars(u64::try_from(b.cap_uusd_month).unwrap_or(0))})),
        None => emit(&json!({"event": "logged_in", "device_id": device_id})),
    }
    if enroll.is_none() {
        let p = crate::style::err();
        eprintln!("{}{} {}", p.mark(true), p.ok("This device is added:"), p.bold(&device_id));
    }
    Ok(())
}

/// The `device_code` event (stdout) and, for people, the code and the approval link (stderr).
fn show_code(origin: &Origin, user_code: &str, browse: bool) {
    let url = origin.device_url(user_code);
    emit(&json!({"event": "device_code", "user_code": user_code, "verification_url": url}));
    let p = crate::style::err();
    let url_shown = clean(&url);
    eprintln!("\n{}\n\n  code  {}\n  link  {}\n", p.bold("Add this device to Moochy"), p.bold(&p.hi(user_code)), p.link(&url_shown));
    let opened = browse && should_open(p.tty, |k| std::env::var_os(k).is_some_and(|v| !v.is_empty())) && open_browser(&url);
    let how = if opened { "Your browser is open: sign in and confirm the code." } else { "Open the link, sign in to Moochy and confirm the code." };
    eprintln!("{}\n{}", p.dim(how), p.dim("Waiting for approval (Ctrl-C to stop)…"));
}

/// Open a browser only where one can show up: a terminal, not over SSH, and on Linux a display.
fn should_open(tty: bool, set: impl Fn(&str) -> bool) -> bool {
    tty && !set("SSH_CONNECTION") && !set("SSH_TTY") && (cfg!(target_os = "macos") || set("DISPLAY") || set("WAYLAND_DISPLAY"))
}

/// Best effort: `open` (macOS) / `xdg-open`, detached, never an error. Runs in the `login`
/// process, which is never locked down (only `up --foreground` applies the lockdown).
fn open_browser(url: &str) -> bool {
    let prog = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    let child = crate::util::command(prog).arg(url).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
    match child {
        Ok(mut c) => {
            // Reap it without blocking the poll loop (xdg-open may wait for the browser).
            std::thread::spawn(move || c.wait());
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::should_open;

    #[test]
    fn browser_only_where_it_can_show() {
        let env = |vars: &'static [&'static str]| move |k: &str| vars.contains(&k);
        assert!(!should_open(false, env(&["DISPLAY"])), "not a terminal");
        assert!(!should_open(true, env(&["DISPLAY", "SSH_CONNECTION"])), "over SSH");
        assert!(should_open(true, env(&["DISPLAY"])));
        assert!(should_open(true, env(&["WAYLAND_DISPLAY"])));
        assert_eq!(should_open(true, env(&[])), cfg!(target_os = "macos"), "Linux without a display");
    }
}
