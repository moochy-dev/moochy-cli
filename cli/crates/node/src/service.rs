//! `moochy service install|uninstall` (07 §2, §8.1 step 6): run the node at login/boot.
//!
//! Linux: a systemd user unit (`--system`: a system unit for this user, needs root), with the
//! platform hardening of CONTRACT §15.2 on top of the node's own lockdown. macOS: a launchd
//! LaunchAgent. `--print` shows the unit and changes nothing.
//! ponytail: generated here until mo-ops ships the reviewed units in `deploy/client`; then
//! these templates are replaced by those files, same paths and names.

use crate::config::Home;
use crate::util::{Ctx as _, Result, emit, internal, usage};
use serde_json::json;
use std::path::{Path, PathBuf};

const UNIT: &str = "moochy.service";
const LABEL: &str = "dev.moochy.node";

/// systemd unit for `moochy --home <home> up --foreground`.
pub fn systemd_unit(exe: &Path, home: &Path, system_user: Option<&str>) -> String {
    let (exe, home) = (exe.display(), home.display());
    let user = system_user.map(|u| format!("User={u}\n")).unwrap_or_default();
    let wanted = if system_user.is_some() { "multi-user.target" } else { "default.target" };
    // A user manager cannot drop capabilities: these need the system manager.
    let system_only = if system_user.is_some() {
        "PrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\nProtectClock=yes\nProtectHostname=yes\n"
    } else {
        ""
    };
    format!(
        "[Unit]
Description=Moochy (donate and use donated tokens)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
{user}ExecStart={exe} --home {home} up --foreground
Restart=on-failure
RestartSec=5
# CONTRACT §15.2: platform hardening on top of the node's own lockdown (seccomp, Landlock).
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={home}
PrivateTmp=yes
{system_only}RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
# @sandbox: the node's own lockdown (landlock_*, seccomp) runs inside the unit.
SystemCallFilter=@system-service @sandbox
SystemCallFilter=~@privileged @mount @debug @module @reboot @swap @raw-io @cpu-emulation @obsolete
UMask=0077

[Install]
WantedBy={wanted}
"
    )
}

/// launchd LaunchAgent plist (paths XML-escaped).
pub fn launchd_plist(exe: &Path, home: &Path) -> String {
    let esc = |p: &Path| p.display().to_string().replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let (exe, home) = (esc(exe), esc(home));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{exe}</string><string>--home</string><string>{home}</string><string>up</string><string>--foreground</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>{home}/state/node.log</string>
</dict>
</plist>
"#
    )
}

fn unit_path(system: bool) -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        let h = std::env::var_os("HOME").ok_or_else(|| internal("HOME is not set"))?;
        return Ok(Path::new(&h).join("Library/LaunchAgents").join(format!("{LABEL}.plist")));
    }
    if system {
        return Ok(Path::new("/etc/systemd/system").join(UNIT));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))
        .ok_or_else(|| internal("HOME is not set"))?;
    Ok(base.join("systemd/user").join(UNIT))
}

fn run(prog: &str, args: &[&str]) -> Result<()> {
    let st = crate::util::command(prog).args(args).status().map_err(|e| internal(format!("{prog}: {e}")))?;
    if st.success() { Ok(()) } else { Err(internal(format!("`{prog} {}` failed ({st})", args.join(" ")))) }
}

/// `moochy service install [--system] [--print]`.
pub fn install(home: &Home, system: bool, print: bool) -> Result<()> {
    let exe = std::env::current_exe().ctx("current exe")?;
    let dir = std::fs::canonicalize(&home.dir).unwrap_or_else(|_| home.dir.clone());
    let user = std::env::var("USER").ok();
    if system && user.as_deref().is_none_or(|u| u.is_empty() || u == "root") {
        return Err(usage("--system runs the node as your user: run it with sudo -E from your account (USER must be set)"));
    }
    let text = if cfg!(target_os = "macos") { launchd_plist(&exe, &dir) } else { systemd_unit(&exe, &dir, system.then_some(user.as_deref().unwrap_or_default())) };
    if print {
        print!("{text}");
        return Ok(());
    }
    let path = unit_path(system)?;
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).ctx("create unit dir")?;
    }
    std::fs::write(&path, text).ctx("write unit")?;
    if cfg!(target_os = "macos") {
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).ctx("home")?);
        let p = path.to_string_lossy().into_owned();
        let _ = run("launchctl", &["bootout", &format!("gui/{uid}"), &p]);
        run("launchctl", &["bootstrap", &format!("gui/{uid}"), &p])?;
    } else {
        let scope: &[&str] = if system { &[] } else { &["--user"] };
        run("systemctl", &[scope, &["daemon-reload"]].concat())?;
        run("systemctl", &[scope, &["enable", "--now", UNIT]].concat())?;
    }
    emit(&json!({"event": "service_installed", "unit": path.display().to_string()}));
    Ok(())
}

/// `moochy service uninstall [--system]`.
pub fn uninstall(system: bool) -> Result<()> {
    let path = unit_path(system)?;
    if cfg!(target_os = "macos") {
        if let Some(h) = std::env::var_os("HOME") {
            let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(h).ctx("home")?);
            let _ = run("launchctl", &["bootout", &format!("gui/{uid}"), &path.to_string_lossy()]);
        }
    } else {
        let scope: &[&str] = if system { &[] } else { &["--user"] };
        let _ = run("systemctl", &[scope, &["disable", "--now", UNIT]].concat());
    }
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(internal(format!("remove {}: {e}", path.display()))),
    }
    if !cfg!(target_os = "macos") {
        let scope: &[&str] = if system { &[] } else { &["--user"] };
        let _ = run("systemctl", &[scope, &["daemon-reload"]].concat());
    }
    emit(&json!({"event": "service_uninstalled", "unit": path.display().to_string()}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        let u = systemd_unit(Path::new("/usr/local/bin/moochy"), Path::new("/home/a/.moochy"), None);
        assert!(u.contains("ExecStart=/usr/local/bin/moochy --home /home/a/.moochy up --foreground"));
        for k in ["NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only", "ReadWritePaths=/home/a/.moochy", "SystemCallFilter=@system-service @sandbox", "WantedBy=default.target"] {
            assert!(u.contains(k), "{k}");
        }
        assert!(!u.contains("User="));
        assert!(!u.contains("ProtectKernelModules"), "capability-dropping directives fail in a user manager");
        let sys = systemd_unit(Path::new("/m"), Path::new("/h"), Some("ann"));
        assert!(sys.contains("User=ann\n") && sys.contains("ProtectKernelModules=yes") && sys.contains("WantedBy=multi-user.target"));
        let p = launchd_plist(Path::new("/Applications/M&M/moochy"), Path::new("/Users/a/.moochy"));
        assert!(p.contains("<string>/Applications/M&amp;M/moochy</string>") && p.contains(LABEL));
    }
}
