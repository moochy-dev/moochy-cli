//! `moochy service install|uninstall` (07 §2, §8.1 step 6): run the node at login/boot.
//!
//! The units are mo-ops's reviewed files in `deploy/client/service` (CONTRACT §15.2 platform
//! hardening on top of the node's own lockdown), embedded at build time. Only these are
//! substituted: the binary path, `--home` when it is not the default, `@sandbox` added to the
//! syscall filter, and an optional 0600 `<home>/service.env`. `--print` shows the unit and changes
//! nothing. Linux: systemd user unit (`--system`: the system unit, user `moochy`, state in
//! `/var/lib/moochy`, needs root). macOS: launchd agent.

use crate::config::Home;
use crate::util::{Ctx as _, Result, emit, internal, usage};
use serde_json::json;
use std::path::{Path, PathBuf};

const USER_UNIT: &str = include_str!("../assets/service/moochy.user.service");
const SYSTEM_UNIT: &str = include_str!("../assets/service/moochy.system.service");
const AGENT_PLIST: &str = include_str!("../assets/service/dev.moochy.agent.plist");
const UNIT: &str = "moochy.service";
const LABEL: &str = "dev.moochy.agent";

/// Paths are written into unit files and an `sh -c` line: plain characters only.
fn plain_path(p: &Path) -> Result<String> {
    let s = p.to_str().ok_or_else(|| usage("the path is not UTF-8"))?;
    if s.is_empty() || !s.starts_with('/') || !s.bytes().all(|c| c.is_ascii_alphanumeric() || b"/._-+@".contains(&c)) {
        return Err(usage(format!("{s}: install the unit by hand (deploy/client/service): this path has characters a unit file cannot carry")));
    }
    Ok(s.to_owned())
}

fn need(text: &str, part: &str) -> Result<()> {
    if text.contains(part) { Ok(()) } else { Err(internal(format!("the bundled unit changed shape (no `{part}`): update service.rs"))) }
}

/// Shared syscall-filter edit: the node's lockdown needs `@sandbox` (landlock_*, seccomp).
fn with_sandbox(unit: &str) -> Result<String> {
    let from = "SystemCallFilter=@system-service ";
    need(unit, from)?;
    Ok(unit.replacen(from, "SystemCallFilter=@system-service @sandbox ", 1))
}

/// The user unit for `exe` (and `home` when it is not the default).
pub fn user_unit(exe: &Path, home: Option<&Path>) -> Result<String> {
    let exe = plain_path(exe)?;
    let mut u = with_sandbox(USER_UNIT)?;
    let start = "ExecStart=%h/.local/bin/moochy up --foreground";
    need(&u, start)?;
    let env_dir = if let Some(h) = home {
        let h = plain_path(h)?;
        u = u.replacen(start, &format!("ExecStart={exe} --home {h} up --foreground"), 1);
        h
    } else {
        u = u.replacen(start, &format!("ExecStart={exe} up --foreground"), 1);
        "%h/.config/moochy".to_owned()
    };
    u = u.replacen("Type=exec\n", &format!("Type=exec\n# Optional, 0600: MOOCHY_PASSPHRASE=… for the file keystore.\nEnvironmentFile=-{env_dir}/service.env\n"), 1);
    Ok(u)
}

/// The system unit (fixed user `moochy`, `/var/lib/moochy`), binary path substituted.
pub fn system_unit(exe: &Path) -> Result<String> {
    let exe = plain_path(exe)?;
    let u = with_sandbox(SYSTEM_UNIT)?;
    need(&u, "ExecStart=/usr/local/bin/moochy ")?;
    Ok(u.replacen("ExecStart=/usr/local/bin/moochy ", &format!("ExecStart={exe} "), 1))
}

/// The launchd agent: `__HOME__`, the binary, and `--home` when it is not the default.
pub fn agent_plist(exe: &Path, user_home: &Path, home: Option<&Path>) -> Result<String> {
    let (exe, uh) = (plain_path(exe)?, plain_path(user_home)?);
    need(AGENT_PLIST, "<string>/usr/local/bin/moochy</string>")?;
    let mut p = AGENT_PLIST.replace("__HOME__", &uh).replacen("<string>/usr/local/bin/moochy</string>", &format!("<string>{exe}</string>"), 1);
    if let Some(h) = home {
        let h = plain_path(h)?;
        need(&p, "\t\t<string>up</string>")?;
        p = p.replacen("\t\t<string>up</string>", &format!("\t\t<string>--home</string>\n\t\t<string>{h}</string>\n\t\t<string>up</string>"), 1);
    }
    Ok(p)
}

fn user_home() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| internal("HOME is not set"))
}

fn unit_path(system: bool) -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        return Ok(user_home()?.join("Library/LaunchAgents").join(format!("{LABEL}.plist")));
    }
    if system {
        return Ok(Path::new("/etc/systemd/system").join(UNIT));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).map_or_else(|| user_home().map(|h| h.join(".config")), Ok)?;
    Ok(base.join("systemd/user").join(UNIT))
}

fn run(prog: &str, args: &[&str]) -> Result<()> {
    let st = crate::util::command(prog).args(args).status().map_err(|e| internal(format!("{prog}: {e}")))?;
    if st.success() { Ok(()) } else { Err(internal(format!("`{prog} {}` failed ({st})", args.join(" ")))) }
}

/// `moochy service install [--system] [--print]`.
pub fn install(home: &Home, system: bool, print: bool) -> Result<()> {
    let exe = std::env::current_exe().ctx("current exe")?;
    let default = Home::resolve(None).ok().map(|d| d.dir);
    let custom = (default.as_ref() != Some(&home.dir)).then_some(home.dir.as_path());
    let text = if cfg!(target_os = "macos") {
        agent_plist(&exe, &user_home()?, custom)?
    } else if system {
        system_unit(&exe)?
    } else {
        user_unit(&exe, custom)?
    };
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
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(user_home()?).ctx("home")?);
        let p = path.to_string_lossy().into_owned();
        let _ = run("launchctl", &["bootout", &format!("gui/{uid}"), &p]);
        run("launchctl", &["bootstrap", &format!("gui/{uid}"), &p])?;
    } else if system {
        // The system unit runs as `moochy` with an encrypted credential: finish by hand.
        run("systemctl", &["daemon-reload"])?;
        eprintln!(
            "Installed {}. Next (see the comments at its top): create the `moochy` user, encrypt the keystore passphrase with systemd-creds, log in and add keys as that user, then: sudo systemctl enable --now moochy",
            path.display()
        );
    } else {
        run("systemctl", &["--user", "daemon-reload"])?;
        run("systemctl", &["--user", "enable", "--now", UNIT])?;
    }
    emit(&json!({"event": "service_installed", "unit": path.display().to_string()}));
    Ok(())
}

/// `moochy service uninstall [--system]`.
pub fn uninstall(system: bool) -> Result<()> {
    let path = unit_path(system)?;
    if cfg!(target_os = "macos") {
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(user_home()?).ctx("home")?);
        let _ = run("launchctl", &["bootout", &format!("gui/{uid}"), &path.to_string_lossy()]);
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
    fn units_are_the_reviewed_files_with_substitutions() {
        let u = user_unit(Path::new("/usr/local/bin/moochy"), None).unwrap();
        assert!(u.contains("\nExecStart=/usr/local/bin/moochy up --foreground\n") && !u.contains("/bin/sh"), "{u}");
        assert!(u.contains("SystemCallFilter=@system-service @sandbox landlock_create_ruleset"));
        assert!(u.contains("EnvironmentFile=-%h/.config/moochy/service.env"));
        assert!(u.contains("NoNewPrivileges=yes") && u.contains("WantedBy=default.target"));
        let c = user_unit(Path::new("/opt/m/moochy"), Some(Path::new("/srv/mh"))).unwrap();
        assert!(c.contains("\nExecStart=/opt/m/moochy --home /srv/mh up --foreground\n"), "{c}");
        assert!(c.contains("EnvironmentFile=-/srv/mh/service.env"));
        assert!(user_unit(Path::new("/a b/moochy"), None).is_err(), "no spaces in a unit line");
        assert!(user_unit(Path::new("/x/%h"), None).is_err(), "no systemd specifiers");
        let s = system_unit(Path::new("/usr/bin/moochy")).unwrap();
        assert!(s.contains("\nExecStart=/usr/bin/moochy up --foreground\n") && s.contains("User=moochy") && s.contains("CapabilityBoundingSet=") && s.contains("@sandbox"));
        let p = agent_plist(Path::new("/opt/homebrew/bin/moochy"), Path::new("/Users/ann"), Some(Path::new("/Users/ann/mh"))).unwrap();
        assert!(p.contains("<string>/opt/homebrew/bin/moochy</string>") && p.contains("/Users/ann/Library/Logs/moochy.log") && !p.contains("__HOME__"));
        assert!(p.contains("<string>--home</string>\n\t\t<string>/Users/ann/mh</string>\n\t\t<string>up</string>"), "{p}");
    }
}
