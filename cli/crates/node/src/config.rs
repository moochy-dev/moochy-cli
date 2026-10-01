//! `--home` layout and the (secret-free) config file.
//!
//! ```text
//! <home>/config.json      settings, no secrets
//! <home>/keystore.enc     encrypted secrets (file backend)
//! <home>/state/           0700: node.json, node.sock
//! ```

use crate::util::{Ctx as _, Result, usage};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `wss://host:port` as dialed.
    pub relay: Option<String>,
    /// Absolute path of a PEM CA bundle that replaces the public roots.
    pub ca_file: Option<PathBuf>,
    pub roles: Vec<String>,
    pub device_id: Option<String>,
    pub device_monthly_cap_uusd: Option<u64>,
    pub slots_max: Option<u32>,
    pub gateway_addr: Option<String>,
    /// Bumped by `moochy env --rotate`: invalidates every local token.
    pub token_gen: u64,
    /// Repo slug → workspace root recorded by `moochy env`/`connect` (MCP `files` root).
    pub repos: BTreeMap<String, RepoEntry>,
    /// `file` (default) or `keychain`.
    pub keystore: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RepoEntry {
    pub root: Option<PathBuf>,
}

pub const DEFAULT_GATEWAY_ADDR: &str = "127.0.0.1:0";
pub const DEFAULT_SLOTS: u32 = 4;

#[derive(Clone, Debug)]
pub struct Home {
    pub dir: PathBuf,
}

impl Home {
    pub fn resolve(flag: Option<PathBuf>) -> Result<Self> {
        let dir = match flag.or_else(|| std::env::var_os("MOOCHY_HOME").map(PathBuf::from)) {
            Some(d) => d,
            None => {
                let base = std::env::var_os("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
                    .ok_or_else(|| usage("cannot find a home directory; pass --home"))?;
                base.join("moochy")
            }
        };
        let dir = std::path::absolute(&dir).ctx("home path")?;
        Ok(Self { dir })
    }

    pub fn ensure(&self) -> Result<()> {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(self.state_dir()).ctx("create home")
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir.join("config.json")
    }
    pub fn keystore_path(&self) -> PathBuf {
        self.dir.join("keystore.enc")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }
    pub fn node_json(&self) -> PathBuf {
        self.state_dir().join("node.json")
    }
    pub fn socket_path(&self) -> PathBuf {
        self.state_dir().join("node.sock")
    }

    pub fn load(&self) -> Result<Config> {
        match fs::read(self.config_path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| usage(format!("bad config.json: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(crate::util::internal(format!("read config: {e}"))),
        }
    }

    pub fn save(&self, cfg: &Config) -> Result<()> {
        self.ensure()?;
        let mut b = serde_json::to_vec_pretty(cfg).ctx("encode config")?;
        b.push(b'\n');
        write_private(&self.config_path(), &b)
    }
}

/// Atomic write with mode 0600 (tmp + fsync + rename).
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).ctx("create file")?;
    f.write_all(data).ctx("write file")?;
    f.sync_all().ctx("fsync")?;
    drop(f);
    fs::rename(&tmp, path).ctx("rename")
}

impl Config {
    pub fn gateway_addr(&self) -> Result<SocketAddr> {
        let s = self.gateway_addr.as_deref().unwrap_or(DEFAULT_GATEWAY_ADDR);
        let a: SocketAddr = s.parse().map_err(|_| usage(format!("gateway_addr {s:?} is not ip:port")))?;
        if !a.ip().is_loopback() {
            return Err(usage("gateway_addr must be a loopback address"));
        }
        Ok(a)
    }

    pub fn has_role(&self, r: &str) -> bool {
        self.roles.iter().any(|x| x == r)
    }

    /// `moochy config set <key> <value>`.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "device_monthly_cap_uusd" => {
                self.device_monthly_cap_uusd = Some(value.parse().map_err(|_| usage("expected an integer µ$ amount"))?);
            }
            "slots_max" => {
                let n: u32 = value.parse().map_err(|_| usage("expected an integer"))?;
                if !(1..=64).contains(&n) {
                    return Err(usage("slots_max must be within 1..=64"));
                }
                self.slots_max = Some(n);
            }
            "gateway_addr" => {
                let old = self.gateway_addr.replace(value.to_owned());
                if let Err(e) = self.gateway_addr() {
                    self.gateway_addr = old;
                    return Err(e);
                }
            }
            _ => return Err(usage(format!("unknown config key {key:?} (device_monthly_cap_uusd, slots_max, gateway_addr)"))),
        }
        Ok(())
    }
}

/// `owner/name` with conservative characters.
pub fn valid_slug(s: &str) -> bool {
    let ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 100
            && p != "."
            && p != ".."
            && p.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
    };
    matches!(s.split_once('/'), Some((o, n)) if ok(o) && ok(n))
}

#[cfg(test)]
mod tests {
    #[test]
    fn slugs() {
        assert!(super::valid_slug("acme/widget.rs"));
        assert!(!super::valid_slug("acme"));
        assert!(!super::valid_slug("acme/../x"));
        assert!(!super::valid_slug("acme/.."));
        assert!(!super::valid_slug("a/b c"));
    }
}
