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
    /// The user's public pseudonym (`ps_…`, from device approval): key-log entries name it.
    pub pseudonym: Option<String>,
    pub device_monthly_cap_uusd: Option<u64>,
    pub slots_max: Option<u32>,
    pub gateway_addr: Option<String>,
    /// Bumped by `moochy env --rotate`: invalidates every local token.
    pub token_gen: u64,
    /// Repo slug → workspace root recorded by `moochy env`/`connect` (MCP `files` root).
    pub repos: BTreeMap<String, RepoEntry>,
    /// `file` (default) or `keychain`.
    pub keystore: Option<String>,
    /// Opt-in: the local journal may keep full request/response text (default off: metadata only).
    pub journal_full_text: bool,
    /// Gateway: automatic prompt caching for multi-turn Anthropic requests (default on).
    pub auto_cache: Option<bool>,
    /// Worker firewall strictness: `strict` (default) or `paranoid` (06 §7.3).
    pub firewall_level: Option<String>,
    /// Key-log note key (`origin+hash+base64`, signed-note vkey) pinned for the relay; without
    /// it the node trusts relay-asserted membership and approvals (D14, dev only).
    pub log_key: Option<String>,
    pub log_origin: Option<String>,
    /// Receipt transparency log note key (KEYLOG §8, origin `moochy.dev/receipts`): inclusion
    /// proofs in `ReceiptAck` are verified against it (compiled in for the default relay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipts_log_key: Option<String>,
    /// Public Git anchor of the key log (hourly fork check), e.g. a raw-file base URL.
    pub log_anchor_url: Option<String>,
    /// Worker: serve only these public models (comma-separated), below what the keys allow.
    pub models_override: Option<String>,
    /// Projects (`owner/name`, comma-separated) whose clients receive tool calls from donated
    /// tokens outside `moochy run` (CONTRACT §15.4 opt-in; warned at every start).
    pub allow_unsandboxed_tools: Option<String>,
    /// Donor safety step (07 §8.1 step 4) accepted at this Unix ms: a monthly cap for this
    /// machine and the provider-side spend limit advice. No serving without it (outside dev).
    pub donor_safety_ack_ms: Option<u64>,
    /// Pinned donors per project (06 §8 "pinned donors"): `owner/name` → donor names; tasks for
    /// that project are sealed only to these donors.
    pub pinned_donors: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RepoEntry {
    pub root: Option<PathBuf>,
}

pub const DEFAULT_GATEWAY_ADDR: &str = "127.0.0.1:0";
/// The public relay's gRPC listener (CONTRACT §14b R2).
pub const DEFAULT_RELAY: &str = "https://relay.moochy.dev:8443";

/// Short stable tag of a relay origin (file names, keychain entries).
pub fn origin_tag(origin: &str) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(origin.as_bytes()).iter().take(8).fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}
pub const DEFAULT_SLOTS: u32 = 4;

#[derive(Clone, Debug)]
pub struct Home {
    pub dir: PathBuf,
}

impl Home {
    pub fn resolve(flag: Option<PathBuf>) -> Result<Self> {
        let dir = if let Some(d) = flag.or_else(|| std::env::var_os("MOOCHY_HOME").map(PathBuf::from)) {
            d
        } else {
            let base = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
                .ok_or_else(|| usage("cannot find a home directory; pass --home"))?;
            base.join("moochy")
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
    /// Keystore file for a relay origin: the default relay uses `keystore.enc`; any other origin
    /// gets its own file (A135: a login to another relay never touches the default keys).
    pub fn keystore_path(&self, relay: Option<&str>) -> PathBuf {
        match relay {
            None => self.dir.join("keystore.enc"),
            Some(r) if r == DEFAULT_RELAY => self.dir.join("keystore.enc"),
            Some(r) => self.dir.join(format!("keystore-{}.enc", origin_tag(r))),
        }
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

    pub fn auto_cache(&self) -> bool {
        self.auto_cache.unwrap_or(true)
    }

    /// `models_override` as a list (`None` = no override).
    pub fn models_override(&self) -> Option<Vec<&str>> {
        self.models_override.as_deref().map(|v| v.split(',').map(str::trim).filter(|m| !m.is_empty()).collect())
    }

    /// The §15.4 opt-in: tool calls reach clients of `slug` that are not sandboxed.
    pub fn unsandboxed_tools_allowed(&self, slug: &str) -> bool {
        self.allow_unsandboxed_tools.as_deref().is_some_and(|v| v.split(',').any(|s| s.trim().eq_ignore_ascii_case(slug)))
    }

    pub fn has_role(&self, r: &str) -> bool {
        self.roles.iter().any(|x| x == r)
    }

    /// `moochy config set <key> <value>`.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "monthly_limit" => {
                self.device_monthly_cap_uusd = Some(crate::util::parse_amount(value).map_err(|e| usage(format!("monthly_limit is a dollar amount, e.g. 20 or 12.50: {e}")))?);
            }
            // Machine form of `monthly_limit` (millionths of a dollar), kept for scripts.
            "device_monthly_cap_uusd" => {
                self.device_monthly_cap_uusd = Some(value.parse().map_err(|_| usage("device_monthly_cap_uusd is a whole number; use `monthly_limit 20` for $20"))?);
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
            "journal_full_text" => self.journal_full_text = parse_bool(key, value)?,
            "auto_cache" => self.auto_cache = Some(parse_bool(key, value)?),
            "firewall_level" => {
                if !matches!(value, "strict" | "paranoid") {
                    return Err(usage("firewall_level (safety checks) is strict or paranoid"));
                }
                self.firewall_level = Some(value.into());
            }
            "log_key" => {
                moochy_keylog::NoteKey::parse(value).map_err(|e| usage(format!("log_key: {e}")))?;
                self.log_key = Some(value.into());
            }
            "receipts_log_key" => {
                moochy_keylog::NoteKey::parse(value).map_err(|e| usage(format!("receipts_log_key: {e}")))?;
                self.receipts_log_key = Some(value.into());
            }
            "log_anchor_url" => {
                if !value.starts_with("https://") {
                    return Err(usage("log_anchor_url must be https://"));
                }
                self.log_anchor_url = Some(value.into());
            }
            "models_override" => self.models_override = Some(value.into()).filter(|v: &String| !v.is_empty()),
            "pinned_donors" => {
                // `owner/name=alice,bob` (empty list clears the project's pins).
                let (slug, names) = value.split_once('=').ok_or_else(|| usage("pinned_donors is owner/name=donor1,donor2"))?;
                if !valid_slug(slug) {
                    return Err(usage("pinned_donors is owner/name=donor1,donor2"));
                }
                let names: Vec<String> = names.split(',').map(str::trim).filter(|n| !n.is_empty()).map(str::to_owned).collect();
                if names.len() > 64 || !names.iter().all(|n| n.len() <= 64 && n.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(&c))) {
                    return Err(usage("pinned_donors: at most 64 names of letters, digits, _ - ."));
                }
                if names.is_empty() {
                    self.pinned_donors.remove(&slug.to_ascii_lowercase());
                } else {
                    self.pinned_donors.insert(slug.to_ascii_lowercase(), names);
                }
            }
            "allow_unsandboxed_tools" => {
                if !value.is_empty() && !value.split(',').all(|s| valid_slug(s.trim())) {
                    return Err(usage("allow_unsandboxed_tools is a comma-separated list of owner/name projects (empty to clear)"));
                }
                self.allow_unsandboxed_tools = Some(value.into()).filter(|v: &String| !v.is_empty());
            }
            _ => {
                return Err(usage(format!(
                    "unknown config key {key:?} (monthly_limit, slots_max, gateway_addr, journal_full_text, auto_cache, firewall_level, models_override, allow_unsandboxed_tools, pinned_donors, log_key, receipts_log_key, log_anchor_url)"
                )));
            }
        }
        Ok(())
    }
}

fn parse_bool(key: &str, v: &str) -> Result<bool> {
    match v {
        "true" | "1" | "on" => Ok(true),
        "false" | "0" | "off" => Ok(false),
        _ => Err(usage(format!("{key} is true or false"))),
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
