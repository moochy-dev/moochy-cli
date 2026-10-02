//! Secrets: device keys, local-token secret, provider API keys.
//!
//! Backends: encrypted file (scrypt → XChaCha20-Poly1305, passphrase from `MOOCHY_PASSPHRASE`,
//! mode 0600) and, behind the `keychain` feature, the OS keychain.

use crate::config::{Config, Home, write_private};
use crate::util::{Ctx as _, Result, auth, b64d, b64e, internal, lp, rand_bytes};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac as _};
use moochy_proto::crypto::{EncSecret, SignKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const AAD: &[u8] = b"moochy/keystore/v1";
const TOKEN_PREFIX: &str = "mooch_local_";
/// scrypt cost: N = 2^15, r = 8, p = 1 (32 MiB, ~0.1 s).
const LOG_N: u8 = 15;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Default)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    #[serde(default)]
    pub device: Option<DeviceKeys>,
    /// HMAC key for repo-scoped local tokens and affinity keys.
    #[serde(with = "b64_32")]
    pub local_secret: [u8; 32],
    #[serde(default)]
    pub providers: Vec<ProviderKey>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct DeviceKeys {
    /// Ed25519 signing seed.
    #[serde(with = "b64_32")]
    pub sign_seed: [u8; 32],
    /// X25519 static secret.
    #[serde(with = "b64_32")]
    pub enc_secret: [u8; 32],
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProviderKey {
    pub provider: String,
    pub key: String,
    #[serde(default)]
    pub base_url: Option<String>,
    /// `local`: the server may be a public IP or host name (`--allow-unvetted-host`, dev only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[zeroize(skip)]
    pub allow_unvetted_host: bool,
    /// `local`: public catalog slug → the server's model id (`--model local/x=server-id`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    #[zeroize(skip)]
    pub models: std::collections::BTreeMap<String, String>,
    /// `local`: the model ids the server listed at `keys add` (`GET /v1/models`); a `local/*`
    /// catalog entry whose `provider_model_id` is among them is served without a mapping.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[zeroize(skip)]
    pub served_ids: Vec<String>,
    /// `local` over TLS (CONTRACT §17.3): the `host:port` the donor confirmed is their server
    /// (`provider::remote_host_key`). In the keystore, not the plain config: it is authenticated
    /// with the keys, so nobody can add a host behind the donor's back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub remote_host: Option<String>,
    /// Certificate check of a remote server: `roots`, `ca:<base64url DER>`, `sha256:<hex>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub trust: Option<String>,
    /// When set, `key` is the value of this header (e.g. `x-api-key`), not a Bearer API key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub auth_header: Option<String>,
}

impl DeviceKeys {
    pub fn generate() -> Result<Self> {
        Ok(Self { sign_seed: rand_bytes()?, enc_secret: rand_bytes()? })
    }
    pub fn sign_key(&self) -> SignKey {
        SignKey::from_seed(&self.sign_seed)
    }
    pub fn sign_pub(&self) -> [u8; 32] {
        self.sign_key().public()
    }
    pub fn enc_key(&self) -> Result<EncSecret> {
        EncSecret::from_bytes(&self.enc_secret).map_err(|_| auth("device encryption key is corrupt"))
    }
    pub fn enc_pub(&self) -> Result<[u8; 32]> {
        self.enc_key().map(|k| k.public())
    }
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sign_key().sign(msg)
    }
}

type HmacSha256 = Hmac<Sha256>;

impl Secrets {
    pub fn new() -> Result<Self> {
        Ok(Self { device: None, local_secret: rand_bytes()?, providers: Vec::new() })
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <HmacSha256 as hmac::Mac>::new_from_slice(&self.local_secret).unwrap_or_else(|_| unreachable_hmac());
        m.update(&lp(parts));
        m.finalize().into_bytes().into()
    }

    /// Repo-scoped local token: `mooch_local_<b64(slug)>.<b64(HMAC(secret, lp(label, slug, gen)))>`.
    pub fn local_token(&self, slug: &str, generation: u64) -> String {
        let mac = self.mac(&[b"moochy/local-token", slug.as_bytes(), &generation.to_be_bytes()]);
        format!("{TOKEN_PREFIX}{}.{}", b64e(slug.as_bytes()), b64e(&mac))
    }

    /// Verify a local token in constant time; returns its repo slug.
    pub fn check_token(&self, token: &str, generation: u64) -> Option<String> {
        if token.len() > 512 {
            return None;
        }
        let (slug_b64, mac_b64) = token.strip_prefix(TOKEN_PREFIX)?.split_once('.')?;
        let slug = String::from_utf8(b64d(slug_b64)?).ok()?;
        if !crate::config::valid_slug(&slug) {
            return None;
        }
        let given = b64d(mac_b64)?;
        let want = self.mac(&[b"moochy/local-token", slug.as_bytes(), &generation.to_be_bytes()]);
        bool::from(want.as_slice().ct_eq(&given)).then_some(slug)
    }

    /// Session-affinity key: HMAC(per-device secret, lp(label, system, tools, first user message)), 16 bytes.
    pub fn affinity(&self, system: &[u8], tools: &[u8], first_user: &[u8]) -> [u8; 16] {
        let m = self.mac(&[b"moochy/affinity", system, tools, first_user]);
        let mut out = [0u8; 16];
        out.copy_from_slice(m.get(..16).unwrap_or(&[0u8; 16]));
        out
    }

    pub fn provider(&self, name: &str) -> Option<&ProviderKey> {
        self.providers.iter().find(|p| p.provider == name)
    }
}

/// HMAC-SHA256 accepts keys of any length; this cannot happen.
#[cold]
fn unreachable_hmac() -> HmacSha256 {
    std::process::abort()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileV1 {
    v: u32,
    kdf: String,
    log_n: u8,
    r: u32,
    p: u32,
    salt: String,
    nonce: String,
    ct: String,
}

fn passphrase() -> Result<Zeroizing<String>> {
    passphrase_source()?.ok_or_else(|| auth("keystore locked: set MOOCHY_PASSPHRASE (or MOOCHY_PASSPHRASE_FILE, or a systemd credential `moochy-passphrase`)"))
}

/// The file-keystore passphrase (mo-ops units): `MOOCHY_PASSPHRASE`, else the file named by
/// `MOOCHY_PASSPHRASE_FILE` (owner-only permissions), else the systemd credential
/// `$CREDENTIALS_DIRECTORY/moochy-passphrase` (LoadCredential/LoadCredentialEncrypted).
/// One trailing newline is dropped; at most 4 KiB is read.
pub fn passphrase_source() -> Result<Option<Zeroizing<String>>> {
    use std::io::Read as _;
    if let Ok(p) = std::env::var("MOOCHY_PASSPHRASE").map(Zeroizing::new)
        && !p.is_empty()
    {
        return Ok(Some(p));
    }
    let read = |path: &std::path::Path, owner_only: bool| -> Result<Option<Zeroizing<String>>> {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(f) = std::fs::File::open(path) else { return Ok(None) };
        let md = f.metadata().map_err(|e| auth(format!("{}: {e}", path.display())))?;
        if !md.is_file() || (owner_only && md.permissions().mode() & 0o077 != 0) {
            return Err(auth(format!("{}: the passphrase file must be a regular file readable only by you (chmod 600)", path.display())));
        }
        let mut raw = Zeroizing::new(Vec::new());
        f.take(4097).read_to_end(&mut raw).map_err(|e| auth(format!("{}: {e}", path.display())))?;
        if raw.len() > 4096 {
            return Err(auth("the passphrase file is larger than 4 KiB"));
        }
        let s = std::str::from_utf8(&raw).map_err(|_| auth("the passphrase file is not UTF-8"))?;
        let s = s.strip_suffix('\n').map_or(s, |t| t.strip_suffix('\r').unwrap_or(t));
        Ok((!s.is_empty()).then(|| Zeroizing::new(s.to_owned())))
    };
    if let Some(p) = std::env::var_os("MOOCHY_PASSPHRASE_FILE") {
        return match read(std::path::Path::new(&p), true)? {
            Some(s) => Ok(Some(s)),
            None => Err(auth("MOOCHY_PASSPHRASE_FILE names no readable, non-empty file")),
        };
    }
    match std::env::var_os("CREDENTIALS_DIRECTORY") {
        Some(d) => read(&std::path::Path::new(&d).join("moochy-passphrase"), false),
        None => Ok(None),
    }
}

fn derive(pass: &str, salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = scrypt::Params::new(log_n, r, p, 32).map_err(|_| auth("bad keystore kdf params"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(pass.as_bytes(), salt, &params, key.as_mut()).map_err(|_| internal("scrypt"))?;
    Ok(key)
}

/// Encrypt under a passphrase; `aad` separates file kinds (keystore, owner key).
pub(crate) fn seal(plain: &[u8], pass: &str, aad: &[u8]) -> Result<Vec<u8>> {
    let salt: [u8; 16] = rand_bytes()?;
    let nonce: [u8; 24] = rand_bytes()?;
    let key = derive(pass, &salt, LOG_N, 8, 1)?;
    let ct = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
        .map_err(|_| internal("keystore encrypt"))?;
    let f = FileV1 {
        v: 1,
        kdf: "scrypt".into(),
        log_n: LOG_N,
        r: 8,
        p: 1,
        salt: b64e(&salt),
        nonce: b64e(&nonce),
        ct: b64e(&ct),
    };
    serde_json::to_vec(&f).ctx("encode keystore")
}

pub(crate) fn open(file: &[u8], pass: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let f: FileV1 = serde_json::from_slice(file).map_err(|_| auth("keystore file is corrupt"))?;
    // Bound the KDF cost an attacker-supplied file can impose.
    if f.v != 1 || f.kdf != "scrypt" || !(10..=20).contains(&f.log_n) || f.r != 8 || f.p != 1 {
        return Err(auth("unsupported keystore parameters"));
    }
    let (Some(salt), Some(nonce), Some(ct)) = (b64d(&f.salt), b64d(&f.nonce), b64d(&f.ct)) else {
        return Err(auth("keystore file is corrupt"));
    };
    if nonce.len() != 24 {
        return Err(auth("keystore file is corrupt"));
    }
    let key = derive(pass, &salt, f.log_n, f.r, f.p)?;
    XChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| auth("wrong passphrase or tampered keystore"))
}

/// This build has an OS keychain backend.
pub const KEYCHAIN_BUILT: bool = cfg!(all(feature = "keychain", any(target_os = "linux", target_os = "macos")));

fn use_keychain(cfg: &Config) -> bool {
    cfg.keystore.as_deref() == Some("keychain")
}

/// Load secrets; `None` when no keystore exists yet.
pub fn load(home: &Home, cfg: &Config) -> Result<Option<Secrets>> {
    let plain = if use_keychain(cfg) {
        match keychain::get(home, cfg)? {
            Some(p) => p,
            None => return Ok(None),
        }
    } else {
        match std::fs::read(home.keystore_path(cfg.relay.as_deref())) {
            Ok(b) => open(&b, &passphrase()?, AAD)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(internal(format!("read keystore: {e}"))),
        }
    };
    serde_json::from_slice(&plain).map(Some).map_err(|_| auth("keystore content is corrupt"))
}

/// Load, or create fresh secrets (choosing the backend on first creation).
pub fn load_or_init(home: &Home, cfg: &mut Config) -> Result<Secrets> {
    if let Some(s) = load(home, cfg)? {
        return Ok(s);
    }
    let s = Secrets::new()?;
    if cfg.keystore.is_none() {
        // T-02-010: the OS keychain by default; the encrypted file when MOOCHY_PASSPHRASE is set
        // (headless, CI) or when this machine has no keychain service.
        let mut chosen = "file";
        if KEYCHAIN_BUILT && passphrase_source().ok().flatten().is_none() {
            let mut probe = cfg.clone();
            probe.keystore = Some("keychain".into());
            match save(home, &probe, &s) {
                Ok(()) => chosen = "keychain",
                Err(e) => {
                    return Err(auth(format!(
                        "no OS keychain available here ({}); set MOOCHY_PASSPHRASE to keep the keys in the encrypted file instead",
                        e.msg
                    )));
                }
            }
        }
        cfg.keystore = Some(chosen.into());
        home.save(cfg)?;
        if chosen == "keychain" {
            return Ok(s);
        }
    }
    save(home, cfg, &s)?;
    Ok(s)
}

pub fn save(home: &Home, cfg: &Config, s: &Secrets) -> Result<()> {
    home.ensure()?;
    let plain = Zeroizing::new(serde_json::to_vec(s).ctx("encode secrets")?);
    if use_keychain(cfg) {
        return keychain::set(home, cfg, &plain);
    }
    write_private(&home.keystore_path(cfg.relay.as_deref()), &seal(&plain, &passphrase()?, AAD)?)
}

#[cfg(all(feature = "keychain", any(target_os = "linux", target_os = "macos")))]
mod keychain {
    use super::{Config, Home, Result, Zeroizing, b64d, b64e};
    use crate::util::{auth, internal};

    fn entry(home: &Home, cfg: &Config) -> Result<keyring::Entry> {
        let user = match cfg.relay.as_deref() {
            Some(r) if r != crate::config::DEFAULT_RELAY => format!("{}#{}", home.dir.to_string_lossy(), crate::config::origin_tag(r)),
            _ => home.dir.to_string_lossy().into_owned(),
        };
        keyring::Entry::new("moochy", &user).map_err(|e| internal(format!("keychain: {e}")))
    }
    /// Keyring calls may block on D-Bus (Linux Secret Service): run them on their own short-lived
    /// OS thread, never on an async runtime's thread, whoever the caller is.
    fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> Result<T> {
        std::thread::scope(|s| s.spawn(f).join()).map_err(|_| internal("keychain thread failed"))
    }

    pub fn get(home: &Home, cfg: &Config) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let e = entry(home, cfg)?;
        match off_runtime(move || e.get_password())? {
            Ok(p) => {
                let p = Zeroizing::new(p);
                b64d(&p).map(|v| Some(Zeroizing::new(v))).ok_or_else(|| auth("keychain entry is corrupt"))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(auth(format!("keychain: {e}"))),
        }
    }
    pub fn set(home: &Home, cfg: &Config, plain: &[u8]) -> Result<()> {
        let s = Zeroizing::new(b64e(plain));
        let e = entry(home, cfg)?;
        off_runtime(move || e.set_password(&s))?.map_err(|e| internal(format!("keychain: {e}")))
    }
}

#[cfg(not(all(feature = "keychain", any(target_os = "linux", target_os = "macos"))))]
mod keychain {
    use super::{Config, Home, Result, Zeroizing};
    use crate::util::usage;
    pub fn get(_: &Home, _: &Config) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Err(usage("this build has no keychain support (feature `keychain`)"))
    }
    pub fn set(_: &Home, _: &Config, _: &[u8]) -> Result<()> {
        Err(usage("this build has no keychain support (feature `keychain`)"))
    }
}

mod b64_32 {
    use serde::{Deserialize as _, Deserializer, Serializer};
    use zeroize::Zeroizing;
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&Zeroizing::new(crate::util::b64e(v)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        crate::util::b64d32(&s).ok_or_else(|| serde::de::Error::custom("expected 32 bytes base64url"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_tokens() {
        let mut s = Secrets::new().unwrap();
        s.device = Some(DeviceKeys::generate().unwrap());
        let plain = serde_json::to_vec(&s).unwrap();
        let file = seal(&plain, "pw", AAD).unwrap();
        assert_eq!(&*open(&file, "pw", AAD).unwrap(), &plain);
        assert!(open(&file, "pW", AAD).is_err());
        let mut f: serde_json::Value = serde_json::from_slice(&file).unwrap();
        let ct = f["ct"].as_str().unwrap().replace('A', "B");
        f["ct"] = ct.into();
        assert!(open(&serde_json::to_vec(&f).unwrap(), "pw", AAD).is_err());

        let t = s.local_token("acme/widget", 0);
        assert_eq!(s.check_token(&t, 0).as_deref(), Some("acme/widget"));
        assert_eq!(s.check_token(&t, 1), None, "rotation invalidates");
        let other = s.local_token("acme/other", 0);
        let forged = format!("{}.{}", other.split_once('.').unwrap().0, t.split_once('.').unwrap().1);
        assert_eq!(s.check_token(&forged, 0), None, "mac bound to slug");
        assert_eq!(Secrets::new().unwrap().check_token(&t, 0), None);
    }
}
