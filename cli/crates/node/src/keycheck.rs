//! `moochy keys add` validation (06 §4.2): API keys only, checked with the provider's free
//! models endpoint before they are stored. `--base-url` replaces the provider origin only, for
//! loopback IP literals with `MOOCHY_INSECURE_DEV=1` (CONTRACT §6).

use crate::util::{Result, auth, net, usage};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Donor providers `moochy keys add` accepts (CONTRACT §9).
pub const PROVIDERS: &[&str] = &["anthropic", "openai", "openrouter", "deepseek", "xai"];

/// Provider origin and models path (relative to the origin).
fn endpoint(provider: &str) -> Option<(&'static str, &'static str)> {
    Some(match provider {
        "anthropic" => ("https://api.anthropic.com", "/v1/models"),
        "openai" => ("https://api.openai.com", "/v1/models"),
        "deepseek" => ("https://api.deepseek.com", "/models"),
        "openrouter" => ("https://openrouter.ai", "/api/v1/models"),
        "xai" => ("https://api.x.ai", "/v1/models"),
        _ => return None,
    })
}

/// Consumer / subscription credentials are refused technically (06 §14): API keys only.
pub fn refuse_consumer_credential(provider: &str, key: &str) -> Result<()> {
    let oauth = key.starts_with("sk-ant-oat") || key.starts_with("sk-ant-ort") || key.starts_with("eyJ") || key.starts_with("Bearer ");
    if oauth {
        return Err(usage(format!("{provider}: this looks like a subscription/OAuth credential; Moochy accepts provider API keys only")));
    }
    Ok(())
}

/// `--base-url`: `http(s)://<loopback IP literal>:port` only (`localhost` is a name: refused).
pub fn check_base_url(u: &str, dev: bool) -> Result<()> {
    if !dev {
        return Err(usage("--base-url is only accepted with MOOCHY_INSECURE_DEV=1"));
    }
    let rest = u.strip_prefix("http://").or_else(|| u.strip_prefix("https://")).ok_or_else(|| usage("--base-url must be http(s)://"))?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains('@') || rest.trim_end_matches('/').contains('/') {
        return Err(usage("--base-url is an origin (scheme://ip:port) without credentials or path"));
    }
    let host = if let Some(v6) = authority.strip_prefix('[') { v6.split(']').next().unwrap_or("") } else { authority.rsplit_once(':').map_or(authority, |(h, _)| h) };
    if !host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return Err(usage("--base-url must be a loopback IP literal (e.g. http://127.0.0.1:PORT)"));
    }
    Ok(())
}

/// GET the models endpoint with the key; Ok = the key works.
pub async fn validate(provider: &str, key: &str, base_url: Option<&str>) -> Result<()> {
    let (origin, path) = endpoint(provider).ok_or_else(|| usage("unknown provider"))?;
    let (status, _) = fetch(provider, key, base_url.unwrap_or(origin), path).await?;
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(auth(format!("{provider} rejected the key ({status}); nothing was stored"))),
        s => Err(net(format!("{provider} models endpoint answered {s}; key not validated, nothing stored"))),
    }
}

/// GET `origin + path` with the provider's auth header (none for an empty key).
async fn fetch(provider: &str, key: &str, origin: &str, path: &str) -> Result<(u16, Bytes)> {
    let origin = origin.trim_end_matches('/');
    let (scheme, authority) = origin.split_once("://").ok_or_else(|| usage("bad provider URL"))?;
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => {
            let (h, rest) = v6.split_once(']').ok_or_else(|| usage("bad IPv6 host"))?;
            (h.to_owned(), rest.strip_prefix(':').map_or(Ok(default_port), str::parse).map_err(|_| usage("bad port"))?)
        }
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().map_err(|_| usage("bad port"))?),
            None => (authority.to_owned(), default_port),
        },
    };
    let mut req = hyper::Request::get(path).header(hyper::header::HOST, authority).header("user-agent", concat!("moochy/", env!("CARGO_PKG_VERSION")));
    req = if provider == "anthropic" {
        req.header("x-api-key", key).header("anthropic-version", "2023-06-01")
    } else if key.is_empty() {
        req
    } else {
        req.header("authorization", format!("Bearer {key}"))
    };
    let req = req.body(Empty::<Bytes>::new()).map_err(|e| usage(format!("bad request: {e}")))?;
    let tcp = timeout(TIMEOUT, tokio::net::TcpStream::connect((host.as_str(), port))).await.map_err(|_| net("provider connect timeout"))?.map_err(|e| net(format!("provider connect: {e}")))?;
    let _ = tcp.set_nodelay(true);
    if scheme == "https" {
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| net(format!("tls: {e}")))?
            .with_root_certificates(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| usage("bad provider host"))?;
        let tls = timeout(TIMEOUT, tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp)).await.map_err(|_| net("TLS timeout"))?.map_err(|e| net(format!("TLS: {e}")))?;
        get(TokioIo::new(tls), req).await
    } else {
        get(TokioIo::new(tcp), req).await
    }
}

async fn get<T>(io: TokioIo<T>, req: hyper::Request<Empty<Bytes>>) -> Result<(u16, Bytes)>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut tx, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| net(format!("http: {e}")))?;
    let c = tokio::spawn(conn);
    let resp = timeout(TIMEOUT, tx.send_request(req)).await.map_err(|_| net("provider timeout"))?.map_err(|e| net(format!("http: {e}")))?;
    let status = resp.status().as_u16();
    // Bounded read (also lets the connection close cleanly).
    let body = match timeout(TIMEOUT, Limited::new(resp.into_body(), 1 << 20).collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        _ => Bytes::new(),
    };
    c.abort();
    Ok((status, body))
}

/// Model ids a local server lists (`GET /v1/models`, OpenAI shape): plain ids only, bounded.
fn model_ids(body: &[u8]) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    v.get("data")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|m| m.get("id")?.as_str())
        .filter(|id| !id.is_empty() && id.len() <= 200 && id.bytes().all(|c| c.is_ascii_graphic()))
        .take(1000)
        .map(str::to_owned)
        .collect()
}

/// `moochy keys add local --base-url URL [--key-stdin] [--allow-unvetted-host] --model SLUG=ID…`
/// (worker API.md "Local inference servers"): host vetting, optional key, model discovery, and
/// the slug → server id mapping the worker serves.
pub fn add_local(home: &crate::config::Home, base_url: Option<&str>, key_stdin: bool, allow_unvetted: bool, models: &[String]) -> Result<()> {
    use moochy_worker::provider::{LocalHost, check_local_base_url};
    let url = base_url.ok_or_else(|| usage("keys add local needs --base-url http://127.0.0.1:PORT (your server's origin)"))?;
    if allow_unvetted && std::env::var("MOOCHY_INSECURE_DEV").as_deref() != Ok("1") {
        return Err(usage("--allow-unvetted-host is only accepted with MOOCHY_INSECURE_DEV=1"));
    }
    match check_local_base_url(url, allow_unvetted).map_err(|e| usage(format!("--base-url: {e}")))? {
        LocalHost::Loopback => {}
        LocalHost::Lan => eprintln!("Note: requests to this server cross your local network{}.", if url.starts_with("http://") { " in clear text" } else { "" }),
        LocalHost::Unvetted => eprintln!("WARNING: {url} is not a loopback or private address: its name can be re-pointed elsewhere (development only)."),
        // Remote servers take `add_remote` (vetted host, TLS); not reachable through --base-url.
        LocalHost::Remote => return Err(usage("a remote server needs --url https://… (vetted, TLS)")),
    }
    let key = if key_stdin {
        let mut raw = zeroize::Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut std::io::Read::take(std::io::stdin(), 4097), &mut raw).map_err(|e| usage(format!("read stdin: {e}")))?;
        let k = zeroize::Zeroizing::new(std::str::from_utf8(&raw).map_err(|_| usage("key must be UTF-8"))?.trim().to_owned());
        if raw.len() > 4096 || !k.bytes().all(|c| c.is_ascii_graphic()) {
            return Err(usage("key must be printable ASCII, at most 4 KiB"));
        }
        k
    } else {
        zeroize::Zeroizing::new(String::new())
    };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| net(format!("runtime: {e}")))?;
    let (status, body) = rt.block_on(fetch("local", &key, url, "/v1/models"))?;
    match status {
        200..=299 => {}
        401 | 403 => return Err(auth(format!("the server refused the key ({status}); nothing was stored"))),
        s => return Err(net(format!("{url}/v1/models answered {s}; is it an OpenAI-compatible server? nothing stored"))),
    }
    let served = model_ids(&body);
    let mut map = std::collections::BTreeMap::new();
    for m in models {
        let (slug, id) = m.split_once('=').ok_or_else(|| usage("--model is local/<slug>=<server model id>"))?;
        if !slug.starts_with("local/") || !crate::node::plain_id(slug) || !crate::node::plain_id(id) {
            return Err(usage(format!("--model {m}: the public slug starts with local/ and both sides are plain ids")));
        }
        if moochy_worker::firewall::is_cloud_routed(id) {
            return Err(usage(format!("--model {m}: {id} runs in the cloud (billed to your account), not on this machine")));
        }
        if !served.iter().any(|s| s == id) {
            return Err(usage(format!("--model {m}: the server does not list {id} (it lists: {})", served.join(", "))));
        }
        map.insert(slug.to_owned(), id.to_owned());
    }
    if map.is_empty() {
        eprintln!("The server lists: {}. Catalog models with one of these ids are served as is; map others with --model local/<slug>=<id>.", served.join(", "));
    }
    let mut cfg = home.load()?;
    let mut sec = crate::keystore::load_or_init(home, &mut cfg)?;
    sec.providers.retain(|p| p.provider != "local");
    sec.providers.push(crate::keystore::ProviderKey { provider: "local".into(), key: key.to_string(), base_url: Some(url.to_owned()), allow_unvetted_host: allow_unvetted, models: map.clone(), remote_host: None, trust: None, auth_header: None, served_ids: served.iter().filter(|id| !moochy_worker::firewall::is_cloud_routed(id)).cloned().collect() });
    crate::keystore::save(home, &cfg, &sec)?;
    crate::util::emit(&serde_json::json!({"event": "key_added", "provider": "local", "models": map}));
    Ok(())
}

/// `keys add local --url https://…` options (CONTRACT §17.3).
pub struct Remote {
    /// `provider::remote_host_key(url)`: the canonical `host:port`.
    pub host: String,
    pub ca_file: Option<std::path::PathBuf>,
    pub cert_sha256: Option<String>,
    /// Header name for the secret read on stdin (e.g. `x-api-key`); else a Bearer API key.
    pub auth_header: Option<String>,
    /// Headless confirmation: must be exactly `host`.
    pub confirm_host: Option<String>,
}

/// First certificate of a PEM file, as DER.
fn pem_cert(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let body = pem.split("-----BEGIN CERTIFICATE-----").nth(1)?.split("-----END CERTIFICATE-----").next()?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok().filter(|d| !d.is_empty() && d.len() <= 16 << 10)
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim().replace(':', "").to_ascii_lowercase();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i.checked_mul(2)?..i.checked_mul(2)?.checked_add(2)?)?, 16).ok()?;
    }
    Some(out)
}

/// The adapter options of a stored `local` provider (vetted host, header, certificate check).
pub fn local_options(p: &crate::keystore::ProviderKey, dev: bool) -> std::result::Result<moochy_worker::provider::LocalOptions, &'static str> {
    use moochy_worker::provider::{LocalOptions, RemoteTrust};
    let trust = match p.trust.as_deref() {
        None | Some("roots") => RemoteTrust::Roots,
        Some(t) if t.starts_with("ca:") => RemoteTrust::Ca(rustls::pki_types::CertificateDer::from(crate::util::b64d(t.get(3..).unwrap_or("")).ok_or("stored CA is corrupt")?)),
        Some(t) if t.starts_with("sha256:") => RemoteTrust::Fingerprint(hex32(t.get(7..).unwrap_or("")).ok_or("stored fingerprint is corrupt")?),
        Some(_) => return Err("unknown certificate check"),
    };
    let auth_header = p.auth_header.clone().map(|n| (n, zeroize::Zeroizing::new(p.key.clone())));
    Ok(LocalOptions { allow_unvetted_host: p.allow_unvetted_host && dev, vetted_hosts: p.remote_host.clone().into_iter().collect(), auth_header, trust })
}

/// `roots` / `ca` / `fingerprint`, for status and doctor (never the header value).
pub fn trust_name(p: &crate::keystore::ProviderKey) -> &'static str {
    match p.trust.as_deref() {
        Some(t) if t.starts_with("ca:") => "ca",
        Some(t) if t.starts_with("sha256:") => "fingerprint",
        _ => "roots",
    }
}

/// `moochy keys add local --url https://… [--ca-file PEM | --cert-sha256 HEX]
/// [--header-from-keystore NAME --key-stdin] --model local/<slug>=<id> [--confirm-host HOST:PORT]`
/// (CONTRACT §17.3, worker API.md "Remote GPU servers"): the donor confirms the exact host is
/// theirs (`--yes` never does it), the secret goes to the keystore only, the adapter is built
/// once to check the whole configuration before anything is stored.
pub fn add_remote(home: &crate::config::Home, url: &str, r: &Remote, key_stdin: bool, allow_unvetted: bool, models: &[String]) -> Result<()> {
    if allow_unvetted && std::env::var("MOOCHY_INSECURE_DEV").as_deref() != Ok("1") {
        return Err(usage("--allow-unvetted-host is only accepted with MOOCHY_INSECURE_DEV=1"));
    }
    let trust = match (&r.ca_file, &r.cert_sha256) {
        (Some(_), Some(_)) => return Err(usage("--ca-file or --cert-sha256, not both")),
        (Some(f), None) => {
            let pem = std::fs::read_to_string(f).map_err(|e| usage(format!("--ca-file {}: {e}", f.display())))?;
            format!("ca:{}", crate::util::b64e(&pem_cert(&pem).ok_or_else(|| usage("--ca-file has no PEM certificate"))?))
        }
        (None, Some(h)) => format!("sha256:{}", h.trim().replace(':', "").to_ascii_lowercase()).chars().take(71).collect::<String>(),
        (None, None) => "roots".to_owned(),
    };
    if r.cert_sha256.as_deref().is_some_and(|h| hex32(h).is_none()) {
        return Err(usage("--cert-sha256 is the SHA-256 of the server certificate: 64 hex digits"));
    }
    if r.auth_header.is_some() && !key_stdin {
        return Err(usage("--header-from-keystore needs the header value on stdin (--key-stdin)"));
    }
    let key = if key_stdin {
        let mut raw = zeroize::Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut std::io::Read::take(std::io::stdin(), 4097), &mut raw).map_err(|e| usage(format!("read stdin: {e}")))?;
        let k = zeroize::Zeroizing::new(std::str::from_utf8(&raw).map_err(|_| usage("secret must be UTF-8"))?.trim().to_owned());
        if raw.len() > 4096 || k.is_empty() || !k.bytes().all(|c| c.is_ascii_graphic() || c == b' ') {
            return Err(usage("secret must be printable ASCII, at most 4 KiB"));
        }
        k
    } else {
        zeroize::Zeroizing::new(String::new())
    };
    let mut map = std::collections::BTreeMap::new();
    for m in models {
        let (slug, id) = m.split_once('=').ok_or_else(|| usage("--model is local/<slug>=<server model id>"))?;
        if !slug.starts_with("local/") || !crate::node::plain_id(slug) || !crate::node::plain_id(id) || moochy_worker::firewall::is_cloud_routed(id) {
            return Err(usage(format!("--model {m}: local/<slug>=<server id>, plain ids, not a cloud-routed model")));
        }
        map.insert(slug.to_owned(), id.to_owned());
    }
    if map.is_empty() {
        return Err(usage("a remote server needs at least one --model local/<slug>=<server model id>"));
    }
    let mut p = crate::keystore::ProviderKey {
        provider: "local".into(),
        key: key.to_string(),
        base_url: Some(url.to_owned()),
        allow_unvetted_host: allow_unvetted,
        models: map.clone(),
        served_ids: Vec::new(),
        remote_host: Some(r.host.clone()),
        trust: Some(trust),
        auth_header: r.auth_header.clone(),
    };
    // The whole configuration is checked by the worker before the donor is asked anything.
    let opts = local_options(&p, allow_unvetted).map_err(usage)?;
    let cfg = moochy_worker::provider::AdapterConfig {
        provider: moochy_worker::Provider::Local,
        api_key: zeroize::Zeroizing::new(if p.auth_header.is_some() { String::new() } else { key.to_string() }),
        base_url: Some(url.to_owned()),
        insecure_dev: false,
        dev_root: None,
        limits: moochy_worker::provider::Limits::local(),
    };
    moochy_worker::provider::check_local_url(url, &opts).map_err(|e| usage(format!("--url: {e}")))?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| net(format!("runtime: {e}")))?;
    rt.block_on(async { moochy_worker::provider::Adapter::new_local_with(&cfg, &opts).map(drop) }).map_err(|e| usage(format!("remote server: {e}")))?;
    // The donor states the exact host is theirs: requests (prompts) will be sent to it.
    eprintln!("Remote model server {} (certificate check: {}{}).", r.host, trust_name(&p), p.auth_header.as_deref().map(|h| format!(", header {h} from the keystore")).unwrap_or_default());
    eprintln!("Prompts of the projects you donate to will be sent to this server. Only add a server you control.");
    let confirmed = match &r.confirm_host {
        Some(c) => c.trim() == r.host,
        None => crate::owner::ask(&format!("Type {} to confirm it is your server: ", r.host), false)?.trim() == r.host,
    };
    if !confirmed {
        return Err(usage("host not confirmed; nothing stored"));
    }
    let mut cfgf = home.load()?;
    let mut sec = crate::keystore::load_or_init(home, &mut cfgf)?;
    sec.providers.retain(|x| x.provider != "local");
    p.models = map.clone();
    sec.providers.push(p);
    crate::keystore::save(home, &cfgf, &sec)?;
    crate::util::emit(&serde_json::json!({"event": "key_added", "provider": "local", "remote": r.host, "models": map}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_pins() {
        assert_eq!(hex32(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(hex32(&"AB:".repeat(32)), Some([0xab; 32]));
        assert!(hex32("abc").is_none());
        assert!(hex32(&"zz".repeat(32)).is_none());
        assert_eq!(pem_cert("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"), Some(vec![1, 2, 3]));
        assert!(pem_cert("no pem").is_none());
    }

    #[test]
    fn base_url_and_credentials() {
        assert!(check_base_url("http://127.0.0.1:9", true).is_ok());
        assert!(check_base_url("http://[::1]:9", true).is_ok());
        assert!(check_base_url("http://127.0.0.1:9", false).is_err());
        assert!(check_base_url("http://localhost:9", true).is_err());
        assert!(check_base_url("http://10.255.255.1:1", true).is_err());
        assert!(check_base_url("http://127.0.0.1:9/v1", true).is_err());
        assert!(refuse_consumer_credential("anthropic", "sk-ant-oat01-xxxx").is_err());
        assert!(refuse_consumer_credential("anthropic", "sk-ant-api03-xxxx").is_ok());
    }
}
