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

/// Provider origin and models path (relative to the origin).
fn endpoint(provider: &str) -> Option<(&'static str, &'static str)> {
    Some(match provider {
        "anthropic" => ("https://api.anthropic.com", "/v1/models"),
        "openai" => ("https://api.openai.com", "/v1/models"),
        "deepseek" => ("https://api.deepseek.com", "/models"),
        "openrouter" => ("https://openrouter.ai", "/api/v1/models"),
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
    let origin = base_url.unwrap_or(origin).trim_end_matches('/');
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
    req = if provider == "anthropic" { req.header("x-api-key", key).header("anthropic-version", "2023-06-01") } else { req.header("authorization", format!("Bearer {key}")) };
    let req = req.body(Empty::<Bytes>::new()).map_err(|e| usage(format!("bad request: {e}")))?;
    let tcp = timeout(TIMEOUT, tokio::net::TcpStream::connect((host.as_str(), port))).await.map_err(|_| net("provider connect timeout"))?.map_err(|e| net(format!("provider connect: {e}")))?;
    let _ = tcp.set_nodelay(true);
    let status = if scheme == "https" {
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| net(format!("tls: {e}")))?
            .with_root_certificates(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| usage("bad provider host"))?;
        let tls = timeout(TIMEOUT, tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp)).await.map_err(|_| net("TLS timeout"))?.map_err(|e| net(format!("TLS: {e}")))?;
        get(TokioIo::new(tls), req).await?
    } else {
        get(TokioIo::new(tcp), req).await?
    };
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(auth(format!("{provider} rejected the key ({status}); nothing was stored"))),
        s => Err(net(format!("{provider} models endpoint answered {s}; key not validated, nothing stored"))),
    }
}

async fn get<T>(io: TokioIo<T>, req: hyper::Request<Empty<Bytes>>) -> Result<u16>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut tx, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| net(format!("http: {e}")))?;
    let c = tokio::spawn(conn);
    let resp = timeout(TIMEOUT, tx.send_request(req)).await.map_err(|_| net("provider timeout"))?.map_err(|e| net(format!("http: {e}")))?;
    let status = resp.status().as_u16();
    // Drain (bounded) so the connection closes cleanly; the content is not needed.
    let _ = timeout(TIMEOUT, Limited::new(resp.into_body(), 1 << 20).collect()).await;
    c.abort();
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

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
