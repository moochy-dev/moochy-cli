//! TLS 1.3 client (rustls + ring), RFC 9266 channel binding, and a tiny HTTPS JSON client.

use crate::util::{Ctx as _, Result, b64d, internal, net, usage};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A relay origin, always carrying an explicit port: `wss://host:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Parse `wss://host[:port][/]`. Only `wss` is accepted: the relay link is always TLS.
    pub fn parse(url: &str) -> Result<Self> {
        let rest = url.strip_prefix("wss://").ok_or_else(|| usage("relay URL must start with wss://"))?;
        let auth = rest.strip_suffix('/').unwrap_or(rest);
        if auth.is_empty() || auth.contains(['/', '?', '#', '@']) {
            return Err(usage("relay URL must be wss://host[:port]"));
        }
        let (host, port) = if let Some(v6) = auth.strip_prefix('[') {
            let (h, p) = v6.split_once(']').ok_or_else(|| usage("bad IPv6 relay host"))?;
            (h, p.strip_prefix(':'))
        } else {
            match auth.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (auth, None),
            }
        };
        let port = match port {
            Some(p) => p.parse().map_err(|_| usage("bad relay port"))?,
            None => 443,
        };
        if host.is_empty() || port == 0 {
            return Err(usage("bad relay host"));
        }
        Ok(Self { host: host.to_ascii_lowercase(), port })
    }

    fn host_part(&self) -> String {
        if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() }
    }
    /// `host:port` (Host header / authority).
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host_part(), self.port)
    }
    /// The dialed origin bound into the auth signature (CONTRACT §3).
    pub fn wss(&self) -> String {
        format!("wss://{}", self.authority())
    }
}

pub fn client_config(ca_file: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    match ca_file {
        Some(p) => {
            let certs = CertificateDer::pem_file_iter(p).map_err(|e| usage(format!("--ca-file {}: {e}", p.display())))?;
            for c in certs {
                roots.add(c.map_err(|e| usage(format!("--ca-file: {e}")))?).map_err(|e| usage(format!("--ca-file: {e}")))?;
            }
            if roots.is_empty() {
                return Err(usage("--ca-file contains no certificate"));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ctx("tls config")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub async fn connect(cfg: &Arc<ClientConfig>, o: &Origin) -> Result<TlsStream<TcpStream>> {
    let name = ServerName::try_from(o.host.clone()).map_err(|_| usage("bad relay host name"))?;
    let tcp = timeout(IO_TIMEOUT, TcpStream::connect((o.host.as_str(), o.port)))
        .await
        .map_err(|_| net("relay connect timeout"))?
        .map_err(|e| net(format!("relay connect: {e}")))?;
    let _ = tcp.set_nodelay(true);
    timeout(IO_TIMEOUT, TlsConnector::from(cfg.clone()).connect(name, tcp))
        .await
        .map_err(|_| net("TLS handshake timeout"))?
        .map_err(|e| net(format!("TLS: {e}")))
}

/// RFC 9266 `tls-exporter` channel binding value (32 bytes, empty context).
pub fn exporter(s: &TlsStream<TcpStream>) -> Result<[u8; 32]> {
    s.get_ref().1.export_keying_material([0u8; 32], b"EXPORTER-Channel-Binding", Some(&[])).ctx("tls exporter")
}

/// POST a JSON body over HTTPS, return `(status, strict-parsed JSON body)`.
pub async fn post_json(cfg: &Arc<ClientConfig>, o: &Origin, path: &str, body: &Value) -> Result<(u16, Value)> {
    let tls = connect(cfg, o).await?;
    let (mut tx, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls))
        .await
        .map_err(|e| net(format!("http: {e}")))?;
    let conn = tokio::spawn(conn);
    let req = hyper::Request::post(path)
        .header(hyper::header::HOST, o.authority())
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .ctx("build request")?;
    let resp = timeout(IO_TIMEOUT, tx.send_request(req)).await.map_err(|_| net("relay timeout"))?.map_err(|e| net(format!("http: {e}")))?;
    let status = resp.status().as_u16();
    let bytes = timeout(IO_TIMEOUT, Limited::new(resp.into_body(), 64 * 1024).collect())
        .await
        .map_err(|_| net("relay timeout"))?
        .map_err(|e| net(format!("http body: {e}")))?
        .to_bytes();
    conn.abort();
    let v = if bytes.is_empty() { Value::Null } else { crate::json::parse(&bytes).map_err(|e| internal(format!("relay sent bad JSON: {e}")))? };
    Ok((status, v))
}

/// Decode a base64url field to exactly `N` bytes.
pub fn field_bytes<const N: usize>(v: &Value, k: &str) -> Option<[u8; N]> {
    b64d(v.get(k)?.as_str()?)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::Origin;

    #[test]
    fn origins() {
        assert_eq!(Origin::parse("wss://127.0.0.1:8443").unwrap().wss(), "wss://127.0.0.1:8443");
        assert_eq!(Origin::parse("wss://Relay.Moochy.dev/").unwrap().wss(), "wss://relay.moochy.dev:443");
        assert_eq!(Origin::parse("wss://[::1]:9").unwrap().wss(), "wss://[::1]:9");
        assert!(Origin::parse("ws://x").is_err());
        assert!(Origin::parse("wss://x/path").is_err());
        assert!(Origin::parse("wss://u@x").is_err());
        assert!(Origin::parse("wss://x:0").is_err());
    }
}
