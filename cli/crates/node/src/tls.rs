//! TLS 1.3 client (rustls + ring, ALPN h2) and RFC 9266 channel binding for the gRPC link.

use crate::util::{Ctx as _, Result, net, usage};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A relay origin, always carrying an explicit port: `https://host:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Parse `https://host[:port][/]`. Only TLS is accepted: the relay link is always TLS.
    pub fn parse(url: &str) -> Result<Self> {
        let rest = url.strip_prefix("https://").ok_or_else(|| usage("relay URL must start with https://"))?;
        let auth = rest.strip_suffix('/').unwrap_or(rest);
        if auth.is_empty() || auth.contains(['/', '?', '#', '@']) {
            return Err(usage("relay URL must be https://host[:port]"));
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
    /// The dialed origin bound into the auth signature (CONTRACT §3): `https://host:port`
    /// exactly as dialed, port always explicit.
    pub fn url(&self) -> String {
        format!("https://{}", self.authority())
    }
}

/// The relay's trust roots: `--ca-file` alone (development), else the web PKI.
pub fn roots(ca_file: Option<&Path>) -> Result<RootCertStore> {
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
    Ok(roots)
}

pub fn client_config(ca_file: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let roots = roots(ca_file)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ctx("tls config")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
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

#[cfg(test)]
mod tests {
    use super::Origin;

    #[test]
    fn origins() {
        assert_eq!(Origin::parse("https://127.0.0.1:8443").unwrap().url(), "https://127.0.0.1:8443");
        assert_eq!(Origin::parse("https://Relay.Moochy.dev/").unwrap().url(), "https://relay.moochy.dev:443");
        assert_eq!(Origin::parse("https://[::1]:9").unwrap().url(), "https://[::1]:9");
        assert!(Origin::parse("http://x").is_err());
        assert!(Origin::parse("https://x/path").is_err());
        assert!(Origin::parse("https://u@x").is_err());
        assert!(Origin::parse("https://x:0").is_err());
    }
}
