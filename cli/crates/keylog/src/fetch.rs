//! Blocking tile fetcher (feature `http`): HTTP/1.0 GET (no chunked encoding to parse)
//! over std `TcpStream`, TLS via rustls (ring, webpki roots) for `https://`. Every
//! response is size-bounded before it is buffered, and every step has a deadline.

use crate::{
    Error,
    mirror::{Alert, Mirror},
    tiles::{MAX_BUNDLE_BYTES, MAX_CHECKPOINT_BYTES, bundles, parse_bundle},
};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_HEADER_BYTES: usize = 16 * 1024;

/// A log endpoint: `http(s)://host[:port]/prefix/` (e.g. `https://moochy.dev/log/`).
#[derive(Clone)]
pub struct Fetcher {
    host: String,
    authority: String,
    addr: String,
    prefix: String,
    timeout: Duration,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

fn io(e: impl std::fmt::Display) -> Error {
    Error::Io(e.to_string())
}

impl Fetcher {
    /// `timeout` bounds each request end to end (connect, TLS, send, receive).
    pub fn new(base: &str, timeout: Duration) -> Result<Self, Error> {
        Self::with_roots(
            base,
            timeout,
            rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
        )
    }

    /// Like [`Fetcher::new`] but trusting only `roots` for `https://` (e.g. the
    /// relay CA a dev Node pins with `--ca-file`).
    pub fn with_roots(
        base: &str,
        timeout: Duration,
        roots: rustls::RootCertStore,
    ) -> Result<Self, Error> {
        let (tls, rest) = if let Some(r) = base.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = base.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(Error::Format("url scheme"));
        };
        let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
        if authority.is_empty()
            || authority.contains(['@', '?', '#'])
            || path.contains(['?', '#'])
            || base.chars().any(char::is_control)
        {
            return Err(Error::Format("url"));
        }
        let host = match authority.strip_prefix('[') {
            Some(v6) => v6
                .split_once(']')
                .map(|(h, _)| h)
                .ok_or(Error::Format("url host"))?,
            None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
        };
        let has_port = authority.rsplit_once(':').is_some_and(|(h, p)| {
            !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) && !h.ends_with(':')
        });
        let addr = if has_port {
            authority.to_owned()
        } else {
            format!("{authority}:{}", if tls { 443 } else { 80 })
        };
        let mut prefix = format!("/{path}");
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        let tls_config = if tls {
            let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io)?
            .with_root_certificates(roots)
            .with_no_client_auth();
            Some(Arc::new(cfg))
        } else {
            None
        };
        Ok(Self {
            host: host.to_owned(),
            authority: authority.to_owned(),
            addr,
            prefix,
            timeout,
            tls_config,
        })
    }

    /// GET `prefix + path`; 200 only; body ≤ `max` bytes.
    pub fn get(&self, path: &str, max: usize) -> Result<Vec<u8>, Error> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(Error::Io("timeout".into()))?;
        let left = || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::Io("timeout".into()))
        };
        let mut last = Error::Io("no address".into());
        let mut sock = None;
        for a in self.addr.to_socket_addrs().map_err(io)? {
            match TcpStream::connect_timeout(&a, left()?) {
                Ok(s) => {
                    sock = Some(s);
                    break;
                }
                Err(e) => last = io(e),
            }
        }
        let sock = sock.ok_or(last)?;
        sock.set_nodelay(true).map_err(io)?;
        let req = format!(
            "GET {}{} HTTP/1.0\r\nHost: {}\r\nUser-Agent: moochy-keylog\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            self.prefix, path, self.authority
        );
        let limit = max.saturating_add(MAX_HEADER_BYTES);
        let raw = match &self.tls_config {
            Some(cfg) => {
                let name =
                    rustls::pki_types::ServerName::try_from(self.host.clone()).map_err(io)?;
                let conn = rustls::ClientConnection::new(Arc::clone(cfg), name).map_err(io)?;
                exchange(
                    rustls::StreamOwned::new(conn, sock.try_clone().map_err(io)?),
                    &sock,
                    req.as_bytes(),
                    limit,
                    left,
                )?
            }
            None => exchange(
                sock.try_clone().map_err(io)?,
                &sock,
                req.as_bytes(),
                limit,
                left,
            )?,
        };
        parse_response(&raw, max)
    }

    /// One sync round: fetch + verify the checkpoint, fetch the missing entry bundles,
    /// and grow the mirror (all-or-nothing). The caller persists `records` (for
    /// [`Mirror::restore`]) and acts on `alerts`.
    pub fn sync(&self, m: &mut Mirror) -> Result<Synced, Error> {
        let note = self.get("checkpoint", MAX_CHECKPOINT_BYTES)?;
        let checkpoint = m.open_checkpoint(&note)?;
        let mut records = Vec::new();
        for b in bundles(m.size(), checkpoint.size) {
            let data = self.get(&b.path(), MAX_BUNDLE_BYTES)?;
            let skip = usize::try_from(b.skip).map_err(|_| Error::TooLarge)?;
            records.extend(
                parse_bundle(&data, b.width)?
                    .into_iter()
                    .skip(skip)
                    .map(<[u8]>::to_vec),
            );
        }
        let refs: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
        let alerts = m.update(&checkpoint, &refs)?;
        Ok(Synced {
            checkpoint,
            note,
            records,
            alerts,
        })
    }
}

/// The outcome of [`Fetcher::sync`].
#[derive(Debug)]
pub struct Synced {
    pub checkpoint: crate::Checkpoint,
    /// The signed checkpoint note (persist it with the records).
    pub note: Vec<u8>,
    /// The new records, in log order.
    pub records: Vec<Vec<u8>>,
    pub alerts: Vec<Alert>,
}

fn exchange(
    mut s: impl Read + Write,
    sock: &TcpStream,
    req: &[u8],
    limit: usize,
    left: impl Fn() -> Result<Duration, Error>,
) -> Result<Vec<u8>, Error> {
    sock.set_write_timeout(Some(left()?)).map_err(io)?;
    s.write_all(req).map_err(io)?;
    s.flush().map_err(io)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        sock.set_read_timeout(Some(left()?)).map_err(io)?;
        let n = match s.read(&mut buf) {
            Ok(n) => n,
            // A peer closing TLS without close_notify after a complete HTTP/1.0 body.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(io(e)),
        };
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(buf.get(..n).unwrap_or_default());
        if out.len() > limit {
            return Err(Error::TooLarge);
        }
    }
}

fn parse_response(raw: &[u8], max: usize) -> Result<Vec<u8>, Error> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(Error::Io("bad response".into()))?;
    let head = std::str::from_utf8(raw.get(..end).unwrap_or_default())
        .map_err(|_| Error::Io("bad response".into()))?;
    let body = raw.get(end.saturating_add(4)..).unwrap_or_default();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !(status.starts_with("HTTP/1.0 200 ")
        || status.starts_with("HTTP/1.1 200 ")
        || status == "HTTP/1.1 200"
        || status == "HTTP/1.0 200")
    {
        return Err(Error::Io(format!(
            "status: {}",
            status
                .chars()
                .take(40)
                .filter(|c| !c.is_control())
                .collect::<String>()
        )));
    }
    for l in lines {
        let (k, v) = l.split_once(':').ok_or(Error::Io("bad header".into()))?;
        let v = v.trim();
        if k.eq_ignore_ascii_case("transfer-encoding")
            || (k.eq_ignore_ascii_case("content-encoding") && v != "identity")
        {
            return Err(Error::Io("unsupported encoding".into()));
        }
        if k.eq_ignore_ascii_case("content-length") && v.parse::<usize>().ok() != Some(body.len()) {
            return Err(Error::Io("truncated body".into()));
        }
    }
    if body.len() > max {
        return Err(Error::TooLarge);
    }
    Ok(body.to_vec())
}
