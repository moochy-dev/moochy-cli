//! `--allow-host`: a client-side HTTP CONNECT proxy with an exact-host
//! allowlist (CONTRACT §15.1, off by default). Runs in the launcher, outside the
//! sandbox, on a Unix socket bind-mounted at [`crate::PROXY_SOCK_PATH`]; the agent
//! reaches it only through the reaper's bridge on
//! `127.0.0.1:`[`crate::PROXY_LOOPBACK_PORT`] (`HTTPS_PROXY` points there).
//!
//! Policy (fail closed):
//! - only `CONNECT <host>:443`; anything else → 405/400;
//! - `host` must equal an allowlist entry (exact DNS name, case-insensitive; no
//!   wildcards, no IP literals);
//! - every address `host` resolves to must be public: a name that resolves to
//!   loopback, private, link-local, CGNAT, ULA, multicast… is refused (DNS
//!   rebinding onto the gateway, the host's services or cloud metadata), and
//!   the tunnel connects to the checked address itself (no second lookup);
//! - head ≤ 8 KiB read within 10 s, upstream connect ≤ 10 s, ≤ 64 tunnels.

use std::io::Write as _;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const HEAD_MAX: usize = 8 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TUNNELS: usize = 64;
const PORT: u16 = 443;

/// Lower-cased exact host names (`registry.npmjs.org`).
#[derive(Clone, Debug, Default)]
pub struct Allowlist(Vec<String>);

impl Allowlist {
    /// Fails on the first entry that is not an exact DNS host name (so a typo
    /// or `*.x` never silently widens or narrows what the user asked for).
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>>(hosts: I) -> Result<Self, crate::Error> {
        let mut v = Vec::new();
        for h in hosts {
            let h = h.as_ref().trim().to_ascii_lowercase();
            if !valid_name(&h) {
                return Err(crate::Error::Setup {
                    what: "--allow-host",
                    err: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("not an exact DNS host name: {h:?}"),
                    ),
                });
            }
            v.push(h);
        }
        Ok(Self(v))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exact (case-insensitive) match only.
    #[must_use]
    pub fn allows(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        valid_name(&host) && self.0.contains(&host)
    }
}

/// A DNS name: labels of `[a-z0-9-]`, not starting/ending with `-`, at least
/// one dot, ≤ 253 bytes, and not all-numeric (no IP literals).
fn valid_name(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && !h.split('.').all(|l| l.bytes().all(|b| b.is_ascii_digit()))
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// True for addresses a tunnel may reach: globally routable unicast only.
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254/16: cloud metadata lives here
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
                || o[0] >= 240) // reserved
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 (could reach v4 private)
                || s[0] == 0) // ::/16 incl. v4-compatible
        }
    }
}

/// Outcome of parsing one request head.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Tunnel to this (allowlisted) host on :443.
    Connect(String),
    /// A well-formed request for a host outside the allowlist (403). The name
    /// is a validated DNS name, safe to print.
    NotAllowed(String),
    /// Refuse with this status line.
    Refuse(&'static str),
}

/// Decide on a request head (everything up to the blank line).
#[must_use]
pub fn judge(head: &[u8], allow: &Allowlist) -> Verdict {
    let Ok(text) = std::str::from_utf8(head) else { return Verdict::Refuse("400 Bad Request") };
    let line = text.split("\r\n").next().unwrap_or("");
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Verdict::Refuse("400 Bad Request");
    };
    if !version.starts_with("HTTP/1.") {
        return Verdict::Refuse("400 Bad Request");
    }
    if method != "CONNECT" {
        return Verdict::Refuse("405 Method Not Allowed");
    }
    let Some((host, port)) = target.rsplit_once(':') else { return Verdict::Refuse("400 Bad Request") };
    if port != "443" {
        return Verdict::Refuse("403 Forbidden");
    }
    let host = host.to_ascii_lowercase();
    if allow.allows(&host) {
        Verdict::Connect(host)
    } else if valid_name(&host) {
        Verdict::NotAllowed(host)
    } else {
        Verdict::Refuse("403 Forbidden")
    }
}

/// The proxy of one run, served on its own thread from before the sandbox is
/// spawned, stopped when dropped. Linux: a Unix socket (bind-mounted into the
/// view, reached through the reaper's bridge). macOS: a loopback TCP port (the
/// Seatbelt profile allows exactly that port; no netns there).
pub(crate) struct Proxy {
    wake: Wake,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

enum Wake {
    Unix(PathBuf),
    Tcp(SocketAddr),
}

/// A connection the proxy can serve (Unix or loopback TCP).
trait Stream: std::io::Read + std::io::Write + Send + Sized + 'static {
    fn set_read_timeout(&self, d: Option<Duration>) -> std::io::Result<()>;
    fn try_clone(&self) -> std::io::Result<Self>;
    fn shutdown_write(&self) -> std::io::Result<()>;
}

macro_rules! impl_stream {
    ($t:ty) => {
        impl Stream for $t {
            fn set_read_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
                <$t>::set_read_timeout(self, d)
            }
            fn try_clone(&self) -> std::io::Result<Self> {
                <$t>::try_clone(self)
            }
            fn shutdown_write(&self) -> std::io::Result<()> {
                <$t>::shutdown(self, std::net::Shutdown::Write)
            }
        }
    };
}
impl_stream!(UnixStream);
impl_stream!(TcpStream);

impl Proxy {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn bind(sock: PathBuf, allow: Allowlist) -> Result<Self, crate::Error> {
        let l = UnixListener::bind(&sock).map_err(|err| crate::Error::Setup { what: "bind --allow-host proxy", err })?;
        Ok(Self::spawn(Wake::Unix(sock), move |stop| serve(l.incoming(), &allow, &stop)))
    }

    /// `127.0.0.1:<ephemeral>`; the port is [`Proxy::port`].
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(crate) fn bind_loopback(allow: Allowlist) -> Result<Self, crate::Error> {
        let err = |err| crate::Error::Setup { what: "bind --allow-host proxy", err };
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(err)?;
        let addr = l.local_addr().map_err(err)?;
        Ok(Self::spawn(Wake::Tcp(addr), move |stop| {
            serve(l.incoming().map(|c| c.and_then(|c| c.set_nodelay(true).map(|()| c))), &allow, &stop);
        }))
    }

    fn spawn(wake: Wake, f: impl FnOnce(Arc<AtomicBool>) + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = Arc::clone(&stop);
        Self { wake, stop, thread: Some(std::thread::spawn(move || f(s2))) }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn sock(&self) -> Option<&std::path::Path> {
        match &self.wake {
            Wake::Unix(p) => Some(p),
            Wake::Tcp(_) => None,
        }
    }

    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(crate) fn port(&self) -> Option<u16> {
        match &self.wake {
            Wake::Tcp(a) => Some(a.port()),
            Wake::Unix(_) => None,
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            // Wake the accept loop.
            match &self.wake {
                Wake::Unix(p) => drop(UnixStream::connect(p)),
                Wake::Tcp(a) => drop(TcpStream::connect_timeout(a, Duration::from_secs(1))),
            }
            let _ = t.join();
        }
    }
}

/// Serve accepted connections until `stop` is set (then one more connection
/// wakes the accept loop). Blocking. Live tunnels end when their client does.
fn serve<S: Stream>(incoming: impl Iterator<Item = std::io::Result<S>>, allow: &Allowlist, stop: &AtomicBool) {
    let live = Arc::new(AtomicUsize::new(0));
    for conn in incoming {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let Ok(conn) = conn else { continue };
        if live.load(Ordering::Relaxed) >= MAX_TUNNELS {
            continue; // drop: bounded
        }
        live.fetch_add(1, Ordering::Relaxed);
        let (allow, live) = (allow.clone(), Arc::clone(&live));
        std::thread::spawn(move || {
            let _ = handle(conn, &allow);
            live.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn handle<S: Stream>(mut c: S, allow: &Allowlist) -> std::io::Result<()> {
    c.set_read_timeout(Some(HEAD_TIMEOUT))?;
    let mut head = Vec::with_capacity(512);
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = c.read(&mut buf)?;
        if n == 0 || head.len().saturating_add(n) > HEAD_MAX {
            return refuse(&mut c, "400 Bad Request");
        }
        head.extend_from_slice(buf.get(..n).unwrap_or(&[]));
    }
    let host = match judge(&head, allow) {
        Verdict::Connect(h) => h,
        Verdict::NotAllowed(h) => {
            eprintln!("moochy: --allow-host proxy refused {h}:443 (not in the allowlist)");
            return refuse(&mut c, "403 Forbidden");
        }
        Verdict::Refuse(status) => return refuse(&mut c, status),
    };
    // Resolve, then require every address to be public (anti-rebinding: one
    // private answer refuses the whole name).
    let addrs: Vec<SocketAddr> = match (host.as_str(), PORT).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => return refuse(&mut c, "502 Bad Gateway"),
    };
    if addrs.is_empty() || !addrs.iter().all(|a| is_public(a.ip())) {
        eprintln!("moochy: --allow-host proxy refused {host}:443 (resolves to a non-public address)");
        return refuse(&mut c, "403 Forbidden");
    }
    let Some(up) = addrs.iter().find_map(|a| TcpStream::connect_timeout(a, CONNECT_TIMEOUT).ok()) else {
        return refuse(&mut c, "502 Bad Gateway");
    };
    up.set_nodelay(true)?;
    c.set_read_timeout(None)?;
    c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    // Bytes the client sent after the head belong to the tunnel.
    let mut up_w = up.try_clone()?;
    if let Some(pos) = head.windows(4).position(|w| w == b"\r\n\r\n") {
        let rest = head.get(pos.saturating_add(4)..).unwrap_or(&[]);
        up_w.write_all(rest)?;
    }
    let mut c_r = c.try_clone()?;
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c_r, &mut up_w);
        let _ = up_w.shutdown(std::net::Shutdown::Write);
    });
    let mut up_r = up;
    let _ = std::io::copy(&mut up_r, &mut c);
    let _ = c.shutdown_write();
    let _ = t.join();
    Ok(())
}

fn refuse(c: &mut impl std::io::Write, status: &str) -> std::io::Result<()> {
    // One write: the client sees the whole status line in its first read.
    c.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_exact_only() {
        let a = Allowlist::new(["registry.npmjs.org", " PyPI.org "]).unwrap();
        assert!(a.allows("registry.npmjs.org"));
        assert!(a.allows("REGISTRY.NPMJS.ORG"));
        assert!(a.allows("pypi.org"));
        assert!(!a.allows("files.pypi.org"), "no implicit subdomains");
        assert!(!a.allows("evil-registry.npmjs.org"));
        assert!(!a.allows("registry.npmjs.org.evil.com"));
        assert!(!a.allows("npmjs.org"));
        for bad in ["*.pypi.org", "BAD HOST", "1.2.3.4", "example.com.", "localhost", "-a.com", "a..com", "\u{1b}[2J.com", ""] {
            assert!(Allowlist::new([bad]).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn judge_only_connect_443_to_allowed_names() {
        let a = Allowlist::new(["example.com"]).unwrap();
        assert_eq!(judge(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", &a), Verdict::Connect("example.com".into()));
        assert_eq!(judge(b"CONNECT example.com:22 HTTP/1.1\r\n\r\n", &a), Verdict::Refuse("403 Forbidden"));
        assert_eq!(judge(b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n", &a), Verdict::NotAllowed("evil.com".into()));
        assert_eq!(judge(b"CONNECT \x1b[2J.com:443 HTTP/1.1\r\n\r\n", &a), Verdict::Refuse("403 Forbidden"));
        assert_eq!(judge(b"GET http://example.com/ HTTP/1.1\r\n\r\n", &a), Verdict::Refuse("405 Method Not Allowed"));
        assert_eq!(judge(b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n", &a), Verdict::Refuse("403 Forbidden"));
        assert_eq!(judge(b"CONNECT example.com:443 HTTP/1.1 x\r\n\r\n", &a), Verdict::Refuse("400 Bad Request"));
        assert_eq!(judge(b"\xff\xfe", &a), Verdict::Refuse("400 Bad Request"));
    }

    #[test]
    fn only_public_addresses() {
        for bad in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
                    "224.0.0.1", "255.255.255.255", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "::"] {
            assert!(!is_public(bad.parse().unwrap()), "{bad} treated as public");
        }
        for good in ["1.1.1.1", "160.79.104.10", "2606:4700::1111", "2607:6bc0::10"] {
            assert!(is_public(good.parse().unwrap()), "{good} treated as private");
        }
    }
}
