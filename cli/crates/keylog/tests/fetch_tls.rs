//! The `http` feature's TLS path against a local rustls server: a pinned CA works,
//! the public roots refuse the private CA, size caps and timeouts hold.
#![cfg(feature = "http")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use moochy_keylog::{Error, fetch::Fetcher};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const CA: &[u8] = include_bytes!("data/ca.der");
const LEAF: &[u8] = include_bytes!("data/leaf.der");
const KEY: &[u8] = include_bytes!("data/leaf.key.der"); // test-only key, never used elsewhere

/// A TLS 1.3 server answering every request with `reply(path)`; `stall` never answers.
fn server(reply: fn(&str) -> Vec<u8>, stall: bool) -> String {
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(LEAF.to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
    )
    .unwrap();
    let cfg = Arc::new(cfg);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let cfg = Arc::clone(&cfg);
            thread::spawn(move || {
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, s);
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.ends_with(b"\r\n\r\n") {
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                if stall {
                    thread::sleep(Duration::from_secs(5));
                    return;
                }
                let line = String::from_utf8_lossy(&req);
                let path = line.split(' ').nth(1).unwrap_or("").to_owned();
                let body = reply(&path);
                let _ = write!(
                    tls,
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(&body);
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    format!("https://127.0.0.1:{}/log/", addr.port())
}

fn pinned() -> rustls::RootCertStore {
    let mut r = rustls::RootCertStore::empty();
    r.add(CertificateDer::from(CA.to_vec())).unwrap();
    r
}

#[test]
fn tls_pinned_ca_size_cap_and_timeout() {
    let base = server(|p| format!("you asked for {p}").into_bytes(), false);
    let f = Fetcher::with_roots(&base, Duration::from_secs(5), pinned()).unwrap();
    assert_eq!(
        f.get("checkpoint", 1024).unwrap(),
        b"you asked for /log/checkpoint"
    );
    assert_eq!(
        f.get("tile/0/000", 1024).unwrap(),
        b"you asked for /log/tile/0/000"
    );
    // Response larger than the caller's cap: refused before it is returned.
    assert_eq!(f.get("checkpoint", 8), Err(Error::TooLarge));

    // The public web roots do not trust a private CA: the TLS handshake fails.
    let public = Fetcher::new(&base, Duration::from_secs(5)).unwrap();
    assert!(matches!(public.get("checkpoint", 1024), Err(Error::Io(_))));

    // A server that never answers: the per-request deadline holds.
    let slow = server(|_| Vec::new(), true);
    let f = Fetcher::with_roots(&slow, Duration::from_millis(300), pinned()).unwrap();
    let t = Instant::now();
    assert!(matches!(f.get("checkpoint", 1024), Err(Error::Io(_))));
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "timeout not enforced: {:?}",
        t.elapsed()
    );
}
