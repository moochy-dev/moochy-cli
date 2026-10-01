//! Adapters against local fake providers: the dev HTTP/1.1 path (what the e2e fakes
//! speak) and the production HTTP/2 + TLS path (rcgen test CA). Real binaries, fake
//! providers only.
#![allow(clippy::panic, clippy::expect_used, clippy::format_collect, clippy::range_plus_one, clippy::cast_possible_truncation, clippy::assert_is_empty, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::too_many_lines, clippy::cast_precision_loss)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming};
use moochy_worker::firewall::{self, Catalog, Level, MaxPrice, Policy, Request};
use moochy_worker::provider::{Adapter, AdapterConfig, FailKind, Limits};
use moochy_worker::stream::StreamParser;
use moochy_worker::{Dialect, Effort, Flags, Provider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

const ANTH: &str = include_str!("fixtures/anthropic_tool.sse");
const OAI: &str = include_str!("fixtures/openai_tool.sse");
const XAI: &str = include_str!("fixtures/xai.sse");

#[derive(Clone)]
enum Mode {
    Sse(&'static str),
    Status(u16, &'static str, &'static str),
    SlowHeaders(u64),
    Hang,
}

struct Recorded {
    head: String,
    body: Vec<u8>,
}

struct Fake {
    addr: SocketAddr,
    reqs: mpsc::UnboundedReceiver<Recorded>,
    disconnected: mpsc::UnboundedReceiver<()>,
}

async fn read_request(s: &mut TcpStream) -> Option<Recorded> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let len: usize = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Some(Recorded { head, body })
}

async fn chunk(s: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    s.write_all(format!("{:x}\r\n", data.len()).as_bytes()).await?;
    s.write_all(data).await?;
    s.write_all(b"\r\n").await?;
    s.flush().await
}

/// Raw HTTP/1.1 fake: one request per connection, behaviour per `mode`.
async fn fake(mode: Mode) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (rtx, reqs) = mpsc::unbounded_channel();
    let (dtx, disconnected) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let (mode, rtx, dtx) = (mode.clone(), rtx.clone(), dtx.clone());
            tokio::spawn(async move {
                let Some(r) = read_request(&mut s).await else { return };
                rtx.send(r).unwrap();
                // One request per connection, so say so (the adapter pools keep-alive connections).
                const SSE_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\nx-ratelimit-limit-requests: 480\r\nx-ratelimit-remaining-requests: 120\r\nx-ratelimit-limit-tokens: 2000000\r\nx-ratelimit-remaining-tokens: 1000000\r\ntransfer-encoding: chunked\r\n\r\n";
                match mode {
                    Mode::Status(code, extra, body) => {
                        let resp = format!("HTTP/1.1 {code} X\r\ncontent-type: application/json\r\nconnection: close\r\n{extra}content-length: {}\r\n\r\n{body}", body.len());
                        let _ = s.write_all(resp.as_bytes()).await;
                    }
                    Mode::Sse(_) | Mode::SlowHeaders(_) => {
                        let body = match mode {
                            Mode::Sse(b) => b,
                            Mode::SlowHeaders(ms) => {
                                tokio::time::sleep(Duration::from_millis(ms)).await;
                                ANTH
                            }
                            _ => unreachable!(),
                        };
                        let _ = s.write_all(SSE_HEAD).await;
                        for ev in body.split_inclusive("\n\n") {
                            if chunk(&mut s, ev.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        let _ = s.write_all(b"0\r\n\r\n").await;
                    }
                    Mode::Hang => {
                        let _ = s.write_all(SSE_HEAD).await;
                        let _ = chunk(&mut s, b"event: ping\ndata: {\"type\":\"ping\"}\n\n").await;
                        let mut b = [0u8; 64];
                        loop {
                            match s.read(&mut b).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        let _ = dtx.send(());
                    }
                }
            });
        }
    });
    Fake { addr, reqs, disconnected }
}

fn adapter(p: Provider, base: String, limits: Limits) -> Adapter {
    Adapter::new(&AdapterConfig {
        provider: p,
        api_key: Zeroizing::new("sk-test-123".into()),
        base_url: Some(base),
        insecure_dev: true,
        dev_root: None,
        limits,
    })
    .unwrap()
}

const CAT: Catalog = Catalog { default_effort: Effort::High, max_output: 64_000, max_image_tokens: 1600 };
const POL: Policy = Policy { level: Level::Strict, flags: Flags::NONE, max_effort: Effort::Max };

fn prepare(p: Provider, d: Dialect, body: &str) -> firewall::Prepared {
    firewall::prepare(&Request {
        provider: p,
        dialect: d,
        body: body.as_bytes(),
        headers: &[("anthropic-version", "2023-06-01")][..usize::from(d == Dialect::AnthropicMessages)],
        policy: &POL,
        catalog: &CAT,
        provider_model_id: "provider-model",
        user_pseudonym: "ps_1",
        max_price: Some(MaxPrice { prompt_uusd_per_mtok: 1_000_000, completion_uusd_per_mtok: 2_000_000 }),
    })
    .unwrap()
}

const ABODY: &str = r#"{"model":"anthropic/claude-sonnet-5.5","max_tokens":100,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
const OBODY: &str = r#"{"model":"openai/gpt-5","max_tokens":100,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anthropic_stream_end_to_end() {
    let mut f = fake(Mode::Sse(ANTH)).await;
    let a = adapter(Provider::Anthropic, format!("http://{}", f.addr), Limits::default());
    let prep = prepare(Provider::Anthropic, Dialect::AnthropicMessages, ABODY);
    let mut resp = a.send(Dialect::AnthropicMessages, prep.body.clone(), &prep.headers).await.unwrap();
    assert_eq!(resp.status, 200);
    let mut p = StreamParser::new(Dialect::AnthropicMessages, true);
    let (mut got, mut chunks, mut ends) = (Vec::new(), 0, 0);
    while let Some(c) = resp.next().await.unwrap() {
        got.extend_from_slice(&c);
        chunks += 1;
        ends += p.feed(&c, &mut |_, _| {}).unwrap().tool_ends;
    }
    assert_eq!(got, ANTH.as_bytes(), "bytes forwarded unaltered");
    assert!(chunks >= 12, "flushed per event, not batched ({chunks})");
    assert_eq!(ends, 1);
    let o = p.finish();
    assert_eq!((o.usage.output, o.usage.cache_read, o.usage.estimated), (89, 2000, false));

    let r = f.reqs.recv().await.unwrap();
    assert!(r.head.starts_with("POST /v1/messages HTTP/1.1\r\n"), "{}", r.head);
    let h = r.head.to_ascii_lowercase();
    assert!(h.contains("x-api-key: sk-test-123\r\n") && h.contains("anthropic-version: 2023-06-01\r\n"), "{h}");
    assert!(!h.contains("authorization"));
    assert_eq!(r.body, prep.body.to_vec());
    assert!(std::str::from_utf8(&r.body).unwrap().contains(r#""metadata":{"user_id":"ps_1"}"#));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_paths_and_auth() {
    // The base URL is an origin; every adapter sends its own full path (the e2e fakes and
    // the real providers serve the same paths).
    for (p, d, want, body, sse) in [
        (Provider::DeepSeek, Dialect::AnthropicMessages, "POST /anthropic/v1/messages ", ABODY, ANTH),
        (Provider::DeepSeek, Dialect::OpenAiChat, "POST /chat/completions ", OBODY, OAI),
        (Provider::OpenRouter, Dialect::OpenAiChat, "POST /api/v1/chat/completions ", OBODY, OAI),
        (Provider::OpenRouter, Dialect::AnthropicMessages, "POST /api/v1/messages ", ABODY, ANTH),
        (Provider::OpenAi, Dialect::OpenAiChat, "POST /v1/chat/completions ", OBODY, OAI),
        (Provider::XAi, Dialect::OpenAiChat, "POST /v1/chat/completions ", OBODY, XAI),
    ] {
        let mut f = fake(Mode::Sse(sse)).await;
        let base = if p == Provider::OpenAi { format!("http://{}/", f.addr) } else { format!("http://{}", f.addr) };
        let a = adapter(p, base, Limits::default());
        let prep = prepare(p, d, body);
        a.warm().await.unwrap();
        let mut resp = a.send(d, prep.body, &prep.headers).await.unwrap();
        assert_eq!(resp.rate_limit.headroom_pct(), Some(25), "{p:?}: {:?}", resp.rate_limit);
        let mut parser = StreamParser::new(d, true);
        while let Some(c) = resp.next().await.unwrap() {
            parser.feed(&c, &mut |_, _| {}).unwrap();
        }
        let o = parser.finish();
        assert!(!o.usage.estimated, "{p:?} {o:?}");
        if p == Provider::XAi {
            assert_eq!((o.usage.output, o.usage.provider_cost_uusd), (280, Some(1235)));
        }
        let r = f.reqs.recv().await.unwrap();
        assert!(r.head.starts_with(want), "{p:?} {}", r.head);
        assert!(r.head.to_ascii_lowercase().contains("authorization: bearer sk-test-123\r\n"), "{p:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_statuses_map_to_nacks() {
    for (mode, kind, nack, retry) in [
        (Mode::Status(429, "retry-after: 3\r\nanthropic-ratelimit-requests-limit: 50\r\nanthropic-ratelimit-requests-remaining: 0\r\n", r#"{"type":"error","error":{"type":"rate_limit_error"}}"#), FailKind::RateLimited, ("rate_limited", true), Some(3000)),
        (Mode::Status(429, "retry-after-ms: 250\r\n", "{}"), FailKind::RateLimited, ("rate_limited", true), Some(250)),
        (Mode::Status(529, "", r#"{"type":"error","error":{"type":"overloaded_error"}}"#), FailKind::Overloaded, ("overloaded", true), None),
        (Mode::Status(500, "", "{}"), FailKind::ProviderError, ("provider_error", true), None),
        (Mode::Status(401, "", "{}"), FailKind::Auth, ("provider_error", true), None),
        (Mode::Status(404, "", "{}"), FailKind::ModelUnavailable, ("model_unavailable", true), None),
        (Mode::Status(400, "", r#"{"error":"bad"}"#), FailKind::InvalidRequest, ("provider_error", false), None),
    ] {
        let body = if let Mode::Status(_, _, b) = &mode { *b } else { "" };
        let f = fake(mode).await;
        let a = adapter(Provider::Anthropic, format!("http://{}", f.addr), Limits::default());
        let prep = prepare(Provider::Anthropic, Dialect::AnthropicMessages, ABODY);
        let e = a.send(Dialect::AnthropicMessages, prep.body, &prep.headers).await.unwrap_err();
        assert_eq!((e.kind, e.nack(), e.retry_after_ms), (kind, nack, retry));
        if retry == Some(3000) {
            assert_eq!(e.rate_limit.as_ref().and_then(|r| r.headroom_pct()), Some(0), "429 reports its rate-limit headers");
        }
        assert_eq!(&e.body[..], body.as_bytes(), "native error body kept for the Gateway");
    }
    // Nothing listening: network failure before start, retryable.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let a = adapter(Provider::Anthropic, format!("http://{addr}"), Limits::default());
    let e = a.send(Dialect::AnthropicMessages, Bytes::from_static(b"{}"), &[]).await.unwrap_err();
    assert_eq!(e.nack(), ("provider_error", true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeouts_and_caps() {
    let f = fake(Mode::SlowHeaders(1500)).await;
    let a = adapter(Provider::Anthropic, format!("http://{}", f.addr), Limits { headers: Duration::from_millis(200), ..Limits::default() });
    let t = Instant::now();
    let e = a.send(Dialect::AnthropicMessages, Bytes::from_static(b"{}"), &[]).await.unwrap_err();
    assert_eq!(e.kind, FailKind::Timeout);
    assert!(t.elapsed() < Duration::from_millis(1000));

    let f = fake(Mode::Hang).await;
    let a = adapter(Provider::Anthropic, format!("http://{}", f.addr), Limits { idle: Duration::from_millis(200), ..Limits::default() });
    let mut r = a.send(Dialect::AnthropicMessages, Bytes::from_static(b"{}"), &[]).await.unwrap();
    assert!(r.next().await.unwrap().is_some());
    assert_eq!(r.next().await.unwrap_err().kind, FailKind::Timeout);

    let f = fake(Mode::Sse(ANTH)).await;
    let a = adapter(Provider::Anthropic, format!("http://{}", f.addr), Limits { max_response: 300, ..Limits::default() });
    let mut r = a.send(Dialect::AnthropicMessages, Bytes::from_static(b"{}"), &[]).await.unwrap();
    let e = loop {
        match r.next().await {
            Ok(Some(_)) => {}
            Ok(None) => panic!("cap not enforced"),
            Err(e) => break e,
        }
    };
    assert_eq!(e.kind, FailKind::TooLarge);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_aborts_provider_request_h1() {
    let mut f = fake(Mode::Hang).await;
    let a = adapter(Provider::Anthropic, format!("http://{}", f.addr), Limits::default());
    let mut r = a.send(Dialect::AnthropicMessages, Bytes::from_static(b"{}"), &[]).await.unwrap();
    assert!(r.next().await.unwrap().is_some());
    drop(r);
    tokio::time::timeout(Duration::from_secs(2), f.disconnected.recv()).await.expect("fake saw no disconnect").unwrap();
}

// --- HTTP/2 + TLS (production path) ------------------------------------------------------

/// Response body that streams `chunks`, then ends or hangs; signals when dropped (= the
/// client reset the stream).
struct TestBody {
    chunks: VecDeque<Bytes>,
    hang: bool,
    dropped: Option<oneshot::Sender<()>>,
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.chunks.pop_front() {
            Some(c) => Poll::Ready(Some(Ok(Frame::data(c)))),
            None if self.hang => Poll::Pending,
            None => Poll::Ready(None),
        }
    }
}

impl Drop for TestBody {
    fn drop(&mut self) {
        if let Some(t) = self.dropped.take() {
            let _ = t.send(());
        }
    }
}

struct H2Fake {
    addr: SocketAddr,
    ca: rustls::pki_types::CertificateDer<'static>,
    conns: Arc<AtomicUsize>,
    reset: mpsc::UnboundedReceiver<()>,
}

async fn h2_fake() -> H2Fake {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap().signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let (rtx, reset) = mpsc::unbounded_channel();
    let c2 = conns.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            s.set_nodelay(true).unwrap();
            c2.fetch_add(1, Ordering::SeqCst);
            let (acceptor, rtx) = (acceptor.clone(), rtx.clone());
            tokio::spawn(async move {
                let tls = acceptor.accept(s).await.unwrap();
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let rtx = rtx.clone();
                    async move {
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let hang = body.windows(5).any(|w| w == b"#hang");
                        let (dtx, drx) = oneshot::channel();
                        tokio::spawn(async move {
                            if drx.await.is_ok() && hang {
                                let _ = rtx.send(());
                            }
                        });
                        let bulk = body.windows(5).any(|w| w == b"#bulk");
                        let chunks = if bulk {
                            let ev = Bytes::from_static(BULK_EVENT.as_bytes());
                            std::iter::repeat_n(ev, BULK_N).collect()
                        } else {
                            ANTH.split_inclusive("\n\n").map(|e| Bytes::from(e.to_owned())).take(if hang { 2 } else { usize::MAX }).collect()
                        };
                        Ok::<_, Infallible>(hyper::Response::new(TestBody { chunks, hang, dropped: Some(dtx) }))
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    H2Fake { addr, ca: ca.der().clone(), conns, reset }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_tls_warm_multiplexed_and_cancel() {
    let mut f = h2_fake().await;
    let a = Arc::new(
        Adapter::new(&AdapterConfig {
            provider: Provider::Anthropic,
            api_key: Zeroizing::new("sk-test".into()),
            base_url: Some(format!("https://{}", f.addr)),
            insecure_dev: true,
            dev_root: Some(f.ca.clone()),
            limits: Limits::default(),
        })
        .unwrap(),
    );
    a.warm().await.unwrap();
    assert_eq!(f.conns.load(Ordering::SeqCst), 1);
    let prep = prepare(Provider::Anthropic, Dialect::AnthropicMessages, ABODY);

    // Warm request latency (headers) and 32 concurrent streams on the one connection.
    let t = Instant::now();
    let mut r = a.send(Dialect::AnthropicMessages, prep.body.clone(), &prep.headers).await.unwrap();
    let ttfb = t.elapsed();
    let mut n = 0;
    while let Some(c) = r.next().await.unwrap() {
        n += c.len();
    }
    assert_eq!(n, ANTH.len());
    println!("warm h2 request → headers: {ttfb:?}");
    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let (a, b, h) = (a.clone(), prep.body.clone(), prep.headers.clone());
            tokio::spawn(async move {
                let mut r = a.send(Dialect::AnthropicMessages, b, &h).await.unwrap();
                let mut p = StreamParser::new(Dialect::AnthropicMessages, true);
                while let Some(c) = r.next().await.unwrap() {
                    p.feed(&c, &mut |_, _| {}).unwrap();
                }
                p.finish().usage
            })
        })
        .collect();
    for t in tasks {
        assert!(!t.await.unwrap().estimated);
    }
    assert_eq!(f.conns.load(Ordering::SeqCst), 1, "all requests multiplexed on the warm connection");

    // Cancel = drop: the provider sees the stream reset at once.
    let hang = prepare(Provider::Anthropic, Dialect::AnthropicMessages, &ABODY.replace("hi", "hi #hang"));
    let mut r = a.send(Dialect::AnthropicMessages, hang.body, &hang.headers).await.unwrap();
    assert!(r.next().await.unwrap().is_some());
    let t = Instant::now();
    drop(r);
    tokio::time::timeout(Duration::from_secs(2), f.reset.recv()).await.expect("provider never saw the reset").unwrap();
    println!("cancel → provider stream reset: {:?}", t.elapsed());
}

const BULK_EVENT: &str = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" token\"}}\n\n";
const BULK_N: usize = 50_000;

/// CONTRACT §13 per-chunk path on the Worker: h2 frame in → chunk handed out → parsed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_per_chunk_overhead() {
    let f = h2_fake().await;
    let a = Adapter::new(&AdapterConfig {
        provider: Provider::Anthropic,
        api_key: Zeroizing::new("sk-test".into()),
        base_url: Some(format!("https://{}", f.addr)),
        insecure_dev: true,
        dev_root: Some(f.ca.clone()),
        limits: Limits::default(),
    })
    .unwrap();
    a.warm().await.unwrap();
    let prep = prepare(Provider::Anthropic, Dialect::AnthropicMessages, &ABODY.replace("hi", "hi #bulk"));
    let mut r = a.send(Dialect::AnthropicMessages, prep.body, &prep.headers).await.unwrap();
    let mut p = StreamParser::new(Dialect::AnthropicMessages, true);
    let t = Instant::now();
    let (mut chunks, mut bytes) = (0u64, 0usize);
    while let Some(c) = r.next().await.unwrap() {
        chunks += 1;
        bytes += c.len();
        p.feed(&c, &mut |_, _| {}).unwrap();
    }
    let e = t.elapsed();
    assert_eq!(bytes, BULK_EVENT.len() * BULK_N);
    println!(
        "h2 loopback: {BULK_N} events in {chunks} chunks, {:.0} ns/event incl. TLS+h2+parse ({:.0} MB/s)",
        e.as_nanos() as f64 / BULK_N as f64,
        bytes as f64 / e.as_secs_f64() / 1e6
    );
}

#[test]
fn real_hosts_refuse_overrides() {
    let cfg = |base: &str, dev: bool| AdapterConfig {
        provider: Provider::OpenRouter,
        api_key: Zeroizing::new("k".into()),
        base_url: Some(base.into()),
        insecure_dev: dev,
        dev_root: None,
        limits: Limits::default(),
    };
    assert!(Adapter::new(&cfg("https://evil.example", true)).is_err());
    assert!(Adapter::new(&cfg("http://127.0.0.1:9", false)).is_err());
    assert!(Adapter::new(&cfg("http://169.254.169.254", true)).is_err());
    // A path is never interpreted (no origin-vs-root guessing): refused with a clear error.
    for base in ["http://127.0.0.1:9/api", "http://127.0.0.1:9/api/v1", "http://127.0.0.1:9/anthropic"] {
        let e = Adapter::new(&cfg(base, true)).unwrap_err();
        assert!(e.0.contains("origin"), "{base}: {e}");
    }
    assert!(Adapter::new(&cfg("http://127.0.0.1:9/", true)).is_ok());
}

/// Cross-check against the real Go e2e fakes (`e2e/fake`), which mirror the providers'
/// paths. Opt-in: `MOOCHY_E2E_FAKES="anthropic=URL=KEY;openai=URL=KEY;…" cargo test -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs MOOCHY_E2E_FAKES from the Go fake servers"]
async fn against_e2e_fakes() {
    let spec = std::env::var("MOOCHY_E2E_FAKES").unwrap();
    let mut checked = 0;
    for entry in spec.split(';').filter(|e| !e.is_empty()) {
        let mut it = entry.splitn(3, '=');
        let (kind, url, key) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
        let p = Provider::parse(kind).unwrap();
        let a = Adapter::new(&AdapterConfig {
            provider: p,
            api_key: Zeroizing::new(key.into()),
            base_url: Some(url.into()),
            insecure_dev: true,
            dev_root: None,
            limits: Limits::default(),
        })
        .unwrap();
        // Warm first: the Go harness then asserts one TCP connection per fake for every
        // request below (E77 semantics on the dev path).
        a.warm().await.unwrap();
        for (d, body) in [(Dialect::AnthropicMessages, ABODY), (Dialect::OpenAiChat, OBODY)].repeat(3) {
            if !p.serves(d) {
                continue;
            }
            let prep = prepare(p, d, body);
            let mut r = a.send(d, prep.body, &prep.headers).await.unwrap_or_else(|e| panic!("{kind} {d:?}: {e}"));
            let mut parser = StreamParser::new(d, true);
            while let Some(c) = r.next().await.unwrap() {
                parser.feed(&c, &mut |_, _| {}).unwrap();
            }
            let o = parser.finish();
            assert!(o.complete && !o.malformed && !o.usage.estimated, "{kind} {d:?}: {o:?}");
            // The harness sets a distinct rate-limit headroom per fake (fake.SetHeadroom).
            let want = std::env::var("MOOCHY_E2E_HEADROOM").ok().and_then(|h| {
                h.split(';').find_map(|kv| kv.strip_prefix(kind).and_then(|v| v.strip_prefix('=')).and_then(|v| v.parse::<u8>().ok()))
            });
            if let Some(want) = want {
                let rl = r.rate_limit;
                assert!(rl.requests_limit.is_some() && rl.tokens_limit.is_some(), "{kind} {d:?}: {rl:?}");
                assert_eq!(rl.headroom_pct(), Some(want), "{kind} {d:?}: {rl:?}");
            }
            if p == Provider::XAi {
                assert!(o.usage.provider_cost_uusd.is_some(), "xAI reports cost_in_usd_ticks: {o:?}");
            }
            println!("{kind} {d:?}: ok, usage {:?}", o.usage);
            checked += 1;
        }
    }
    assert!(checked >= 18, "{checked}");
}

// --- HTTP/1.1 keep-alive (the loopback dev path the e2e fakes speak) ---------------------

/// A keep-alive HTTP/1.1 fake (hyper server): counts TCP connections, streams the fixture,
/// or (`#hang`) streams two events and then waits, reporting when the client drops it.
async fn h1_keepalive_fake() -> (SocketAddr, Arc<AtomicUsize>, mpsc::UnboundedReceiver<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let (rtx, reset) = mpsc::unbounded_channel();
    let c2 = conns.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            s.set_nodelay(true).unwrap();
            c2.fetch_add(1, Ordering::SeqCst);
            let rtx = rtx.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                    let rtx = rtx.clone();
                    async move {
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let hang = body.windows(5).any(|w| w == b"#hang");
                        let (dtx, drx) = oneshot::channel();
                        tokio::spawn(async move {
                            if drx.await.is_ok() && hang {
                                let _ = rtx.send(());
                            }
                        });
                        let chunks = ANTH.split_inclusive("\n\n").map(|e| Bytes::from(e.to_owned())).take(if hang { 2 } else { usize::MAX }).collect();
                        Ok::<_, Infallible>(hyper::Response::new(TestBody { chunks, hang, dropped: Some(dtx) }))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
            });
        }
    });
    (addr, conns, reset)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h1_dev_path_warm_keepalive_and_cancel() {
    let (addr, conns, mut reset) = h1_keepalive_fake().await;
    let a = adapter(Provider::Anthropic, format!("http://{addr}"), Limits::default());
    a.warm().await.unwrap();
    a.warm().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(conns.load(Ordering::SeqCst), 1, "warm() opens exactly one connection");
    let prep = prepare(Provider::Anthropic, Dialect::AnthropicMessages, ABODY);
    let read_all = |mut r: moochy_worker::provider::Response| async move {
        let mut n = 0;
        while let Some(c) = r.next().await.unwrap() {
            n += c.len();
        }
        n
    };
    for _ in 0..5 {
        let r = a.send(Dialect::AnthropicMessages, prep.body.clone(), &prep.headers).await.unwrap();
        assert_eq!(read_all(r).await, ANTH.len());
    }
    assert_eq!(conns.load(Ordering::SeqCst), 1, "sequential tasks reuse the warm connection");

    // Cancel mid-stream: the connection is closed (provider stops) and never reused.
    let hang = prepare(Provider::Anthropic, Dialect::AnthropicMessages, &ABODY.replace("hi", "hi #hang"));
    let mut r = a.send(Dialect::AnthropicMessages, hang.body, &hang.headers).await.unwrap();
    assert!(r.next().await.unwrap().is_some());
    drop(r);
    tokio::time::timeout(Duration::from_secs(2), reset.recv()).await.expect("provider never saw the abort").unwrap();
    let r = a.send(Dialect::AnthropicMessages, prep.body.clone(), &prep.headers).await.unwrap();
    assert_eq!(read_all(r).await, ANTH.len());
    assert_eq!(conns.load(Ordering::SeqCst), 2, "a fresh connection replaces the cancelled one");

    // Concurrent tasks each get their own connection, then all return to the pool.
    let a = Arc::new(a);
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let (a, b, h) = (a.clone(), prep.body.clone(), prep.headers.clone());
            tokio::spawn(async move { read_all(a.send(Dialect::AnthropicMessages, b, &h).await.unwrap()).await })
        })
        .collect();
    for t in tasks {
        assert_eq!(t.await.unwrap(), ANTH.len());
    }
    let after = conns.load(Ordering::SeqCst);
    assert!(after <= 5, "{after}");
    for _ in 0..5 {
        let r = a.send(Dialect::AnthropicMessages, prep.body.clone(), &prep.headers).await.unwrap();
        assert_eq!(read_all(r).await, ANTH.len());
    }
    assert_eq!(conns.load(Ordering::SeqCst), after, "pooled connections are reused afterwards");
}
