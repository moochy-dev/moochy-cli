//! Shared node state: config snapshot, unlocked secrets, engines, relay link handle, pool,
//! sessions, journal.

use crate::config::{Config, Home};
use crate::engine::{Catalog, STUB_MODEL};
use crate::keystore::Secrets;
use crate::pb::link::{ApprovalRequest, LogEntryAck, NodeMsg, PoolSync, node_link_client::NodeLinkClient};
use moochy_proto::crypto::{EncSecret, SignKey};
use moochy_worker::provider::Adapter;
use moochy_worker::store::Store;
use crate::pb::local::JournalEntry;
use crate::util::{clean, now_ms};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::Channel;

/// Lock that survives poisoning (a panic aborts the process anyway: `panic = "abort"`).
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkState {
    Down,
    Up,
    Refused(String),
}

/// The authenticated relay session: one TLS connection, one Channel.
#[derive(Clone)]
pub struct LinkHandle {
    pub client: NodeLinkClient<Channel>,
    /// `x-moochy-session` metadata for Submit/Serve streams.
    pub session: AsciiMetadataValue,
    pub up: mpsc::Sender<NodeMsg>,
}

#[derive(Clone, Debug)]
pub struct PoolWorker {
    pub worker_device: String,
    pub enc_pub: [u8; 32],
    pub sign_pub: Option<[u8; 32]>,
    pub donor: String,
    pub dialects: Vec<String>,
    pub models: Vec<String>,
    pub hint: u32,
}

#[derive(Clone, Debug, Default)]
pub struct RepoPool {
    pub repo_id: String,
    pub slug: Option<String>,
    pub workers: Vec<PoolWorker>,
    /// Repo setting `PoolSync.auto_cache` (07 §4.2).
    pub auto_cache: bool,
}

impl RepoPool {
    /// Sorted unique `(model, dialects)` offered by this pool.
    pub fn models(&self) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for w in &self.workers {
            for m in &w.models {
                if !out.iter().any(|(x, _)| x == m) {
                    out.push((m.clone(), Vec::new()));
                }
                if let Some((_, ds)) = out.iter_mut().find(|(x, _)| x == m) {
                    for d in &w.dialects {
                        if !ds.contains(d) {
                            ds.push(d.clone());
                        }
                    }
                }
            }
        }
        out.sort();
        out
    }
}

/// Device keys in usable form (built once from the keystore seeds).
pub struct Keys {
    pub sign: SignKey,
    pub enc: EncSecret,
    pub device_id: moochy_proto::DeviceId,
}

pub struct Node {
    pub home: Home,
    pub cfg: Config,
    pub secrets: Secrets,
    pub keys: Option<Keys>,
    /// Dev/test mode: no relay; the doors answer with canned stub responses.
    pub offline: bool,
    /// `MOOCHY_INSECURE_DEV=1`: loopback provider URLs, relay-asserted trust (D14).
    pub insecure_dev: bool,
    /// Process start (ms): the served-task boot floor (D18).
    pub boot_ms: u64,
    pub catalog: Mutex<Arc<Catalog>>,
    /// Worker: one warm adapter per provider key.
    pub adapters: Vec<Arc<Adapter>>,
    /// Worker: outbox + served-task set + reservations (blocking I/O: use on a blocking thread).
    pub store: Option<Arc<Mutex<Store>>>,
    /// Owner: requests waiting for this device's signature (pushed by the relay).
    pub approvals: Mutex<Vec<ApprovalRequest>>,
    pub log_acks: Mutex<HashMap<String, oneshot::Sender<LogEntryAck>>>,
    pub link: Mutex<Option<LinkHandle>>,
    pub link_state: watch::Sender<LinkState>,
    /// Wakes the reconnect loop now (a request arrived while the link was down).
    pub link_kick: tokio::sync::Notify,
    pub pools: Mutex<HashMap<String, RepoPool>>,
    /// Bumped whenever the set of pool models changes (MCP `tools/list_changed`).
    pub pool_gen: watch::Sender<u64>,
    /// Affinity key → (last worker device, expiry ms).
    pub sessions: Mutex<HashMap<[u8; 16], (String, u64)>>,
    pub gateway_port: AtomicU32,
    pub token_gen: AtomicU64,
    pub paused: AtomicBool,
    pub worker_busy: AtomicU32,
    pub gateway_tasks: AtomicU32,
    /// `Welcome.max_concurrent_tasks`: the relay fails a Submit past it, so the Gateway queues.
    pub max_tasks: AtomicU32,
    pub task_freed: tokio::sync::Notify,
    pub journal: Mutex<VecDeque<JournalEntry>>,
    pub journal_tx: broadcast::Sender<JournalEntry>,
    pub shutdown: watch::Sender<bool>,
    /// Relay server_time − node clock at the last Hello.
    pub clock_skew_ms: std::sync::atomic::AtomicI64,
    /// Evidence of the last consumed tasks, for `moochy report` (bounded).
    pub evidence: Mutex<VecDeque<crate::task::Evidence>>,
    /// Key-log mirror (None = no pinned log key: relay-asserted trust).
    pub keylog: Option<Arc<crate::keylog::LogMirror>>,
}

const MAX_SESSIONS: usize = 4096;
const JOURNAL_KEEP: usize = 512;

impl Node {
    pub fn new(home: Home, cfg: Config, secrets: Secrets, keys: Option<Keys>, w: WorkerParts, offline: bool) -> Arc<Self> {
        let keylog = crate::keylog::LogMirror::open(&home, &cfg, keys.as_ref().map(|k| k.sign.public()));
        let token_gen = AtomicU64::new(cfg.token_gen);
        Arc::new(Self {
            home,
            cfg,
            secrets,
            keys,
            offline,
            insecure_dev: std::env::var("MOOCHY_INSECURE_DEV").as_deref() == Ok("1"),
            boot_ms: now_ms(),
            catalog: Mutex::new(if offline { Catalog::stub() } else { Arc::new(Catalog::default()) }),
            adapters: w.adapters,
            store: w.store,
            approvals: Mutex::new(Vec::new()),
            log_acks: Mutex::new(HashMap::new()),
            link: Mutex::new(None),
            link_state: watch::channel(LinkState::Down).0,
            link_kick: tokio::sync::Notify::new(),
            pools: Mutex::new(HashMap::new()),
            pool_gen: watch::channel(0).0,
            sessions: Mutex::new(HashMap::new()),
            gateway_port: AtomicU32::new(0),
            token_gen,
            paused: AtomicBool::new(false),
            worker_busy: AtomicU32::new(0),
            gateway_tasks: AtomicU32::new(0),
            max_tasks: AtomicU32::new(16),
            task_freed: tokio::sync::Notify::new(),
            journal: Mutex::new(VecDeque::new()),
            journal_tx: broadcast::channel(64).0,
            shutdown: watch::channel(false).0,
            clock_skew_ms: std::sync::atomic::AtomicI64::new(0),
            evidence: Mutex::new(VecDeque::new()),
            keylog,
        })
    }

    pub fn catalog(&self) -> Arc<Catalog> {
        lock(&self.catalog).clone()
    }

    /// Right after start the relay may not have pushed every donor yet (it throttles pool
    /// updates): wait up to 2 s for `ok(pool)`, only during the node's first 5 seconds.
    pub async fn settle_pool(&self, slug: &str, ok: impl Fn(&RepoPool) -> bool) {
        let ready = |n: &Self| n.pool_for(slug).is_some_and(|p| ok(&p));
        if now_ms().saturating_sub(self.boot_ms) >= 5_000 || ready(self) {
            return;
        }
        let mut rx = self.pool_gen.subscribe();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    r = rx.changed() => if r.is_err() { return },
                    () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                }
                if ready(self) {
                    return;
                }
            }
        })
        .await;
    }

    /// Accept a newer catalog (versions never go down).
    pub fn set_catalog(&self, c: Catalog) {
        let mut cur = lock(&self.catalog);
        if c.version >= cur.version {
            *cur = Arc::new(c);
        }
    }

    pub fn device_id(&self) -> Option<&str> {
        self.cfg.device_id.as_deref()
    }

    pub fn link(&self) -> Option<LinkHandle> {
        lock(&self.link).clone()
    }

    /// The link, reconnecting at once if it is down (waits at most `wait`).
    pub async fn link_now(&self, wait: std::time::Duration) -> Option<LinkHandle> {
        if let Some(l) = self.link() {
            return Some(l);
        }
        self.link_kick.notify_one();
        let mut rx = self.link_state.subscribe();
        let _ = tokio::time::timeout(wait, rx.wait_for(|s| *s == LinkState::Up)).await;
        self.link()
    }

    pub fn gateway_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.gateway_port.load(Ordering::Relaxed))
    }

    pub fn check_token(&self, token: &str) -> Option<String> {
        self.secrets.check_token(token, self.token_gen.load(Ordering::Relaxed))
    }

    pub fn token(&self, slug: &str) -> String {
        self.secrets.local_token(slug, self.token_gen.load(Ordering::Relaxed))
    }

    /// The pool serving `slug`. Offline: a synthetic pool of the local executor's models.
    ///
    /// Matched by `PoolSync.repo_slug` (case-insensitive: slugs are lowercase on the wire).
    pub fn pool_for(&self, slug: &str) -> Option<RepoPool> {
        if self.offline {
            let mut w = PoolWorker {
                worker_device: "local".into(),
                enc_pub: [0; 32],
                sign_pub: None,
                donor: "local".into(),
                dialects: Vec::new(),
                models: Vec::new(),
                hint: 100,
            };
            w.dialects = vec!["anthropic.messages".into(), "openai.chat".into()];
            w.models = vec![STUB_MODEL.into()];
            return Some(RepoPool { repo_id: format!("local:{slug}"), slug: Some(slug.into()), workers: vec![w], auto_cache: true });
        }
        let pools = lock(&self.pools);
        pools.values().find(|p| p.slug.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(slug))).cloned()
    }

    /// Whether the repo behind `slug` allows auto-caching (no clone of the pool).
    pub fn repo_auto_cache(&self, slug: &str) -> bool {
        self.offline || lock(&self.pools).values().any(|p| p.auto_cache && p.slug.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(slug)))
    }

    /// Key-log hook (06 §10): a Gateway seals only to worker keys that are logged, unrevoked, and
    /// belong to a donor with an owner-signed `DONOR_APPROVED` for the repo. Until the
    /// key-log mirror has a verified checkpoint, the relay's pool is accepted as-is (D14).
    fn worker_approved(&self, repo_id: &str, worker_device: &str, enc_pub: &[u8; 32]) -> bool {
        match self.keylog.as_ref().filter(|l| l.active()) {
            Some(l) => l.sealable(worker_device, repo_id).is_some_and(|k| crate::util::ct_eq(&k, enc_pub)),
            None => true,
        }
    }

    pub fn apply_pool_sync(&self, v: &PoolSync) {
        if v.repo_id.is_empty() || v.repo_id.len() > 64 {
            return;
        }
        let changed = {
            let mut pools = lock(&self.pools);
            let p = pools.entry(v.repo_id.clone()).or_insert_with(|| RepoPool { repo_id: v.repo_id.clone(), ..RepoPool::default() });
            if crate::config::valid_slug(&v.repo_slug) {
                p.slug = Some(v.repo_slug.to_ascii_lowercase());
            }
            p.auto_cache = v.auto_cache;
            let before = p.models();
            if v.full {
                p.workers.clear();
            }
            p.workers.retain(|x| !v.removed_worker_devices.contains(&x.worker_device));
            for w in v.workers.iter().take(4096) {
                let Ok(enc_pub) = <[u8; 32]>::try_from(w.enc_pub.as_ref()) else { continue };
                let sign_pub = <[u8; 32]>::try_from(w.sign_pub.as_ref()).ok();
                if !self.worker_approved(&v.repo_id, &w.worker_device, &enc_pub) {
                    continue;
                }
                p.workers.retain(|x| x.worker_device != w.worker_device);
                p.workers.push(PoolWorker {
                    worker_device: w.worker_device.clone(),
                    enc_pub,
                    sign_pub,
                    donor: clean(&w.donor_pseudonym).into_owned(),
                    dialects: w.dialects.iter().filter(|d| plain_id(d)).cloned().collect(),
                    models: w.models.iter().filter(|m| plain_id(m)).cloned().collect(),
                    hint: w.hint.min(100),
                });
            }
            before != p.models()
        };
        if changed {
            self.pool_gen.send_modify(|g| *g = g.wrapping_add(1));
        }
        crate::util::log("info", "pool sync", &serde_json::json!({"repo_id": v.repo_id, "full": v.full, "workers": v.workers.len(), "models_changed": changed}));
    }

    pub fn session_worker(&self, key: &[u8; 16]) -> Option<String> {
        let s = lock(&self.sessions);
        s.get(key).filter(|(_, exp)| *exp > now_ms()).map(|(w, _)| w.clone())
    }

    pub fn session_set(&self, key: [u8; 16], worker: String, ttl_ms: u64) {
        let mut s = lock(&self.sessions);
        if s.len() >= MAX_SESSIONS {
            // ponytail: drop expired, then everything; an LRU only if affinity misses show up in metrics.
            let now = now_ms();
            s.retain(|_, (_, e)| *e > now);
            if s.len() >= MAX_SESSIONS {
                s.clear();
            }
        }
        s.insert(key, (worker, now_ms().saturating_add(ttl_ms)));
    }

    pub fn keep_evidence(&self, e: crate::task::Evidence) {
        let mut v = lock(&self.evidence);
        if v.len() >= 32 {
            v.pop_front();
        }
        v.push_back(e);
    }

    /// Record a finished task in the local journal (metadata only, never content).
    pub fn journal(&self, e: JournalEntry) {
        {
            let mut j = lock(&self.journal);
            if j.len() >= JOURNAL_KEEP {
                j.pop_front();
            }
            j.push_back(e.clone());
        }
        let _ = self.journal_tx.send(e);
    }
}

/// Model / dialect ids from the relay: short plain ASCII only (they reach agents and terminals).
fn plain_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:/-@+".contains(&c))
}

/// Worker-role parts built at startup.
#[derive(Default)]
pub struct WorkerParts {
    pub adapters: Vec<Arc<Adapter>>,
    pub store: Option<Arc<Mutex<Store>>>,
}

/// A Gateway task slot under the relay's per-device limit; freed (and waiters woken) on drop.
pub struct TaskSlot(Arc<Node>);

impl Drop for TaskSlot {
    fn drop(&mut self) {
        self.0.gateway_tasks.fetch_sub(1, Ordering::Relaxed);
        self.0.task_freed.notify_waiters();
    }
}

/// Wait up to `wait` for a Gateway task slot (a relay task ends at its receipt, which can trail
/// the client's last byte, so a fast sequential client must queue here, not overrun the relay).
pub async fn task_slot(node: &Arc<Node>, wait: std::time::Duration) -> Option<TaskSlot> {
    let deadline = tokio::time::Instant::now().checked_add(wait)?;
    loop {
        let freed = node.task_freed.notified();
        tokio::pin!(freed);
        freed.as_mut().enable();
        let max = node.max_tasks.load(Ordering::Relaxed);
        let mut n = node.gateway_tasks.load(Ordering::Acquire);
        while n < max {
            match node.gateway_tasks.compare_exchange_weak(n, n.saturating_add(1), Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(TaskSlot(node.clone())),
                Err(cur) => n = cur,
            }
        }
        tokio::time::timeout_at(deadline, freed).await.ok()?;
    }
}

/// RAII counter for in-flight work (`worker_busy`).
pub struct Busy<'a>(&'a AtomicU32);

impl<'a> Busy<'a> {
    pub fn new(c: &'a AtomicU32) -> Self {
        c.fetch_add(1, Ordering::Relaxed);
        Self(c)
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
