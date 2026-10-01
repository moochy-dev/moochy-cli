//! Shared node state: config snapshot, unlocked secrets, engines, relay link handle, pool,
//! sessions, journal.

use crate::config::{Config, Home};
use crate::engine::{Executor, Sealer};
use crate::keystore::Secrets;
use crate::pb::link::{NodeMsg, PoolSync, node_link_client::NodeLinkClient};
use crate::pb::local::JournalEntry;
use crate::util::{clean, now_ms};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::{broadcast, mpsc, watch};
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

pub struct Node {
    pub home: Home,
    pub cfg: Config,
    pub secrets: Secrets,
    pub executor: Arc<dyn Executor>,
    pub sealer: Option<Arc<dyn Sealer>>,
    /// Own-key / stub mode: no relay; tasks run on the local executor.
    pub offline: bool,
    pub link: Mutex<Option<LinkHandle>>,
    pub link_state: watch::Sender<LinkState>,
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
    pub journal: Mutex<VecDeque<JournalEntry>>,
    pub journal_tx: broadcast::Sender<JournalEntry>,
    pub shutdown: watch::Sender<bool>,
}

const MAX_SESSIONS: usize = 4096;
const JOURNAL_KEEP: usize = 512;

impl Node {
    pub fn new(home: Home, cfg: Config, secrets: Secrets, executor: Arc<dyn Executor>, sealer: Option<Arc<dyn Sealer>>, offline: bool) -> Arc<Self> {
        let token_gen = AtomicU64::new(cfg.token_gen);
        Arc::new(Self {
            home,
            cfg,
            secrets,
            executor,
            sealer,
            offline,
            link: Mutex::new(None),
            link_state: watch::channel(LinkState::Down).0,
            pools: Mutex::new(HashMap::new()),
            pool_gen: watch::channel(0).0,
            sessions: Mutex::new(HashMap::new()),
            gateway_port: AtomicU32::new(0),
            token_gen,
            paused: AtomicBool::new(false),
            worker_busy: AtomicU32::new(0),
            gateway_tasks: AtomicU32::new(0),
            journal: Mutex::new(VecDeque::new()),
            journal_tx: broadcast::channel(64).0,
            shutdown: watch::channel(false).0,
        })
    }

    pub fn device_id(&self) -> Option<&str> {
        self.cfg.device_id.as_deref()
    }

    pub fn link(&self) -> Option<LinkHandle> {
        lock(&self.link).clone()
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
    /// `PoolSync` carries no slug yet: when exactly one repo pool is known it serves every
    /// local token (they all belong to this device's user). Requested: `slug` in `PoolSync`.
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
            for m in self.executor.models() {
                let d = m.dialect.wire().to_owned();
                if !w.dialects.contains(&d) {
                    w.dialects.push(d);
                }
                if !w.models.contains(&m.model) {
                    w.models.push(m.model);
                }
            }
            return Some(RepoPool { repo_id: format!("local:{slug}"), slug: Some(slug.into()), workers: vec![w] });
        }
        let pools = lock(&self.pools);
        if let Some(p) = pools.values().find(|p| p.slug.as_deref() == Some(slug)) {
            return Some(p.clone());
        }
        let mut it = pools.values().filter(|p| p.slug.is_none());
        match (it.next(), it.next()) {
            (Some(p), None) => Some(p.clone()),
            _ => None,
        }
    }

    pub fn apply_pool_sync(&self, v: &PoolSync) {
        if v.repo_id.is_empty() || v.repo_id.len() > 64 {
            return;
        }
        let changed = {
            let mut pools = lock(&self.pools);
            let p = pools.entry(v.repo_id.clone()).or_insert_with(|| RepoPool { repo_id: v.repo_id.clone(), ..RepoPool::default() });
            let before = p.models();
            if v.full {
                p.workers.clear();
            }
            p.workers.retain(|x| !v.removed_worker_devices.contains(&x.worker_device));
            for w in v.workers.iter().take(4096) {
                let Ok(enc_pub) = <[u8; 32]>::try_from(w.enc_pub.as_slice()) else { continue };
                p.workers.retain(|x| x.worker_device != w.worker_device);
                p.workers.push(PoolWorker {
                    worker_device: w.worker_device.clone(),
                    enc_pub,
                    sign_pub: None,
                    donor: clean(&w.donor_pseudonym).into_owned(),
                    dialects: w.dialects.clone(),
                    models: w.models.clone(),
                    hint: w.hint.min(100),
                });
            }
            before != p.models()
        };
        if changed {
            self.pool_gen.send_modify(|g| *g = g.wrapping_add(1));
        }
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

/// RAII counter for in-flight work (`gateway_tasks`, `worker_busy`).
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
