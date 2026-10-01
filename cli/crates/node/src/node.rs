//! Shared node state: config snapshot, unlocked secrets, engines, link handles, pool, sessions.

use crate::config::{Config, Home};
use crate::engine::{Executor, Sealer};
use crate::keystore::Secrets;
use crate::util::{b64d32, now_ms};
use bytes::Bytes;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

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

/// Inbound task-scoped traffic routed by the link to one task driver.
pub enum TaskIn {
    Text(Value),
    Frame(Bytes),
}

/// Key in the task registry: task id bytes + side (a node may be gateway *and* worker of a task).
pub type TaskKey = ([u8; 16], Side);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Gateway,
    Worker,
}

/// Bounded per-task inbound buffer (frames are ≤ 64 KiB → ≤ 2 MiB per task).
pub const TASK_BUF: usize = 32;

#[derive(Clone, Debug)]
pub struct PoolWorker {
    pub worker_device: String,
    pub enc_pub: [u8; 32],
    pub sign_pub: Option<[u8; 32]>,
    pub donor: String,
    pub dialects: Vec<String>,
    pub models: Vec<String>,
    pub hint: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RepoPool {
    pub repo_id: String,
    pub slug: Option<String>,
    pub workers: Vec<PoolWorker>,
    /// Extra relay-provided numbers (budget left, quota…), passed to `moochy_pool_status`.
    pub status: Value,
}

impl RepoPool {
    /// Sorted unique `(model, dialects)` offered by this pool.
    pub fn models(&self) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for w in &self.workers {
            for m in &w.models {
                let i = match out.iter().position(|(x, _)| x == m) {
                    Some(i) => i,
                    None => {
                        out.push((m.clone(), Vec::new()));
                        out.len().saturating_sub(1)
                    }
                };
                if let Some((_, ds)) = out.get_mut(i) {
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
    pub link_out: Mutex<Option<mpsc::Sender<Message>>>,
    pub link_state: watch::Sender<LinkState>,
    pub tasks: Mutex<HashMap<TaskKey, mpsc::Sender<TaskIn>>>,
    pub pools: Mutex<HashMap<String, RepoPool>>,
    /// Bumped whenever the set of pool models changes (MCP `tools/list_changed`).
    pub pool_gen: watch::Sender<u64>,
    /// Affinity key → (last worker device, expiry ms).
    pub sessions: Mutex<HashMap<[u8; 16], (String, u64)>>,
    pub gateway_port: Mutex<u16>,
    pub shutdown: watch::Sender<bool>,
}

const MAX_SESSIONS: usize = 4096;

impl Node {
    pub fn new(home: Home, cfg: Config, secrets: Secrets, executor: Arc<dyn Executor>, sealer: Option<Arc<dyn Sealer>>, offline: bool) -> Arc<Self> {
        Arc::new(Self {
            home,
            cfg,
            secrets,
            executor,
            sealer,
            offline,
            link_out: Mutex::new(None),
            link_state: watch::channel(LinkState::Down).0,
            tasks: Mutex::new(HashMap::new()),
            pools: Mutex::new(HashMap::new()),
            pool_gen: watch::channel(0).0,
            sessions: Mutex::new(HashMap::new()),
            gateway_port: Mutex::new(0),
            shutdown: watch::channel(false).0,
        })
    }

    pub fn device_id(&self) -> Option<&str> {
        self.cfg.device_id.as_deref()
    }

    pub fn check_token(&self, token: &str) -> Option<String> {
        self.secrets.check_token(token, self.cfg.token_gen)
    }

    /// The pool serving `slug`. Offline: a synthetic pool of the local executor's models.
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
            return Some(RepoPool { repo_id: format!("local:{slug}"), slug: Some(slug.into()), workers: vec![w], status: Value::Null });
        }
        lock(&self.pools).values().find(|p| p.slug.as_deref() == Some(slug)).cloned()
    }

    /// Apply a `pool.sync` message (full or delta).
    pub fn apply_pool_sync(&self, v: &Value) {
        let Some(repo_id) = v.get("repo").and_then(Value::as_str).or_else(|| v.get("repo_id").and_then(Value::as_str)) else {
            return;
        };
        let full = v.get("full").and_then(Value::as_bool).unwrap_or(true);
        let changed = {
            let mut pools = lock(&self.pools);
            let p = pools.entry(repo_id.to_owned()).or_insert_with(|| RepoPool { repo_id: repo_id.to_owned(), ..RepoPool::default() });
            let before = p.models();
            if let Some(s) = v.get("slug").and_then(Value::as_str).filter(|s| crate::config::valid_slug(s)) {
                p.slug = Some(s.to_owned());
            }
            if let Some(st) = v.get("status").filter(|s| s.is_object()) {
                p.status = st.clone();
            }
            if full {
                p.workers.clear();
            }
            for w in v.get("workers").and_then(Value::as_array).into_iter().flatten() {
                let Some(dev) = w.get("worker_device").and_then(Value::as_str) else { continue };
                p.workers.retain(|x| x.worker_device != dev);
                if w.get("removed").and_then(Value::as_bool) == Some(true) {
                    continue;
                }
                let Some(enc_pub) = w.get("enc_pub").and_then(Value::as_str).and_then(b64d32) else { continue };
                let strs = |k: &str| -> Vec<String> {
                    w.get(k).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect()
                };
                p.workers.push(PoolWorker {
                    worker_device: dev.to_owned(),
                    enc_pub,
                    sign_pub: w.get("sign_pub").and_then(Value::as_str).and_then(b64d32),
                    donor: w.get("donor_pseudonym").and_then(Value::as_str).unwrap_or("").to_owned(),
                    dialects: strs("dialects"),
                    models: w
                        .get("models")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|m| m.as_str().or_else(|| m.get("model").and_then(Value::as_str)))
                        .map(str::to_owned)
                        .collect(),
                    hint: w.get("hint").and_then(Value::as_u64).unwrap_or(50),
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

    /// Queue a message on the current relay connection (fails if the link is down or saturated).
    pub async fn send(&self, m: Message) -> bool {
        let tx = lock(&self.link_out).clone();
        match tx {
            Some(tx) => tx.send(m).await.is_ok(),
            None => false,
        }
    }

    /// Non-blocking variant for the link loop itself (never waits on its own queue).
    pub fn try_send(&self, m: Message) -> bool {
        lock(&self.link_out).as_ref().is_some_and(|tx| tx.try_send(m).is_ok())
    }

    pub fn register(&self, key: TaskKey) -> Option<mpsc::Receiver<TaskIn>> {
        let mut t = lock(&self.tasks);
        if t.contains_key(&key) {
            return None;
        }
        let (tx, rx) = mpsc::channel(TASK_BUF);
        t.insert(key, tx);
        Some(rx)
    }

    pub fn unregister(&self, key: &TaskKey) {
        lock(&self.tasks).remove(key);
    }
}
