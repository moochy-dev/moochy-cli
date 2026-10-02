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
    /// Key-log indexes the relay claims for this worker's KEY_ADDED / DONOR_APPROVED.
    pub key_log_index: u64,
    pub approval_log_index: u64,
    pub donor: String,
    pub dialects: Vec<String>,
    pub models: Vec<String>,
    pub hint: u32,
    /// `PoolWorker.served`: (model, provider) the worker serves it through (§15.4 exclusion).
    pub served: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct RepoPool {
    pub repo_id: String,
    pub slug: Option<String>,
    pub workers: Vec<PoolWorker>,
    /// Repo setting `PoolSync.auto_cache` (07 §4.2).
    pub auto_cache: bool,
    /// Repo settings (§15.4): providers never sealed to, and the unsandboxed-tools opt-in.
    pub excluded_providers: Vec<String>,
    /// Repo setting `PoolSync.pinned_donors`: donors the project prefers (tried first).
    pub pinned_donors: Vec<String>,
    pub allow_unsandboxed_tools: bool,
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
    /// Recent catalog versions (bounded): a Worker prices with the version named in `Assign`.
    pub catalogs: Mutex<VecDeque<Arc<Catalog>>>,
    /// Worker: one warm adapter per provider key.
    pub adapters: Vec<Arc<Adapter>>,
    /// Worker: this donor's own donations (pledge id → status), from `ListDonations` on our own
    /// session, and when they were fetched (ms). The relay's pledge assignment is never trusted
    /// alone (T-03-088).
    pub own_pledges: Mutex<HashMap<String, String>>,
    /// Worker: local model server mapping, public slug → server model id, and the ids it lists.
    pub local_models: HashMap<String, String>,
    pub local_served: std::collections::HashSet<String>,
    /// Worker: serializes `ListDonations` refreshes (T-03-088); value = last fetch (ms).
    pub pledge_refresh: tokio::sync::Mutex<u64>,
    /// The process locked itself down (§15.2): required to donate (A222).
    pub locked: bool,
    /// Worker: single-use jailed request validators (CONTRACT §15.2).
    pub validator: Option<Arc<crate::validator::Pool>>,
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
    /// Provider rate-limit headroom per served model: (percent, expiry ms) (E31).
    pub rl_headroom: Mutex<HashMap<String, (u8, u64)>>,
    pub gateway_tasks: AtomicU32,
    pub journal: Mutex<VecDeque<JournalEntry>>,
    pub journal_tx: broadcast::Sender<JournalEntry>,
    pub shutdown: watch::Sender<bool>,
    /// When the relay link last came up (ms): the relay's pools refill as donors reconnect.
    pub link_up_ms: AtomicU64,
    /// Relay server_time − node clock at the last Hello.
    pub clock_skew_ms: std::sync::atomic::AtomicI64,
    /// Evidence of the last consumed tasks, for `moochy report` (bounded).
    pub evidence: Mutex<VecDeque<crate::task::Evidence>>,
    /// Workers already reported as not sealable (log once).
    pub seal_refused: Mutex<std::collections::HashSet<String>>,
    /// Key-log monitor (None = no pinned log key: nothing trusted outside insecure dev).
    pub keylog: Option<Arc<crate::keylog::KeyLog>>,
}

const MAX_SESSIONS: usize = 4096;
const MAX_CATALOGS: usize = 8;
/// Relays ask workers to reconnect within 10 s of a drain (jitter), plus backoff.
const POOL_REFILL_MS: u64 = 20_000;
const JOURNAL_KEEP: usize = 512;

impl Node {
    pub fn new(home: Home, cfg: Config, secrets: Secrets, keys: Option<Keys>, w: WorkerParts, offline: bool) -> Arc<Self> {
        let keylog = crate::keylog::KeyLog::open(&home, &cfg, keys.as_ref().map(|k| k.sign.public()));
        // Rotations persist in the state dir (`ctl.rs`); config's value is the older location.
        let rotated = std::fs::read_to_string(home.state_dir().join("token_gen")).ok().and_then(|s| s.trim().parse::<u64>().ok());
        let token_gen = AtomicU64::new(rotated.unwrap_or(0).max(cfg.token_gen));
        Arc::new(Self {
            home,
            cfg,
            secrets,
            keys,
            offline,
            insecure_dev: std::env::var("MOOCHY_INSECURE_DEV").as_deref() == Ok("1"),
            boot_ms: now_ms(),
            catalog: Mutex::new(if offline { Catalog::stub() } else { Arc::new(Catalog::default()) }),
            catalogs: Mutex::new(VecDeque::new()),
            adapters: w.adapters,
            store: w.store,
            validator: w.validator,
            locked: w.locked,
            local_models: w.local_models,
            local_served: w.local_served,
            pledge_refresh: tokio::sync::Mutex::new(0),
            own_pledges: Mutex::new(HashMap::new()),
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
            rl_headroom: Mutex::new(HashMap::new()),
            gateway_tasks: AtomicU32::new(0),
            journal: Mutex::new(VecDeque::new()),
            journal_tx: broadcast::channel(64).0,
            shutdown: watch::channel(false).0,
            link_up_ms: AtomicU64::new(0),
            clock_skew_ms: std::sync::atomic::AtomicI64::new(0),
            evidence: Mutex::new(VecDeque::new()),
            seal_refused: Mutex::new(std::collections::HashSet::new()),
            keylog,
        })
    }

    /// The id to send to the provider for a catalog entry: a local server's own id (donor
    /// mapping), else the catalog's. `None` = this node does not serve that local slug.
    pub fn provider_model_id(&self, e: &moochy_proto::money::CatalogEntry) -> Option<String> {
        if e.provider == "local" {
            // The donor's explicit mapping, else the catalog's id when the server lists it.
            return self.local_models.get(&e.model).cloned().or_else(|| self.local_served.contains(&e.provider_model_id).then(|| e.provider_model_id.clone()));
        }
        Some(e.provider_model_id.clone())
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

    /// Accept a newer catalog: versions never go down and a version, once seen, never changes
    /// content (a relay could otherwise swap prices under the same number). `false` = refused.
    pub fn set_catalog(&self, c: Catalog) -> bool {
        let mut cur = lock(&self.catalog);
        if c.version <= cur.version {
            return false;
        }
        let c = Arc::new(c);
        let mut h = lock(&self.catalogs);
        if h.len() >= MAX_CATALOGS {
            h.pop_front();
        }
        h.push_back(c.clone());
        *cur = c;
        true
    }

    /// The catalog a Worker prices an `Assign` with: its `catalog_version` (0 = current, older relay).
    pub fn catalog_v(&self, version: u64) -> Option<Arc<Catalog>> {
        if version == 0 {
            return Some(self.catalog());
        }
        lock(&self.catalogs).iter().find(|c| c.version == version).cloned()
    }

    /// The relay's catalog key = the pinned key-log key (`log_key`, `<name>+<hash>+<b64(0x01‖pub)>`).
    pub fn catalog_key(&self) -> Option<[u8; 32]> {
        let vkey = crate::keylog::effective_log_key(&self.cfg)?;
        let vkey = vkey.as_str();
        moochy_keylog::NoteKey::parse(vkey).ok()?;
        let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, vkey.splitn(3, '+').nth(2)?).ok()?;
        match raw.split_first() {
            Some((1, k)) => k.try_into().ok(),
            _ => None,
        }
    }

    /// `CatalogUpdate.sig` = Ed25519(catalog key, lp("moochy/v1/catalog", catalog_json)) (E41).
    /// Without a pinned key the catalog is relay-asserted: accepted only in insecure dev mode.
    pub fn catalog_trusted(&self, json: &[u8], sig: &[u8]) -> Result<(), &'static str> {
        let Some(pk) = self.catalog_key() else {
            return if self.insecure_dev { Ok(()) } else { Err("no pinned key-log key to verify the catalog") };
        };
        let sig = <[u8; 64]>::try_from(sig).map_err(|_| "catalog signature missing")?;
        moochy_proto::crypto::verify(&pk, &crate::util::lp(&[b"moochy/v1/catalog", json]), &sig).map_err(|_| "bad catalog signature")
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
                key_log_index: 0,
                approval_log_index: 0,
                donor: "local".into(),
                dialects: Vec::new(),
                models: Vec::new(),
                hint: 100,
                served: Vec::new(),
            };
            w.dialects = vec!["anthropic.messages".into(), "openai.chat".into()];
            w.models = vec![STUB_MODEL.into()];
            return Some(RepoPool { repo_id: format!("local:{slug}"), slug: Some(slug.into()), workers: vec![w], auto_cache: true, ..RepoPool::default() });
        }
        let repo = lock(&self.pools).values().find(|p| p.slug.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(slug))).map(|p| p.repo_id.clone())?;
        let p = self.sealable_pool(&repo)?;
        // Right after a (re)connect, e.g. a relay restart, donors are still reconnecting: an empty
        // pool then means "not loaded yet" (retryable), not "nobody donates this model".
        let fresh = now_ms().saturating_sub(self.link_up_ms.load(Ordering::Relaxed)) < POOL_REFILL_MS;
        (!(p.workers.is_empty() && fresh)).then_some(p)
    }

    /// The pool of `repo_id` with only the workers this Gateway may seal to. The ONLY way the
    /// submit path reads a pool (submit, NeedWraps): every read re-applies the key-log rule
    /// (A174), so a later DONOR_REVOKED or a stale/forked log drops workers at once, and the
    /// signing key is replaced by the logged one (A184).
    pub fn sealable_pool(&self, repo_id: &str) -> Option<RepoPool> {
        let mut p = lock(&self.pools).get(repo_id).cloned()?;
        p.workers.retain_mut(|w| self.sealable(repo_id, w));
        Some(p)
    }

    /// Whether the repo behind `slug` allows auto-caching (no clone of the pool).
    pub fn repo_auto_cache(&self, slug: &str) -> bool {
        self.offline || lock(&self.pools).values().any(|p| p.auto_cache && p.slug.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(slug)))
    }

    /// The sealing rule (CONTRACT §15.4, 06 §10): a Gateway seals only to worker keys that are
    /// logged, unrevoked and owner-approved for the repo in a fresh verified key log, and then
    /// verifies receipts and checkpoints with the LOGGED signing key (A184). No verified log ⇒
    /// nothing is sealed; the relay's pool is taken as-is only under `MOOCHY_INSECURE_DEV=1`
    /// with no verified checkpoint yet (D14). A refusal is logged once per worker.
    fn sealable(&self, repo_id: &str, w: &mut PoolWorker) -> bool {
        let r = match &self.keylog {
            Some(l) => match l.seal(repo_id, w) {
                Ok(sign_pub) => {
                    w.sign_pub = Some(sign_pub);
                    return true;
                }
                Err(moochy_keylog::Code::NoCheckpoint) if self.insecure_dev => return true,
                Err(c) => c.as_str(),
            },
            None if self.insecure_dev => return true,
            None => "no_log_key",
        };
        let mut seen = lock(&self.seal_refused);
        if seen.len() >= 4096 {
            seen.clear();
        }
        if seen.insert(w.worker_device.clone()) {
            crate::util::log("warn", "not sealing to a worker the key log does not approve", &serde_json::json!({"worker": w.worker_device, "repo_id": repo_id, "code": r}));
        }
        false
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
            p.excluded_providers = v.excluded_providers.iter().take(16).filter(|x| plain_id(x)).cloned().collect();
            p.pinned_donors = v.pinned_donors.iter().take(64).filter(|x| plain_id(x)).cloned().collect();
            if v.allow_unsandboxed_tools && !p.allow_unsandboxed_tools {
                crate::util::log("warn", "this project lets tool calls from donated tokens reach agents outside `moochy run`", &serde_json::json!({"repo_id": v.repo_id}));
            }
            p.allow_unsandboxed_tools = v.allow_unsandboxed_tools;
            let before = p.models();
            if v.full {
                p.workers.clear();
            }
            p.workers.retain(|x| !v.removed_worker_devices.contains(&x.worker_device));
            for w in v.workers.iter().take(4096) {
                let Ok(enc_pub) = <[u8; 32]>::try_from(w.enc_pub.as_ref()) else { continue };
                let sign_pub = <[u8; 32]>::try_from(w.sign_pub.as_ref()).ok();
                let pw = PoolWorker {
                    worker_device: w.worker_device.clone(),
                    enc_pub,
                    sign_pub,
                    key_log_index: w.key_log_index,
                    approval_log_index: w.approval_log_index,
                    donor: clean(&w.donor_pseudonym).into_owned(),
                    dialects: w.dialects.iter().filter(|d| plain_id(d)).cloned().collect(),
                    models: w.models.iter().filter(|m| plain_id(m)).cloned().collect(),
                    hint: w.hint.min(100),
                    served: w.served.iter().take(256).filter(|s| plain_id(&s.model) && plain_id(&s.provider)).map(|s| (s.model.clone(), s.provider.clone())).collect(),
                };
                // Kept as advertised; the key-log rule is applied when the pool is read
                // (`pool_for`), so a worker refused before the first checkpoint is not lost.
                p.workers.retain(|x| x.worker_device != pw.worker_device);
                p.workers.push(pw);
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
        crate::journal::append(&e); // durable copy (E62; mo-node journal.rs)
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
pub fn plain_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:/-@+".contains(&c))
}

/// Worker-role parts built at startup.
#[derive(Default)]
pub struct WorkerParts {
    pub adapters: Vec<Arc<Adapter>>,
    /// Local model server: public `local/*` slug → the server's model id.
    pub local_models: HashMap<String, String>,
    /// Local model server: the ids it listed at `keys add`.
    pub local_served: std::collections::HashSet<String>,
    pub store: Option<Arc<Mutex<Store>>>,
    pub validator: Option<Arc<crate::validator::Pool>>,
    /// The process is locked down (CONTRACT §15.2); an unlocked node never donates (A222).
    pub locked: bool,
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
