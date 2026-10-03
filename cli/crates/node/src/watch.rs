//! LocalControl `Watch` (CONTRACT §20): the live event stream of `moochy tui`. One task per
//! watcher, bounded queue, at most [`MAX_PER_SEC`] events a second; anything that does not fit is
//! coalesced into one `snapshot` event (the client re-reads the state). Metadata only.

use crate::node::{Node, lock};
use crate::pb::local::{JournalEntry, WatchEvent};
use std::hash::{Hash as _, Hasher as _};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};
use tonic::Status;

pub const QUEUE: usize = 64;
const MAX_PER_SEC: u32 = 20;
/// State without a change channel (approvals, claims, donations, pause) is compared this often.
const POLL: Duration = Duration::from_millis(250);

fn ev(kind: &str, detail: String, served: Option<JournalEntry>) -> WatchEvent {
    WatchEvent { t_ms: i64::try_from(crate::util::now_ms()).unwrap_or(i64::MAX), kind: kind.into(), served, detail }
}

/// Hashes of the polled state: (pending, donations, paused).
fn fingerprint(n: &Node) -> (u64, u64, bool) {
    let mut p = std::collections::hash_map::DefaultHasher::new();
    for a in lock(&n.approvals).iter() {
        a.request_id.hash(&mut p);
    }
    for c in lock(&n.claims).iter() {
        (&c.target_id, c.paused_since_ms, c.releases_at_ms).hash(&mut p);
    }
    let mut d: Vec<(String, String)> = lock(&n.own_pledges).iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    d.sort_unstable();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    d.hash(&mut h);
    (p.finish(), h.finish(), n.paused.load(Ordering::Relaxed))
}

/// Runs until the client hangs up or the node stops.
pub async fn run(node: Arc<Node>, tx: mpsc::Sender<Result<WatchEvent, Status>>) {
    let mut journal = node.journal_tx.subscribe();
    let mut link = node.link_state.subscribe();
    let mut pools = node.pool_gen.subscribe();
    let mut alerts = node.keylog.as_ref().map(|k| k.alerts.subscribe());
    let mut shutdown = node.shutdown.subscribe();
    let mut tick = tokio::time::interval(POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last = fingerprint(&node);
    let (mut window, mut sent) = (Instant::now(), 0u32);
    // A `snapshot` is owed (coalesced events); sent on the next tick.
    let mut dirty = false;
    loop {
        let mut out: Vec<WatchEvent> = Vec::new();
        tokio::select! {
            r = journal.recv() => match r {
                Ok(e) => out.push(ev("served", String::new(), Some(JournalEntry { request: Vec::new(), response: Vec::new(), ..e }))),
                Err(broadcast::error::RecvError::Lagged(_)) => dirty = true,
                Err(broadcast::error::RecvError::Closed) => return,
            },
            r = link.changed() => {
                if r.is_err() {
                    return;
                }
                out.push(ev("link", crate::ctl::link_state(&node), None));
            }
            r = pools.changed() => {
                if r.is_err() {
                    return;
                }
                dirty = true;
            }
            r = async {
                match alerts.as_mut() {
                    Some(a) => a.changed().await.map(|()| a.borrow_and_update().last().cloned().unwrap_or_default()),
                    None => std::future::pending().await,
                }
            } => match r {
                Ok(a) => out.push(ev("alert", a, None)),
                Err(_) => alerts = None,
            },
            _ = tick.tick() => {
                let f = fingerprint(&node);
                if f.0 != last.0 {
                    out.push(ev("pending", String::new(), None));
                }
                if f.1 != last.1 {
                    out.push(ev("donation", String::new(), None));
                }
                if f.2 != last.2 {
                    out.push(ev("link", if f.2 { "paused".into() } else { crate::ctl::link_state(&node) }, None));
                }
                last = f;
                if dirty && tx.try_send(Ok(ev("snapshot", String::new(), None))).is_ok() {
                    dirty = false;
                }
            }
            _ = shutdown.changed() => return,
            () = tx.closed() => return,
        }
        if window.elapsed() >= Duration::from_secs(1) {
            (window, sent) = (Instant::now(), 0);
        }
        for e in out {
            if sent >= MAX_PER_SEC || tx.try_send(Ok(e)).is_err() {
                dirty = true;
            } else {
                sent = sent.saturating_add(1);
            }
        }
    }
}
