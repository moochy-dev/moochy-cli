//! The Worker's durable local state in one append-only log (plan 07 §6.4–6.5, 05 §6):
//! - **outbox**: signed receipts, kept until acked + 7 days (for `receipt.replay_since`);
//! - **served-task set**: `(gateway_device, task_id)` within the ±10 min window (03 §7.2);
//! - **local reservation counters**: device monthly cap and per-pledge budgets, counting
//!   every open attempt (layer 2 of 05 §6).
//!
//! Durability (CONTRACT §13: no fsync before the ack or in the per-chunk path):
//! reservations, served entries, acks and releases are decided in memory and *written*
//! (page cache, survives a process crash) without fsync; [`Store::put_receipt`] writes the
//! receipt and its settlement and fsyncs, which also makes everything before it durable.
//! After a power loss, a reservation whose settlement was lost is settled pessimistically
//! at its amount after 24 h (like the Relay's sweep, 05 §5.2).
//!
//! Frames: `u32_be len | u32_be crc32(body) | body`. A torn or corrupt tail (crash mid-
//! write) is truncated on open. Blocking file I/O: call from a blocking-friendly thread.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const RECEIPT_RETENTION_MS: u64 = 7 * 24 * 3600 * 1000;
pub const TASK_WINDOW_MS: u64 = 10 * 60 * 1000;
pub const STALE_RESERVATION_MS: u64 = 24 * 3600 * 1000;
const MAX_RECORD: usize = 16 << 20;
const SERVED_PRUNE_AT: usize = 8192;

#[derive(Debug)]
pub enum StoreError {
    /// Task id timestamp outside ±10 min of our clock (`unauthorized_task`).
    Stale,
    /// `(gateway_device, task_id)` already served (`unauthorized_task`).
    Replay,
    /// A local cap would be exceeded (`local_cap`, retryable elsewhere).
    Cap(&'static str),
    /// Reservation key already open.
    Duplicate,
    Io(io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stale => f.write_str("task id outside the freshness window"),
            Self::Replay => f.write_str("task already served"),
            Self::Cap(w) => write!(f, "local cap exceeded: {w}"),
            Self::Duplicate => f.write_str("reservation already open"),
            Self::Io(e) => write!(f, "store I/O: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// One local reservation (05 §5.1 amount, computed by the caller with `reserve()`).
#[derive(Clone, Copy, Debug)]
pub struct Reservation<'a> {
    /// Attempt key, e.g. `task_id || u64_be(attempt)`; the receipt uses the same key.
    pub key: &'a [u8],
    pub pledge_id: &'a str,
    /// The pledge's current period id (periods are anchored per pledge, 05 §9).
    pub pledge_period: u64,
    pub pledge_budget_uusd: u64,
    pub per_task_cap_uusd: u64,
    pub amount_uusd: u64,
    pub device_cap_uusd: u64,
    pub now_ms: u64,
}

struct Receipt {
    ts_ms: u64,
    payload: Vec<u8>,
    acked_ms: Option<u64>,
}

struct Open {
    pledge: String,
    period: u64,
    month: u32,
    amount: u64,
    ts_ms: u64,
}

#[derive(Default)]
struct State {
    receipts: BTreeMap<Vec<u8>, Receipt>,
    served: HashMap<(String, String), u64>,
    device_spent: HashMap<u32, u64>,
    pledge_spent: HashMap<(String, u64), u64>,
    open: HashMap<Vec<u8>, Open>,
}

pub struct Store {
    path: PathBuf,
    file: File,
    st: State,
}

const PUT: u8 = 1;
const ACK: u8 = 2;
const SERVED: u8 = 3;
const RESERVE: u8 = 4;
const SETTLE: u8 = 5;
const SPENT_DEVICE: u8 = 6;
const SPENT_PLEDGE: u8 = 7;

impl Store {
    /// Open (creating if needed), replay, truncate a torn tail, compact.
    pub fn open(path: &Path, now_ms: u64) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).append(true).create(true).open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let mut st = State::default();
        let good = replay(&bytes, &mut st);
        if good < bytes.len() {
            file.set_len(u64::try_from(good).unwrap_or(0))?;
            file.sync_all()?;
        }
        let mut s = Self { path: path.to_owned(), file, st };
        s.compact(now_ms)?;
        Ok(s)
    }

    fn append(&mut self, rec: &[u8], sync: bool) -> io::Result<()> {
        self.file.write_all(rec)?;
        if sync {
            self.file.sync_data()?;
        }
        Ok(())
    }

    // --- served-task set ---

    /// 03 §7.2 checks 4–5: freshness and never-served. Records the pair on success.
    pub fn check_served(&mut self, gateway_device: &str, task_id: &str, task_ts_ms: u64, now_ms: u64) -> Result<(), StoreError> {
        if task_ts_ms.abs_diff(now_ms) > TASK_WINDOW_MS {
            return Err(StoreError::Stale);
        }
        let k = (gateway_device.to_owned(), task_id.to_owned());
        if self.st.served.contains_key(&k) {
            return Err(StoreError::Replay);
        }
        let rec = frame(SERVED, |w| {
            w.bytes(gateway_device.as_bytes());
            w.bytes(task_id.as_bytes());
            w.u64(task_ts_ms);
        });
        self.append(&rec, false)?;
        self.st.served.insert(k, task_ts_ms);
        if self.st.served.len() > SERVED_PRUNE_AT {
            prune_served(&mut self.st, now_ms);
        }
        Ok(())
    }

    // --- local reservations ---

    /// Reserve against the device monthly cap, the pledge budget and the per-task cap,
    /// counting all open attempts. In memory + written, not fsynced (see module docs).
    pub fn reserve(&mut self, r: &Reservation<'_>) -> Result<(), StoreError> {
        if self.st.open.contains_key(r.key) {
            return Err(StoreError::Duplicate);
        }
        if r.amount_uusd > r.per_task_cap_uusd {
            return Err(StoreError::Cap("per-task cap"));
        }
        let month = month_of(r.now_ms);
        let dev_used = self.device_used(month);
        if dev_used.checked_add(r.amount_uusd).is_none_or(|t| t > r.device_cap_uusd) {
            return Err(StoreError::Cap("device monthly cap"));
        }
        let pl_used = self.pledge_used(r.pledge_id, r.pledge_period);
        if pl_used.checked_add(r.amount_uusd).is_none_or(|t| t > r.pledge_budget_uusd) {
            return Err(StoreError::Cap("pledge budget"));
        }
        let rec = frame(RESERVE, |w| {
            w.bytes(r.key);
            w.bytes(r.pledge_id.as_bytes());
            w.u64(r.pledge_period);
            w.u64(u64::from(month));
            w.u64(r.amount_uusd);
            w.u64(r.now_ms);
        });
        self.append(&rec, false)?;
        apply_reserve(&mut self.st, r.key.to_vec(), r.pledge_id.to_owned(), r.pledge_period, month, r.amount_uusd, r.now_ms);
        Ok(())
    }

    fn device_used(&self, month: u32) -> u64 {
        let open = self.st.open.values().fold(0u64, |a, o| a.saturating_add(o.amount));
        self.st.device_spent.get(&month).copied().unwrap_or(0).saturating_add(open)
    }

    fn pledge_used(&self, pledge: &str, period: u64) -> u64 {
        let open = self.st.open.values().filter(|o| o.pledge == pledge).fold(0u64, |a, o| a.saturating_add(o.amount));
        self.st.pledge_spent.get(&(pledge.to_owned(), period)).copied().unwrap_or(0).saturating_add(open)
    }

    /// Device headroom for `worker.offer.local_cap_left`.
    pub fn device_left(&self, device_cap_uusd: u64, now_ms: u64) -> u64 {
        device_cap_uusd.saturating_sub(self.device_used(month_of(now_ms)))
    }

    pub fn pledge_left(&self, pledge_id: &str, period: u64, budget_uusd: u64) -> u64 {
        budget_uusd.saturating_sub(self.pledge_used(pledge_id, period))
    }

    /// Release a reservation with proof of zero spend (NACK before the provider call).
    pub fn release(&mut self, key: &[u8]) -> io::Result<()> {
        if self.st.open.contains_key(key) {
            self.append(&settle_rec(key, 0), false)?;
            apply_settle(&mut self.st, key, 0);
        }
        Ok(())
    }

    // --- outbox ---

    /// Store a signed receipt and settle its reservation at `cost_uusd` (attributed to the
    /// attempt's start period), then fsync. Call before sending `task.end`.
    pub fn put_receipt(&mut self, key: &[u8], payload: &[u8], cost_uusd: u64, now_ms: u64) -> io::Result<()> {
        let mut rec = Vec::with_capacity(payload.len().saturating_add(key.len()).saturating_add(64));
        if self.st.open.contains_key(key) {
            rec.extend_from_slice(&settle_rec(key, cost_uusd));
        }
        rec.extend_from_slice(&frame(PUT, |w| {
            w.bytes(key);
            w.u64(now_ms);
            w.bytes(payload);
        }));
        self.append(&rec, true)?;
        apply_settle(&mut self.st, key, cost_uusd);
        self.st.receipts.insert(key.to_vec(), Receipt { ts_ms: now_ms, payload: payload.to_vec(), acked_ms: None });
        Ok(())
    }

    /// `receipt.ack` (sent after the Relay's durable commit). Returns false if unknown.
    pub fn ack(&mut self, key: &[u8], now_ms: u64) -> io::Result<bool> {
        if self.st.receipts.get(key).is_none_or(|r| r.acked_ms.is_some()) {
            return Ok(false);
        }
        let rec = frame(ACK, |w| {
            w.bytes(key);
            w.u64(now_ms);
        });
        self.append(&rec, false)?;
        if let Some(r) = self.st.receipts.get_mut(key) {
            r.acked_ms = Some(now_ms);
        }
        Ok(true)
    }

    /// Receipts not yet acked, to replay after (re)connecting.
    pub fn unacked(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.st.receipts.iter().filter(|(_, r)| r.acked_ms.is_none()).map(|(k, r)| (k.as_slice(), r.payload.as_slice()))
    }

    /// Every retained receipt stored at or after `since_ms` (`receipt.replay_since`).
    pub fn since(&self, since_ms: u64) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.st.receipts.iter().filter(move |(_, r)| r.ts_ms >= since_ms).map(|(k, r)| (k.as_slice(), r.payload.as_slice()))
    }

    /// Rewrite the log with only live state: unacked receipts, receipts acked < 7 days ago,
    /// served entries inside the window, spent totals, open reservations (those older than
    /// 24 h are settled at their amount). Atomic: temp file, fsync, rename, fsync dir.
    pub fn compact(&mut self, now_ms: u64) -> io::Result<()> {
        let stale: Vec<Vec<u8>> =
            self.st.open.iter().filter(|(_, o)| now_ms.saturating_sub(o.ts_ms) > STALE_RESERVATION_MS).map(|(k, _)| k.clone()).collect();
        for k in stale {
            let amount = self.st.open.get(&k).map_or(0, |o| o.amount);
            apply_settle(&mut self.st, &k, amount);
        }
        self.st.receipts.retain(|_, r| r.acked_ms.is_none_or(|a| now_ms.saturating_sub(a) <= RECEIPT_RETENTION_MS));
        prune_served(&mut self.st, now_ms);
        let cur = month_of(now_ms);
        // Keep this and last month for the device; pledge periods are opaque, kept as is
        // (ponytail: one small record per pledge period, prune when it ever matters).
        self.st.device_spent.retain(|m, _| *m >= prev_month(cur));

        let mut out = Vec::new();
        for (m, v) in &self.st.device_spent {
            out.extend(frame(SPENT_DEVICE, |w| {
                w.u64(u64::from(*m));
                w.u64(*v);
            }));
        }
        for ((p, per), v) in &self.st.pledge_spent {
            out.extend(frame(SPENT_PLEDGE, |w| {
                w.bytes(p.as_bytes());
                w.u64(*per);
                w.u64(*v);
            }));
        }
        for (k, o) in &self.st.open {
            out.extend(frame(RESERVE, |w| {
                w.bytes(k);
                w.bytes(o.pledge.as_bytes());
                w.u64(o.period);
                w.u64(u64::from(o.month));
                w.u64(o.amount);
                w.u64(o.ts_ms);
            }));
        }
        for ((g, t), ts) in &self.st.served {
            out.extend(frame(SERVED, |w| {
                w.bytes(g.as_bytes());
                w.bytes(t.as_bytes());
                w.u64(*ts);
            }));
        }
        for (k, r) in &self.st.receipts {
            out.extend(frame(PUT, |w| {
                w.bytes(k);
                w.u64(r.ts_ms);
                w.bytes(&r.payload);
            }));
            if let Some(a) = r.acked_ms {
                out.extend(frame(ACK, |w| {
                    w.bytes(k);
                    w.u64(a);
                }));
            }
        }
        let tmp = self.path.with_extension("compact");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            File::open(dir)?.sync_all()?;
        }
        self.file = OpenOptions::new().append(true).open(&self.path)?;
        Ok(())
    }
}

fn prune_served(st: &mut State, now_ms: u64) {
    st.served.retain(|_, ts| ts.saturating_add(TASK_WINDOW_MS).saturating_add(60_000) >= now_ms);
}

fn apply_reserve(st: &mut State, key: Vec<u8>, pledge: String, period: u64, month: u32, amount: u64, ts_ms: u64) {
    st.open.insert(key, Open { pledge, period, month, amount, ts_ms });
}

fn apply_settle(st: &mut State, key: &[u8], cost: u64) {
    if let Some(o) = st.open.remove(key) {
        let d = st.device_spent.entry(o.month).or_insert(0);
        *d = d.saturating_add(cost);
        let p = st.pledge_spent.entry((o.pledge, o.period)).or_insert(0);
        *p = p.saturating_add(cost);
    }
}

fn settle_rec(key: &[u8], cost: u64) -> Vec<u8> {
    frame(SETTLE, |w| {
        w.bytes(key);
        w.u64(cost);
    })
}

/// Apply every intact frame; returns the length of the intact prefix.
fn replay(bytes: &[u8], st: &mut State) -> usize {
    let mut off = 0usize;
    loop {
        let Some(hdr) = bytes.get(off..off.saturating_add(8)) else { return off };
        let (l, c) = hdr.split_at(4);
        let len = u32::from_be_bytes(l.try_into().unwrap_or_default()) as usize;
        let crc = u32::from_be_bytes(c.try_into().unwrap_or_default());
        let end = off.saturating_add(8).saturating_add(len);
        let Some(body) = bytes.get(off.saturating_add(8)..end) else { return off };
        if len > MAX_RECORD || crc32(body) != crc || apply(body, st).is_none() {
            return off;
        }
        off = end;
    }
}

fn apply(body: &[u8], st: &mut State) -> Option<()> {
    let mut r = Rd(body);
    let s = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
    match r.u8()? {
        PUT => {
            let (k, ts, p) = (r.bytes()?.to_vec(), r.u64()?, r.bytes()?.to_vec());
            st.receipts.insert(k, Receipt { ts_ms: ts, payload: p, acked_ms: None });
        }
        ACK => {
            let (k, ts) = (r.bytes()?, r.u64()?);
            if let Some(x) = st.receipts.get_mut(k) {
                x.acked_ms = Some(ts);
            }
        }
        SERVED => {
            let (g, t, ts) = (s(r.bytes()?)?, s(r.bytes()?)?, r.u64()?);
            st.served.insert((g, t), ts);
        }
        RESERVE => {
            let (k, p) = (r.bytes()?.to_vec(), s(r.bytes()?)?);
            let (per, m, amt, ts) = (r.u64()?, u32::try_from(r.u64()?).ok()?, r.u64()?, r.u64()?);
            apply_reserve(st, k, p, per, m, amt, ts);
        }
        SETTLE => {
            let (k, c) = (r.bytes()?, r.u64()?);
            apply_settle(st, k, c);
        }
        SPENT_DEVICE => {
            let (m, v) = (u32::try_from(r.u64()?).ok()?, r.u64()?);
            let e = st.device_spent.entry(m).or_insert(0);
            *e = e.saturating_add(v);
        }
        SPENT_PLEDGE => {
            let (p, per, v) = (s(r.bytes()?)?, r.u64()?, r.u64()?);
            let e = st.pledge_spent.entry((p, per)).or_insert(0);
            *e = e.saturating_add(v);
        }
        _ => return None,
    }
    r.0.is_empty().then_some(())
}

struct W(Vec<u8>);

impl W {
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
        self.0.extend_from_slice(b);
    }
}

fn frame(kind: u8, f: impl FnOnce(&mut W)) -> Vec<u8> {
    let mut w = W(vec![kind]);
    f(&mut w);
    let body = w.0;
    let mut out = Vec::with_capacity(body.len().saturating_add(8));
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&crc32(&body).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().ok()?);
        self.take(n as usize)
    }
}

/// CRC-32 (IEEE 802.3, reflected), bitwise: records are small and written once.
fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = (c >> 1) ^ (0xEDB8_8320 & (c & 1).wrapping_neg());
        }
    }
    !c
}

/// UTC calendar month `YYYYMM` of a Unix time in ms (device counters use calendar months, 05 §9).
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
pub fn month_of(ms: u64) -> u32 {
    // Howard Hinnant's civil_from_days; days < 2^38 so nothing overflows i64.
    let z = (ms / 86_400_000).cast_signed() + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y * 100 + m) as u32
}

fn prev_month(m: u32) -> u32 {
    if m % 100 == 1 { m.saturating_sub(89) } else { m.saturating_sub(1) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn pure() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(month_of(0), 197_001);
        assert_eq!(month_of(1_790_812_800_000), 202_610); // 2026-10-01T00:00Z
        assert_eq!(month_of(1_790_812_799_999), 202_609);
        assert_eq!(month_of(951_782_400_000), 200_002); // 2000-02-29
        assert_eq!(prev_month(202_601), 202_512);
        assert_eq!(prev_month(202_610), 202_609);
    }
}
