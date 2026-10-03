//! Where the dashboard's data comes from (CONTRACT §20.4). [`FakeSource`] (fixtures for tests,
//! `--demo` and snapshots) lives here; `NodeSource` (over `node.sock`) lives in the node crate,
//! which depends on this one (never the other way round).

use crate::model::{Served, Snapshot};

/// A user action the dashboard asks the node to perform. Each maps to an existing command path
/// and keeps its rules (CONTRACT §20.1): signing actions decode the body and check the server's
/// Lookup exactly like `moochy accept`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    PauseDonation(String),
    ResumeDonation(String),
    StopDonation(String),
    LowerDonation { id: String, budget_uusd: u64 },
    Accept { request_id: String },
    Refuse { request_id: String, reason: String },
    OrgAdd { org: String, repo: String },
    OrgRemove { org: String, repo: String },
    RevokeBox(String),
    /// Revoke a box enrollment token (§17.1) and every box it enrolled (link RevokeBox with a `bt_` id).
    RevokeBoxToken(String),
    Refresh,
}

/// The result of an action, shown as a toast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionResult {
    Done(String),
    Refused(String),
    /// Run `moochy <args…>` in the foreground on the real terminal (the TUI suspends exactly like
    /// Ctrl-Z, then resumes and refreshes): owner-key actions keep the CLI's passphrase prompt,
    /// decoded body and Lookup confirmation unchanged (A217/A218).
    Terminal(Vec<String>),
}

/// Something that changed: the app re-renders after each.
#[derive(Clone, Debug)]
pub enum SourceEvent {
    Snapshot(Box<Snapshot>),
    Toast(String),
    Disconnected(String),
}

/// `run` calls these on its own worker thread, never on the UI thread: blocking (with the source's
/// own timeouts) is fine. After each [`Source::act`], the worker takes a fresh [`Source::snapshot`].
pub trait Source: Send {
    /// The current state (blocking, bounded by the source's own timeout).
    fn snapshot(&mut self) -> Result<Snapshot, String>;
    /// Performs an action (bounded by a timeout); never panics.
    fn act(&mut self, action: Action) -> ActionResult;
    /// The clock the data is relative to (fixtures use a fixed one so snapshots are stable).
    fn now_ms(&self) -> u64 {
        system_now_ms()
    }
    /// For a source with no push stream of its own: how often the worker calls [`Source::tick`]
    /// (between actions). `None` (the default) = never.
    fn tick_every(&self) -> Option<std::time::Duration> {
        None
    }
    /// Advances the source; returns a toast to show, if any. The worker takes a snapshot after.
    fn tick(&mut self) -> Option<String> {
        None
    }
}

#[must_use]
pub fn system_now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Fixtures: the same data on every run, so snapshots are deterministic. Actions change the
/// fixture state the way the node would, so `--demo` is interactive.
#[derive(Clone, Debug, Default)]
pub struct FakeSource {
    pub state: Snapshot,
    pub now_ms: u64,
    /// Interactive `--demo`: a new request every few seconds, so motion can be judged.
    pub live: bool,
    started: Option<std::time::Instant>,
    ticks: u64,
}

impl FakeSource {
    #[must_use]
    pub fn new(state: Snapshot, now_ms: u64) -> FakeSource {
        FakeSource { state, now_ms, ..FakeSource::default() }
    }
}

impl Source for FakeSource {
    fn snapshot(&mut self) -> Result<Snapshot, String> {
        Ok(self.state.clone())
    }

    fn act(&mut self, action: Action) -> ActionResult {
        let set = |s: &mut Snapshot, id: &str, status: &str| -> ActionResult {
            match s.donations.iter_mut().find(|d| d.id == id) {
                Some(d) => {
                    d.status = status.into();
                    ActionResult::Done(format!("Donation to {} {status}", d.target))
                }
                None => ActionResult::Refused(format!("no donation {id}")),
            }
        };
        match action {
            Action::PauseDonation(id) => set(&mut self.state, &id, "paused"),
            Action::ResumeDonation(id) => set(&mut self.state, &id, "active"),
            Action::StopDonation(id) => set(&mut self.state, &id, "stopped"),
            Action::LowerDonation { id, budget_uusd } => match self.state.donations.iter_mut().find(|d| d.id == id) {
                Some(d) if budget_uusd < d.budget_uusd => {
                    d.budget_uusd = budget_uusd;
                    ActionResult::Done(format!("Limit lowered to {}", crate::widgets::dollars(budget_uusd)))
                }
                Some(_) => ActionResult::Refused("a limit can only be lowered here".into()),
                None => ActionResult::Refused(format!("no donation {id}")),
            },
            Action::Accept { request_id } => {
                self.state.pending.retain(|p| p.request_id != request_id);
                ActionResult::Terminal(vec!["accept".into(), request_id])
            }
            Action::Refuse { request_id, .. } => {
                self.state.pending.retain(|p| p.request_id != request_id);
                ActionResult::Done("Refused".into())
            }
            Action::OrgAdd { org, repo } => ActionResult::Terminal(vec!["org".into(), "add".into(), org, repo]),
            Action::OrgRemove { org, repo } => ActionResult::Terminal(vec!["org".into(), "remove".into(), org, repo]),
            Action::RevokeBoxToken(id) => match self.state.box_tokens.iter_mut().find(|b| b.id == id) {
                Some(b) => {
                    b.revoked = true;
                    ActionResult::Done(format!("Token {id} revoked"))
                }
                None => ActionResult::Refused(format!("no token {id}")),
            },
            Action::RevokeBox(id) => {
                self.state.boxes.retain(|b| b.id != id);
                ActionResult::Done(format!("Box {id} revoked"))
            }
            Action::Refresh => ActionResult::Done("Refreshed".into()),
        }
    }

    fn now_ms(&self) -> u64 {
        self.now_ms
    }

    fn tick_every(&self) -> Option<std::time::Duration> {
        self.live.then_some(std::time::Duration::from_secs(3))
    }

    fn tick(&mut self) -> Option<String> {
        const MODELS: [&str; 4] = ["claude-sonnet-5-5", "claude-haiku-4-5", "deepseek-v4", "gpt-5.2-mini"];
        const PROJECTS: [&str; 3] = ["github/tokio-rs/axum", "github/acme/widgets", "gitlab/inkscape/inkscape"];
        let started = *self.started.get_or_insert_with(std::time::Instant::now);
        let at = self.now_ms.saturating_add(u64::try_from(started.elapsed().as_millis()).unwrap_or(0));
        self.ticks = self.ticks.saturating_add(1);
        let k = usize::try_from(self.ticks).unwrap_or(0);
        let pick = |a: &[&str], m: usize| a.get(k.wrapping_mul(m).checked_rem(a.len()).unwrap_or(0)).copied().unwrap_or_default().to_string();
        let tokens = 900u64.saturating_add(self.ticks.wrapping_mul(7_919) % 30_000);
        let row = Served {
            at_ms: at,
            direction: if self.ticks.is_multiple_of(3) { "used" } else { "served" }.into(),
            project: pick(&PROJECTS, 1),
            model: pick(&MODELS, 3),
            tokens_in: tokens,
            tokens_out: tokens / 6,
            cost_uusd: tokens.saturating_mul(4),
            latency_ms: 300u64.saturating_add(self.ticks.wrapping_mul(613) % 2_400),
            outcome: "ok".into(),
        };
        let toast = (self.ticks % 4 == 1).then(|| format!("{} {} for {}", if row.direction == "served" { "Served" } else { "Used" }, row.model, row.project));
        self.state.served.insert(0, row);
        self.state.served.truncate(200);
        toast
    }
}
