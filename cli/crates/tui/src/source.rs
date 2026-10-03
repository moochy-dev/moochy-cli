//! Where the dashboard's data comes from (CONTRACT §20.4). [`FakeSource`] (fixtures for tests,
//! `--demo` and snapshots) lives here; `NodeSource` (over `node.sock`) lives in the node crate,
//! which depends on this one (never the other way round).

use crate::model::Snapshot;

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
}
