//! Where the dashboard's data comes from (CONTRACT §20.4). `mo-tui` implements [`NodeSource`]
//! (over `node.sock`) and [`FakeSource`] (fixtures for tests, `--demo` and snapshots).

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
}

/// Something that changed: the app re-renders after each.
#[derive(Clone, Debug)]
pub enum SourceEvent {
    Snapshot(Box<Snapshot>),
    Toast(String),
    Disconnected(String),
}

pub trait Source: Send {
    /// The current state (blocking, bounded by the source's own timeout).
    fn snapshot(&mut self) -> Result<Snapshot, String>;
    /// Performs an action (bounded by a timeout); never panics.
    fn act(&mut self, action: Action) -> ActionResult;
}

/// Fixtures: the same data on every run, so snapshots are deterministic.
#[derive(Clone, Debug, Default)]
pub struct FakeSource {
    pub state: Snapshot,
}

impl Source for FakeSource {
    fn snapshot(&mut self) -> Result<Snapshot, String> {
        Ok(self.state.clone())
    }

    fn act(&mut self, action: Action) -> ActionResult {
        ActionResult::Done(format!("{action:?}"))
    }
}
