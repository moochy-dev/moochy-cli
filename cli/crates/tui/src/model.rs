//! What the dashboard shows: a typed snapshot of the user's Moochy state, as the local node knows
//! it (CONTRACT §20.4). Money is integer µ$ (`*_uusd`), times are Unix ms. Strings are raw here;
//! views render them through [`crate::sanitize::clean`].

/// Everything the tabs render. `mo-tui` fills it from `node.sock` ([`crate::source::NodeSource`])
/// or from fixtures ([`crate::source::FakeSource`]).
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub me: Me,
    pub donations: Vec<Donation>,
    pub served: Vec<Served>,
    pub projects: Vec<Project>,
    pub orgs: Vec<Org>,
    pub pending: Vec<Pending>,
    pub decisions: Vec<Decision>,
    pub devices: Vec<Device>,
    pub boxes: Vec<BoxDevice>,
    pub keys: Vec<ProviderKey>,
    pub activity: Vec<Activity>,
    pub alerts: Vec<Alert>,
    /// Per-day totals for the last 30 days (oldest first), for sparklines.
    pub donated_per_day_uusd: Vec<u64>,
    pub used_per_day_uusd: Vec<u64>,
    /// The node's configuration as (key, value) for the Settings tab — never a secret value.
    pub config: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct Me {
    pub handle: String,
    pub pseudonym: String,
    pub relay: String,
    pub connected: bool,
    pub roles: Vec<String>,
    pub lockdown: String,
}

#[derive(Clone, Debug, Default)]
pub struct Donation {
    pub id: String,
    /// `github/owner/name`, `gitlab/…`, or an org path when [`Donation::org`] is true.
    pub target: String,
    pub org: bool,
    /// CONTRACT §24: the sponsored person (`github/{login}`, `gitlab/{username}`, link.proto
    /// `Donation.person`); empty unless this is a person sponsorship.
    pub person: String,
    pub status: String,
    pub budget_uusd: u64,
    pub per_task_cap_uusd: u64,
    pub spent_uusd: u64,
    pub schedule: String,
    pub models: Vec<String>,
    /// Org donations: spend per project this month.
    pub per_repo_uusd: Vec<(String, u64)>,
}

#[derive(Clone, Debug, Default)]
pub struct Served {
    pub at_ms: u64,
    /// "served" (my device served it) or "used" (my project used donated tokens).
    pub direction: String,
    pub project: String,
    pub model: String,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_uusd: u64,
    pub latency_ms: u64,
    pub outcome: String,
}

#[derive(Clone, Debug, Default)]
pub struct Project {
    pub id: String,
    pub slug: String,
    pub donors: u32,
    pub pending: u32,
    pub month_uusd: u64,
    pub goal_uusd: u64,
    pub members: Vec<String>,
    pub funded_by: Vec<String>,
    /// §19.2a: 0 = active; else the Unix ms it was paused at.
    pub paused_since_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Org {
    pub id: String,
    pub path: String,
    pub covered: Vec<CoveredRepo>,
    pub donors: u32,
    pub month_uusd: u64,
    pub paused_since_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct CoveredRepo {
    pub slug: String,
    pub used_uusd: u64,
    /// µ$ per month this repo may draw from the org's donations; 0 = no cap (§19.5).
    pub share_cap_uusd: u64,
}

/// Something waiting for this user: a donor to accept, an org repo to add, a revocation…
#[derive(Clone, Debug, Default)]
pub struct Pending {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub subject: String,
    pub summary: String,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Decision {
    pub at_ms: u64,
    pub target: String,
    pub donor: String,
    pub event: String,
    pub via: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub roles: Vec<String>,
    pub online: bool,
    pub this_device: bool,
}

#[derive(Clone, Debug, Default)]
pub struct BoxDevice {
    pub id: String,
    pub project: String,
    pub expires_at_ms: u64,
    pub online: bool,
}

/// A provider key as the keystore reports it: presence and metadata, never the value.
#[derive(Clone, Debug, Default)]
pub struct ProviderKey {
    pub provider: String,
    pub present: bool,
    pub models: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Activity {
    pub at_ms: u64,
    pub text: String,
}

#[derive(Clone, Debug, Default)]
pub struct Alert {
    pub level: String,
    pub text: String,
}
