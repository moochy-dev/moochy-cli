//! `--demo` data: one coherent world (a donor who also maintains two repos and an org), rich
//! enough for every tab, fixed in time so snapshots are byte-for-byte stable. [`hostile`] is the
//! same world with escape sequences in every peer string (E121).

use crate::model::{
    Activity, Alert, BoxDevice, BoxToken, CoveredRepo, Decision, Device, Donation, Lockdown, Me, Org, Pending, Project, ProviderKey, Receipt, ReceiptCheck,
    Served, Snapshot,
};
use crate::source::FakeSource;

/// 2026-10-03 14:05 UTC.
pub const DEMO_NOW_MS: u64 = 1_791_036_300_000;

const MIN: u64 = 60_000;
const HOUR: u64 = 3_600_000;
const DAY: u64 = 86_400_000;

fn s(v: &str) -> String {
    v.to_string()
}

fn ago(ms: u64) -> u64 {
    DEMO_NOW_MS.saturating_sub(ms)
}

/// 1 Nov 2026 00:00 UTC: when the monthly limits start again.
const RENEWS: u64 = 1_793_491_200_000;

/// A 30-day spend curve (µ$ per day, oldest first) that differs per `seed`.
fn trend(seed: u64) -> Vec<u64> {
    (0u64..30).map(|d| (d.wrapping_mul(seed).wrapping_add(seed) % 9).wrapping_mul(120_000).wrapping_add(d.wrapping_mul(9_000))).collect()
}

/// The demo source (`moochy tui --demo`).
#[must_use]
pub fn demo_source() -> FakeSource {
    FakeSource::new(demo(), DEMO_NOW_MS)
}

#[must_use]
pub fn demo() -> Snapshot {
    let models = ["claude-sonnet-5-5", "claude-haiku-4-5", "deepseek-v4", "gpt-5.2-mini", "claude-opus-5-5"];
    let projects = ["github/tokio-rs/axum", "github/rust-lang/rustfmt", "gitlab/inkscape/inkscape", "github/acme/widgets", "github/acme/gadgets"];
    let outcomes = ["ok", "ok", "ok", "ok", "ok", "ok", "refused", "ok", "error", "ok"];
    let served = (0u64..28)
        .map(|i| {
            let idx = |m: u64, len: usize| (i.wrapping_mul(m) as usize).checked_rem(len).unwrap_or(0);
            let tin = 1_200u64.saturating_add(i.wrapping_mul(7_919) % 48_000);
            let tout = 300u64.saturating_add(i.wrapping_mul(3_571) % 9_000);
            Served {
                at_ms: ago(i.saturating_mul(97_000).saturating_add(4_000)),
                direction: if i % 3 == 2 { s("used") } else { s("served") },
                project: s(projects.get(idx(3, projects.len())).copied().unwrap_or_default()),
                model: s(models.get(idx(7, models.len())).copied().unwrap_or_default()),
                tokens_in: tin,
                tokens_out: tout,
                cost_uusd: tin.saturating_mul(3).saturating_add(tout.saturating_mul(15)),
                latency_ms: 380u64.saturating_add(i.wrapping_mul(613) % 4_200),
                outcome: s(outcomes.get(idx(1, outcomes.len())).copied().unwrap_or_default()),
            }
        })
        .collect();
    let donated: Vec<u64> = (0u64..30).map(|d| 400_000u64.saturating_add((d.wrapping_mul(7_331) % 11).wrapping_mul(310_000)).saturating_add(d.wrapping_mul(40_000))).collect();
    let used: Vec<u64> = (0u64..30).map(|d| 150_000u64.saturating_add((d.wrapping_mul(5_113) % 7).wrapping_mul(220_000))).collect();
    Snapshot {
        me: Me {
            handle: s("alice"),
            pseudonym: s("brave-otter-42"),
            relay: s("relay.moochy.dev"),
            web: s("https://moochy.dev"),
            connected: true,
            roles: vec![s("donor"), s("maintainer")],
            lockdown: Lockdown::Enforced(s("landlock + seccomp")),
        },
        donations: vec![
            Donation {
                id: s("don_7f3a"),
                target: s("github/tokio-rs/axum"),
                org: false,
                person: String::new(),
                status: s("active"),
                budget_uusd: 40_000_000,
                per_task_cap_uusd: 500_000,
                spent_uusd: 27_420_000,
                schedule: s("monthly, renews 1 Nov"),
                models: vec![s("claude-sonnet-5-5"), s("claude-haiku-4-5")],
                per_repo_uusd: vec![],
                per_day_uusd: trend(3),
                renews_at_ms: RENEWS,
            },
            Donation {
                id: s("don_19bc"),
                target: s("github/rust-lang/rustfmt"),
                org: false,
                person: String::new(),
                status: s("paused"),
                budget_uusd: 15_000_000,
                per_task_cap_uusd: 250_000,
                spent_uusd: 14_100_000,
                schedule: s("monthly, renews 1 Nov"),
                models: vec![s("deepseek-v4")],
                per_repo_uusd: vec![],
                per_day_uusd: trend(5),
                renews_at_ms: RENEWS,
            },
            Donation {
                id: s("don_a002"),
                target: s("gitlab/inkscape"),
                org: true,
                person: String::new(),
                status: s("active"),
                budget_uusd: 60_000_000,
                per_task_cap_uusd: 1_000_000,
                spent_uusd: 18_650_000,
                schedule: s("weekdays 09:00–18:00 UTC"),
                models: vec![s("claude-opus-5-5"), s("claude-sonnet-5-5")],
                per_repo_uusd: vec![(s("gitlab/inkscape/inkscape"), 12_300_000), (s("gitlab/inkscape/extensions"), 4_100_000), (s("gitlab/inkscape/website"), 2_250_000)],
                per_day_uusd: trend(7),
                renews_at_ms: RENEWS,
            },
            Donation {
                id: s("don_0c11"),
                target: s("github/sharkdp/bat"),
                org: false,
                person: String::new(),
                status: s("stopped"),
                budget_uusd: 10_000_000,
                per_task_cap_uusd: 200_000,
                spent_uusd: 10_000_000,
                schedule: s("one-off"),
                models: vec![s("gpt-5.2-mini")],
                per_repo_uusd: vec![],
                per_day_uusd: trend(11),
                renews_at_ms: RENEWS,
            },
        ],
        served,
        projects: vec![
            Project {
                id: s("prj_widgets"),
                slug: s("github/acme/widgets"),
                donors: 7,
                pending: 2,
                month_uusd: 31_250_000,
                goal_uusd: 50_000_000,
                members: vec![s("alice"), s("bob"), s("chen")],
                funded_by: vec![s("@dana"), s("@eve"), s("org:acme")],
                paused_since_ms: 0,
            },
            Project {
                id: s("prj_gadgets"),
                slug: s("github/acme/gadgets"),
                donors: 3,
                pending: 1,
                month_uusd: 8_900_000,
                goal_uusd: 20_000_000,
                members: vec![s("alice")],
                funded_by: vec![s("@frank")],
                paused_since_ms: 0,
            },
            Project {
                id: s("prj_notes"),
                slug: s("gitlab/alice/notes"),
                donors: 0,
                pending: 0,
                month_uusd: 0,
                goal_uusd: 5_000_000,
                members: vec![s("alice")],
                funded_by: vec![],
                paused_since_ms: ago(9 * DAY),
            },
        ],
        orgs: vec![Org {
            id: s("org_acme"),
            path: s("github/acme"),
            covered: vec![
                CoveredRepo { slug: s("github/acme/widgets"), used_uusd: 21_000_000, share_cap_uusd: 30_000_000 },
                CoveredRepo { slug: s("github/acme/gadgets"), used_uusd: 6_400_000, share_cap_uusd: 0 },
                CoveredRepo { slug: s("github/acme/docs"), used_uusd: 900_000, share_cap_uusd: 5_000_000 },
            ],
            donors: 4,
            month_uusd: 28_300_000,
            paused_since_ms: 0,
            per_day_uusd: trend(13),
        }],
        pending: vec![
            Pending {
                request_id: s("req_51e0"),
                kind: s("donor"),
                target: s("github/acme/widgets"),
                subject: s("@grace"),
                summary: s("$25.00/month · claude-sonnet-5-5 · cap $0.50/task"),
                decide_url: String::new(),
                created_at_ms: ago(42 * MIN),
            },
            Pending {
                request_id: s("req_51e1"),
                kind: s("donor"),
                target: s("github/acme/widgets"),
                subject: s("@heidi"),
                summary: s("$10.00 one-off · deepseek-v4"),
                decide_url: String::new(),
                created_at_ms: ago(3 * HOUR),
            },
            Pending {
                request_id: s("req_51e2"),
                kind: s("org-repo"),
                target: s("github/acme"),
                subject: s("github/acme/gadgets-pro"),
                summary: s("add to the org's covered repos (share cap $5.00)"),
                decide_url: String::new(),
                created_at_ms: ago(DAY + 2 * HOUR),
            },
        ],
        decisions: vec![
            Decision { at_ms: ago(2 * HOUR), target: s("github/acme/widgets"), donor: s("@dana"), event: s("accepted"), via: s("passkey"), reason: s("") },
            Decision { at_ms: ago(5 * HOUR), target: s("github/acme/widgets"), donor: s("@mallory"), event: s("refused"), via: s("owner key"), reason: s("not our stack") },
            Decision { at_ms: ago(DAY), target: s("github/acme/gadgets"), donor: s("@frank"), event: s("accepted"), via: s("owner key"), reason: s("") },
            Decision { at_ms: ago(3 * DAY), target: s("github/acme"), donor: s("@eve"), event: s("accepted"), via: s("passkey"), reason: s("org donor") },
            Decision { at_ms: ago(6 * DAY), target: s("github/acme/widgets"), donor: s("@trent"), event: s("revoked"), via: s("owner key"), reason: s("key rotated") },
            Decision { at_ms: ago(12 * DAY), target: s("gitlab/alice/notes"), donor: s("@ivan"), event: s("accepted"), via: s("passkey"), reason: s("") },
        ],
        devices: vec![
            Device { id: s("dev_laptop"), name: s("alice-mbp"), roles: vec![s("donor"), s("maintainer")], online: true, this_device: true },
            Device { id: s("dev_tower"), name: s("garage-tower (4090)"), roles: vec![s("donor")], online: true, this_device: false },
            Device { id: s("dev_pi"), name: s("pi-headless"), roles: vec![s("donor")], online: false, this_device: false },
        ],
        boxes: vec![
            BoxDevice { id: s("box_ci_01"), project: s("github/acme/widgets"), expires_at_ms: DEMO_NOW_MS.saturating_add(5 * HOUR), online: true },
            BoxDevice { id: s("box_ci_02"), project: s("github/acme/gadgets"), expires_at_ms: DEMO_NOW_MS.saturating_add(2 * DAY), online: false },
        ],
        box_tokens: vec![
            BoxToken { id: s("bt_7k2m"), project: s("github/acme/widgets"), created_at_ms: ago(DAY), expires_at_ms: DEMO_NOW_MS.saturating_add(6 * DAY), cap_uusd: 5_000_000, max_boxes: 4, boxes_enrolled: 1, revoked: false },
            BoxToken { id: s("bt_19aa"), project: s("github/acme/gadgets"), created_at_ms: ago(9 * DAY), expires_at_ms: ago(2 * DAY), cap_uusd: 0, max_boxes: 1, boxes_enrolled: 1, revoked: false },
        ],
        keys: vec![
            ProviderKey { provider: s("anthropic"), present: true, models: vec![s("claude-opus-5-5"), s("claude-sonnet-5-5"), s("claude-haiku-4-5")] },
            ProviderKey { provider: s("deepseek"), present: true, models: vec![s("deepseek-v4")] },
            ProviderKey { provider: s("openai"), present: false, models: vec![] },
            ProviderKey { provider: s("ollama (local)"), present: true, models: vec![s("qwen3-coder:30b")] },
        ],
        activity: vec![
            Activity { at_ms: ago(4 * MIN), text: s("Served claude-sonnet-5-5 for github/tokio-rs/axum · 18.2k tokens · $0.21"), receipt: Some(Receipt { id: s("r_01JB2Y8V9Q3K7M4N5P6R8S0T1X"), check: ReceiptCheck::Unchecked }) },
            Activity { at_ms: ago(11 * MIN), text: s("Receipt verified for github/tokio-rs/axum ($0.21)"), receipt: Some(Receipt { id: s("r_01JB2Y8V9Q3K7M4N5P6R8S0T1W"), check: ReceiptCheck::Verified }) },
            Activity { at_ms: ago(42 * MIN), text: s("@grace asked to donate to github/acme/widgets"), receipt: None },
            Activity { at_ms: ago(2 * HOUR), text: s("Accepted @dana for github/acme/widgets (passkey)"), receipt: None },
            Activity { at_ms: ago(3 * HOUR), text: s("Donation to github/rust-lang/rustfmt paused (94% of the limit)"), receipt: None },
            Activity { at_ms: ago(6 * HOUR), text: s("Key log: checkpoint 18,442 consistent with the Git anchor"), receipt: None },
            Activity { at_ms: ago(DAY), text: s("Device garage-tower (4090) came online"), receipt: None },
            Activity { at_ms: ago(2 * DAY), text: s("Box box_ci_02 created for github/acme/gadgets (expires in 2 days)"), receipt: None },
        ],
        alerts: vec![
            Alert { level: s("warn"), text: s("rustfmt donation is at 94% of its monthly limit") },
            Alert { level: s("error"), text: s("pi-headless has been offline for 3 days") },
        ],
        donated_per_day_uusd: donated,
        used_per_day_uusd: used,
        config: vec![
            (s("relay"), s("https://relay.moochy.dev")),
            (s("node.sock"), s("~/.local/state/moochy/node.sock")),
            (s("role"), s("donor + maintainer")),
            (s("sandbox"), s("landlock + seccomp (enforced)")),
            (s("serve_hours"), s("always")),
            (s("max_concurrent"), s("2")),
            (s("notifications"), s("email: weekly digest")),
            (s("keylog_monitor"), s("on (last check 6h ago)")),
        ],
    }
}

/// The demo world with hostile peer strings: CSI, OSC 52/8, C1, bidi overrides (E121).
#[must_use]
pub fn hostile() -> FakeSource {
    let mut st = demo();
    let evil = |base: &str| format!("{base}\u{1b}[2J\u{1b}]52;c;cHduZWQ=\u{7}\u{9b}31m\u{202E}gnp.exe\u{1b}]8;;https://evil\u{1b}\\");
    st.me.handle = evil("alice");
    for d in &mut st.donations {
        d.target = evil(&d.target);
    }
    for r in &mut st.served {
        r.model = evil(&r.model);
        r.project = evil(&r.project);
    }
    for p in &mut st.pending {
        p.subject = evil(&p.subject);
        p.summary = evil(&p.summary);
    }
    for a in &mut st.activity {
        a.text = evil(&a.text);
    }
    for a in &mut st.alerts {
        a.text = evil(&a.text);
    }
    for p in &mut st.projects {
        p.slug = evil(&p.slug);
    }
    for d in &mut st.decisions {
        d.donor = evil(&d.donor);
        d.reason = evil(&d.reason);
    }
    for d in &mut st.devices {
        d.name = evil(&d.name);
    }
    for (_, v) in &mut st.config {
        *v = evil(v);
    }
    FakeSource::new(st, DEMO_NOW_MS)
}
