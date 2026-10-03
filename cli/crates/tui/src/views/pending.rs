//! What the maintainer tabs (Projects, Organisations, Decisions) share about a waiting request:
//! its list row, its detail, the accept confirmation (every field the owner key will sign) and the
//! refuse dialog; and the §19.2a claim status line.

use ratatui::text::{Line, Span};

use crate::model::Pending;
use crate::sanitize::clean;
use crate::source::Action;
use crate::theme::{Glyph, Theme};
use crate::views::{Outcome, Prompt, Then};
use crate::widgets::{self as w, Tone};

/// The status column of the maintainer lists, in cells.
pub const STATUS_W: usize = 14;

/// A waiting request as a list row: status column, who (`name_w` cells), the terms.
#[must_use]
pub fn line(t: Theme, p: &Pending, name_w: usize) -> Line<'static> {
    Line::from(vec![
        w::col(&w::badge(t, Tone::Warn, t.glyph(Glyph::Pending), "waiting"), STATUS_W),
        w::col(&Span::raw(clean(&p.subject)), name_w),
        w::muted(t, format!("  {}", clean(&p.summary))),
    ])
}

fn fields(t: Theme, p: &Pending, now_ms: u64) -> Vec<Line<'static>> {
    vec![
        w::kv(t, "Request", clean(&p.request_id)),
        w::kv(t, "Kind", clean(&p.kind)),
        w::kv(t, "For", clean(&p.target)),
        w::kv(t, "From", clean(&p.subject)),
        w::kv(t, "Terms", clean(&p.summary)),
        w::kv(t, "Received", w::ago_long(now_ms, p.created_at_ms)),
    ]
}

/// The detail pane of a waiting request, with the keys and the passkey page.
#[must_use]
pub fn detail(t: Theme, p: &Pending, web: &str, now_ms: u64) -> Vec<Line<'static>> {
    let mut v = fields(t, p, now_ms);
    v.push(Line::default());
    v.push(Line::from(vec![w::key("a"), w::muted(t, " accept (owner key, checked with the server)   "), w::key("r"), w::muted(t, " refuse")]));
    if let Some(u) = w::decide_url(web, &p.decide_url, &p.request_id) {
        v.push(Line::from(vec![w::muted(t, "Or with your passkey: "), Span::styled(u, t.info())]));
    }
    v
}

fn text(lines: &[Line<'static>]) -> String {
    lines.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
}

/// `a`: every field the owner key will sign is shown; the node re-decodes the body and checks the
/// names with the server's Lookup before signing (A217/A218), exactly like `moochy accept`.
#[must_use]
pub fn confirm_accept(t: Theme, p: &Pending, web: &str, now_ms: u64) -> Outcome {
    let mut v = fields(t, p, now_ms);
    v.push(Line::default());
    v.push(Line::from(
        "Your owner key signs this approval. Before signing, the node decodes the request and confirms every name with the server; if anything differs from what you see here, nothing is signed.",
    ));
    if let Some(u) = w::decide_url(web, &p.decide_url, &p.request_id) {
        v.push(Line::from(format!("No owner key on this machine? Accept with your passkey: {u}")));
    }
    Outcome::Confirm { title: "Accept this request?".into(), body: text(&v), action: Action::Accept { request_id: p.request_id.clone() } }
}

/// `r`: asks for an optional reason, then confirms; refusing signs nothing.
#[must_use]
pub fn refuse(p: &Pending) -> Outcome {
    Outcome::Prompt(Prompt {
        title: "Refuse this request".into(),
        body: format!("{} → {}: {}", clean(&p.subject), clean(&p.target), clean(&p.summary)),
        label: "Reason (optional, the requester sees it)".into(),
        initial: String::new(),
        max_len: 200,
        then: Then::Refuse { request_id: p.request_id.clone(), what: format!("{} for {}", clean(&p.subject), clean(&p.target)) },
    })
}

/// The §19.2a status line of a claim (project or org).
#[must_use]
pub fn claim_status(t: Theme, now_ms: u64, paused_since_ms: u64) -> Vec<Line<'static>> {
    if paused_since_ms == 0 {
        return vec![w::kv_span(t, "Status", w::badge(t, Tone::Good, t.glyph(Glyph::Online), "active"))];
    }
    vec![
        w::kv_span(t, "Status", w::badge(t, Tone::Bad, t.glyph(Glyph::Paused), &format!("paused {}", w::ago_long(now_ms, paused_since_ms)))),
        Line::from(w::muted(t, "  No new task is routed to its donations until you sign in on the web to re-verify (claims pause after 30 days without a sign-in).")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::test_util::{NOW, theme};

    #[test]
    fn confirmations_show_every_field() {
        let p = Pending {
            request_id: "pl_01J".into(),
            kind: "donor".into(),
            target: "github/acme/widget".into(),
            subject: "\u{1b}[31malice".into(),
            summary: "$20.00/month".into(),
            created_at_ms: NOW - 3 * 3_600_000,
            decide_url: String::new(),
        };
        let Outcome::Confirm { body, action, .. } = confirm_accept(theme(false), &p, "https://moochy.dev", NOW) else { panic!() };
        assert_eq!(action, Action::Accept { request_id: "pl_01J".into() });
        for f in ["pl_01J", "donor", "github/acme/widget", "alice", "$20.00/month", "3h ago", "confirms every name with the server", "https://moochy.dev/decide/pl_01J"] {
            assert!(body.contains(f), "{f} missing from {body}");
        }
        assert!(!body.contains('\u{1b}'));
        let Outcome::Prompt(pr) = refuse(&p) else { panic!() };
        let Ok(Outcome::Confirm { action, .. }) = pr.then.submit("  not now ") else { panic!() };
        assert_eq!(action, Action::Refuse { request_id: "pl_01J".into(), reason: "not now".into() });
    }
}
