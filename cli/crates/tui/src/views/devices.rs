//! The Devices & keys tab (CONTRACT §20.2): my devices and cloud boxes with their online state,
//! provider keys present or absent (never a value: the model has none), the lockdown/sandbox
//! status and a doctor summary; revoke a box behind a confirmation. Owner: mo-tui-donor.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use super::donor_kit::{self as k, Cursor, Tone};
use super::{Ctx, Input, Outcome, View};
use crate::model::{BoxDevice, Device, ProviderKey, Snapshot};
use crate::sanitize::clean;
use crate::source::Action;
use crate::theme::Theme;

const DAY_MS: u64 = 86_400_000;

#[derive(Default)]
pub struct DevicesView {
    cur: Cursor,
}

enum Item<'a> {
    Head(&'static str, usize),
    Hint(&'static str),
    Device(&'a Device),
    Box(&'a BoxDevice),
    Key(&'a ProviderKey),
}

fn items<'a>(ctx: &Ctx<'a>) -> Vec<Item<'a>> {
    let s = ctx.snap;
    let f = ctx.filter;
    let devices: Vec<_> = s.devices.iter().filter(|d| k::matches(f, &[&d.name, &d.id, &d.roles.join(" ")])).map(Item::Device).collect();
    let boxes: Vec<_> = s.boxes.iter().filter(|b| k::matches(f, &[&b.id, &b.project, "box"])).map(Item::Box).collect();
    let keys: Vec<_> = s.keys.iter().filter(|x| k::matches(f, &[&x.provider, &x.models.join(" "), "key"])).map(Item::Key).collect();
    let mut v = Vec::new();
    for (title, total, list, hint) in [
        ("Devices", s.devices.len(), devices, "none yet: `moochy login` adds this machine to your account"),
        ("Provider keys", s.keys.len(), keys, "none yet: `moochy keys add anthropic --key-stdin` (it never leaves this machine)"),
        ("Cloud boxes", s.boxes.len(), boxes, "none: `moochy box token create --repo PROJECT` lets a cloud box use a project"),
    ] {
        if !f.is_empty() && list.is_empty() {
            continue;
        }
        v.push(Item::Head(title, list.len()));
        if total == 0 {
            v.push(Item::Hint(hint));
        }
        v.extend(list);
    }
    v
}

fn online(t: &Theme, on: bool) -> Span<'static> {
    if on { k::badge(t, Tone::Good, k::g(t, "●", "*"), "online") } else { k::badge(t, Tone::Muted, k::g(t, "○", "o"), "offline") }
}

/// The lockdown/sandbox status of the node (`Me.lockdown`), judged fail-closed: anything that
/// says off/unsafe/not is bad, nothing at all is unknown.
fn lockdown(t: &Theme, s: &str) -> (Tone, &'static str, String) {
    let l = s.to_lowercase();
    if l.trim().is_empty() {
        (Tone::Warn, "!", "unknown: the app is not running here (`moochy up`)".into())
    } else if ["unsafe", "off", "disabled", "not ", "none", "fail", "unavailable"].iter().any(|w| l.contains(w)) {
        (Tone::Bad, k::g(t, "✗", "x"), clean(s))
    } else {
        (Tone::Good, k::g(t, "✓", "+"), clean(s))
    }
}

/// The doctor summary from what the dashboard knows; `moochy doctor` does the full check.
fn doctor(t: &Theme, s: &Snapshot, now: u64) -> Vec<(Tone, &'static str, String)> {
    let (ok, warn, bad) = (k::g(t, "✓", "+"), "!", k::g(t, "✗", "x"));
    let mut v = Vec::new();
    if s.me.connected {
        v.push((Tone::Good, ok, format!("connected to {}", clean(&s.me.relay))));
    } else {
        v.push((Tone::Bad, bad, "not connected: start the app with `moochy up`".into()));
    }
    let on = s.devices.iter().filter(|d| d.online).count();
    let here = s.devices.iter().any(|d| d.this_device && d.online);
    match (s.devices.len(), on) {
        (0, _) => v.push((Tone::Bad, bad, "no device: `moochy login`".into())),
        (n, 0) => v.push((Tone::Warn, warn, format!("0 of {n} devices online"))),
        (n, o) => v.push((if here { Tone::Good } else { Tone::Warn }, if here { ok } else { warn }, format!("{o} of {n} devices online{}", if here { "" } else { ", not this one" }))),
    }
    let present: Vec<String> = s.keys.iter().filter(|x| x.present).map(|x| clean(&x.provider)).collect();
    if present.is_empty() {
        v.push((Tone::Warn, warn, "no provider key: nothing to donate from here".into()));
    } else {
        v.push((Tone::Good, ok, format!("{} provider key{} ({})", present.len(), if present.len() == 1 { "" } else { "s" }, present.join(", "))));
    }
    let soon = s.boxes.iter().filter(|b| b.expires_at_ms > now && b.expires_at_ms <= now.saturating_add(DAY_MS)).count();
    if soon > 0 {
        v.push((Tone::Warn, warn, format!("{soon} cloud box{} expire{} within 24 h", if soon == 1 { "" } else { "es" }, if soon == 1 { "s" } else { "" })));
    }
    v
}

impl View for DevicesView {
    fn title(&self) -> &'static str {
        "Devices & keys"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("j/k", "move"), ("x", "revoke box"), ("/", "filter")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = ctx.theme;
        let items = items(ctx);
        let (list, side) = k::split(area, 10);
        self.cur.sync(items.len(), list);
        if items.is_empty() {
            let lines = vec![Line::raw(format!("Nothing matches /{}", clean(ctx.filter))), Line::from(k::dim("Esc clears the filter"))];
            k::empty(f, list, t, self.title(), lines);
        } else {
            let bold = Style::default().add_modifier(Modifier::BOLD);
            let body = items.iter().map(|it| match it {
                Item::Head(title, n) => Row::new([Cell::from(k::dim(k::g(t, "──────────", "----------"))), Cell::from(Span::styled(format!("{title} ({n})"), bold))]),
                Item::Hint(h) => Row::new([Cell::from(""), Cell::from(k::dim(*h))]),
                Item::Device(d) => {
                    let mut name = vec![Span::raw(clean(&d.name))];
                    if d.this_device {
                        name.push(k::dim(format!("{}this device", k::dot(t))));
                    }
                    Row::new([Cell::from(online(t, d.online)), Cell::from(Line::from(name)), Cell::from(k::dim(clean(&d.roles.join(", "))))])
                }
                Item::Box(b) => Row::new([
                    Cell::from(online(t, b.online)),
                    Cell::from(format!("box {}", clean(&b.id))),
                    Cell::from(format!("{}{}expires {}", clean(&b.project), k::dot(t), k::until(ctx.now_ms, b.expires_at_ms))),
                ]),
                Item::Key(x) => Row::new([
                    Cell::from(if x.present {
                        k::badge(t, Tone::Good, k::g(t, "✓", "+"), "present")
                    } else {
                        k::badge(t, Tone::Muted, k::g(t, "✗", "x"), "absent")
                    }),
                    Cell::from(clean(&x.provider)),
                    Cell::from(k::dim(if x.models.is_empty() { "-".to_owned() } else { clean(&x.models.join(", ")) })),
                ]),
            });
            let widths = [Constraint::Length(10), Constraint::Min(18), Constraint::Min(16)];
            let table = Table::new(body, widths)
                .header(Row::new(["State", "Name", "Details"]).style(k::tone(t, Tone::Muted)))
                .row_highlight_style(k::selected(t))
                .highlight_symbol(k::arrow(t))
                .block(k::block(t, format!(" {} ", self.title())));
            f.render_stateful_widget(table, list, &mut self.cur.state);
        }
        let Some(side) = side else { return };
        let (tone, glyph, text) = lockdown(t, &ctx.snap.me.lockdown);
        let mut lines = vec![Line::from(vec![k::dim("Lockdown  "), k::badge(t, tone, glyph, &text)]), Line::raw(""), Line::from(k::dim("Doctor"))];
        for (tone, glyph, text) in doctor(t, ctx.snap, ctx.now_ms) {
            lines.push(Line::from(vec![Span::raw("  "), k::badge(t, tone, glyph, &text)]));
        }
        lines.push(Line::from(vec![k::dim("  full check: "), k::key("moochy doctor")]));
        if let Some(Item::Box(b)) = self.cur.selected().and_then(|i| items.get(i)) {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![k::key("x"), Span::raw(format!(" revoke box {}", clean(&b.id)))]));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(k::block(t, " Safety ")), side);
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        if self.cur.on_input(input) {
            return Outcome::Redraw;
        }
        let items = items(ctx);
        match (input, self.cur.selected().and_then(|i| items.get(i))) {
            (Input::Char('x'), Some(Item::Box(b))) if !b.id.is_empty() => {
                let id = clean(&b.id);
                Outcome::Confirm {
                    title: "Revoke this cloud box".into(),
                    body: format!(
                        "Revoke box {id} of {}? Its keys stop working at once and it can no longer use the project's donations. Same as `moochy box revoke {id}`.",
                        clean(&b.project)
                    ),
                    action: Action::RevokeBox(b.id.clone()),
                }
            }
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Me;
    use crate::views::donor_kit::test_util::{NOW, ctx, draw, themes};

    fn snap() -> Snapshot {
        Snapshot {
            me: Me { relay: "relay.moochy.dev".into(), connected: true, lockdown: "landlock+seccomp".into(), ..Me::default() },
            devices: vec![
                Device { id: "d_1".into(), name: "laptop".into(), roles: vec!["gateway".into(), "worker".into()], online: true, this_device: true },
                Device { id: "d_2".into(), name: "tower\u{1b}[2J".into(), roles: vec!["worker".into()], online: false, this_device: false },
            ],
            boxes: vec![BoxDevice { id: "d_box9".into(), project: "github/foo/bar".into(), expires_at_ms: NOW + 3_600_000, online: true }],
            keys: vec![
                ProviderKey { provider: "anthropic".into(), present: true, models: vec!["claude-sonnet-4".into()] },
                ProviderKey { provider: "openai".into(), present: false, models: vec![] },
            ],
            ..Snapshot::default()
        }
    }

    #[test]
    fn renders_sections_and_doctor() {
        let s = snap();
        for t in themes() {
            for (w, h) in [(80, 24), (160, 48)] {
                let mut v = DevicesView::default();
                let out = draw(&mut v, &s, &t, "", w, h);
                for want in ["Devices (2)", "laptop", "this device", "offline", "Provider keys (2)", "present", "absent", "box d_box9", "expires in 1h", "landlock+seccomp", "connected to relay.moochy.dev", "1 of 2 devices online", "1 cloud box expires within 24 h"] {
                    assert!(out.contains(want), "missing {want}:\n{out}");
                }
                assert!(out.contains("tower\u{FFFD}[2J"), "{out}");
            }
        }
    }

    #[test]
    fn empty_and_unsafe_states_say_what_to_do() {
        let s = Snapshot::default();
        let mut v = DevicesView::default();
        let out = draw(&mut v, &s, &themes()[0], "", 160, 48);
        for want in ["moochy login", "moochy keys add", "moochy box token create", "not connected", "unknown", "no provider key"] {
            assert!(out.contains(want), "missing {want}:\n{out}");
        }
        let mut s = snap();
        s.me.lockdown = "UNSAFE: not locked down".into();
        assert_eq!(lockdown(&themes()[0], &s.me.lockdown).0, Tone::Bad);
        assert_eq!(lockdown(&themes()[0], "  ").0, Tone::Warn);
    }

    #[test]
    fn revoke_only_on_a_box() {
        let s = snap();
        let t = themes()[0];
        let c = ctx(&s, &t);
        let mut v = DevicesView::default();
        draw(&mut v, &s, &t, "", 160, 48);
        assert_eq!(v.on_input(&Input::Char('x'), &c), Outcome::Ignored, "header row");
        v.on_input(&Input::Down, &c);
        assert_eq!(v.on_input(&Input::Char('x'), &c), Outcome::Ignored, "a device");
        v.on_input(&Input::End, &c);
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('x'), &c) else { panic!() };
        assert_eq!(action, Action::RevokeBox("d_box9".into()));
        assert!(body.contains("github/foo/bar"));
        let out = draw(&mut v, &s, &t, "box", 160, 48);
        assert!(out.contains("Cloud boxes (1)") && !out.contains("laptop"), "{out}");
    }
}
