//! The Devices & keys tab (CONTRACT §20.2): my devices, cloud boxes and box enrollment tokens
//! (§17) with their state, provider keys present or absent (never a value: the model has none),
//! the lockdown status (§15) and a doctor summary; revoke a box or a token behind a confirmation.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};

use super::{Ctx, Input, Outcome, View};
use crate::model::{BoxDevice, BoxToken, Device, Lockdown, ProviderKey, Snapshot};
use crate::sanitize::clean;
use crate::source::Action;
use crate::theme::{Glyph, Theme};
use crate::widgets::{self as w, TableCursor, Tone, list};

const DAY_MS: u64 = 86_400_000;
/// CONTRACT §23.1: said above the key list, word for word.
pub const KEYS_PROMISE: &str = "Keys stay on this machine. Moochy never stores them online.";

#[derive(Default)]
pub struct DevicesView {
    cur: TableCursor,
}

enum Item<'a> {
    Head(&'static str, usize),
    Hint(&'static str),
    Device(&'a Device),
    Key(&'a ProviderKey),
    Box(&'a BoxDevice),
    Token(&'a BoxToken),
}

fn items<'a>(ctx: &Ctx<'a>) -> Vec<Item<'a>> {
    let s = ctx.snap;
    let f = ctx.filter;
    let devices: Vec<_> = s.devices.iter().filter(|d| w::matches(f, &[&d.name, &d.id, &d.roles.join(" ")])).map(Item::Device).collect();
    let keys: Vec<_> = s.keys.iter().filter(|x| w::matches(f, &[&x.provider, &x.models.join(" "), "key"])).map(Item::Key).collect();
    let boxes: Vec<_> = s.boxes.iter().filter(|b| w::matches(f, &[&b.id, &b.project, "box"])).map(Item::Box).collect();
    let tokens: Vec<_> = s.box_tokens.iter().filter(|b| w::matches(f, &[&b.id, &b.project, "token"])).map(Item::Token).collect();
    let mut v = Vec::new();
    for (title, total, list, hint) in [
        ("Devices", s.devices.len(), devices, "none yet: `moochy login` adds this machine to your account"),
        ("Provider keys", s.keys.len(), keys, "none yet: `moochy keys add anthropic --key-stdin` (it never leaves this machine)"),
        ("Cloud boxes", s.boxes.len(), boxes, "none: a box enrolls with a token, `MOOCHY_ENROLL=<token> moochy up --headless`"),
        ("Box tokens", s.box_tokens.len(), tokens, "none: `moochy box token create --repo PROJECT` lets cloud boxes use a project"),
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

fn online(t: Theme, on: bool) -> Span<'static> {
    if on { w::badge(t, Tone::Good, t.glyph(Glyph::Online), "online") } else { w::badge(t, Tone::Muted, t.glyph(Glyph::Offline), "offline") }
}

fn token_state(t: Theme, b: &BoxToken, now: u64) -> Span<'static> {
    if b.revoked {
        w::badge(t, Tone::Muted, t.glyph(Glyph::Stopped), "revoked")
    } else if b.expires_at_ms <= now {
        w::badge(t, Tone::Muted, t.glyph(Glyph::Stopped), "expired")
    } else {
        w::badge(t, Tone::Good, t.glyph(Glyph::Ok), "valid")
    }
}

/// The node's lockdown (§15), fail-closed: unknown is attention, failed or unsafe is bad.
fn lockdown(t: Theme, l: &Lockdown) -> Span<'static> {
    match l {
        Lockdown::Unknown => w::badge(t, Tone::Warn, t.glyph(Glyph::Warn), "unknown: the app is not running here (`moochy up`)"),
        Lockdown::Enforced(m) => w::badge(t, Tone::Good, t.glyph(Glyph::Ok), &format!("locked down ({})", clean(m))),
        Lockdown::Failed(why) => w::badge(t, Tone::Bad, t.glyph(Glyph::Error), &format!("not locked down: {} (this device refuses to serve)", clean(why))),
        Lockdown::Unsafe => w::badge(t, Tone::Bad, t.glyph(Glyph::Error), "UNSAFE: started with --unsafe-no-lockdown"),
    }
}

/// The doctor summary from what the dashboard knows; `moochy doctor` does the full check.
fn doctor(t: Theme, snap: &Snapshot, now: u64) -> Vec<Span<'static>> {
    let ok = |s: String| w::badge(t, Tone::Good, t.glyph(Glyph::Ok), &s);
    let warn = |s: String| w::badge(t, Tone::Warn, t.glyph(Glyph::Warn), &s);
    let bad = |s: String| w::badge(t, Tone::Bad, t.glyph(Glyph::Error), &s);
    let mut out = Vec::new();
    out.push(if snap.me.connected { ok(format!("connected to {}", clean(&snap.me.relay))) } else { bad("not connected: start the app with `moochy up`".into()) });
    let on = snap.devices.iter().filter(|d| d.online).count();
    let here = snap.devices.iter().any(|d| d.this_device && d.online);
    out.push(match (snap.devices.len(), on) {
        (0, _) => bad("no device: `moochy login`".into()),
        (n, 0) => warn(format!("0 of {n} devices online")),
        (n, o) if here => ok(format!("{o} of {n} devices online")),
        (n, o) => warn(format!("{o} of {n} devices online, not this one")),
    });
    let present: Vec<String> = snap.keys.iter().filter(|x| x.present).map(|x| clean(&x.provider)).collect();
    out.push(if present.is_empty() {
        warn("no provider key: nothing to donate from here".into())
    } else {
        ok(format!("{} provider key{} ({})", present.len(), if present.len() == 1 { "" } else { "s" }, present.join(", ")))
    });
    let soon = snap.boxes.iter().filter(|b| b.expires_at_ms > now && b.expires_at_ms <= now.saturating_add(DAY_MS)).count();
    if soon > 0 {
        out.push(warn(format!("{soon} cloud box{} expire{} within 24 h", if soon == 1 { "" } else { "es" }, if soon == 1 { "s" } else { "" })));
    }
    out
}

const COLS: [Constraint; 3] = [Constraint::Length(10), Constraint::Min(18), Constraint::Min(16)];

impl View for DevicesView {
    fn title(&self) -> &'static str {
        "Devices & keys"
    }

    fn labels(&self) -> (&'static str, &'static str) {
        ("Devices", "Keys")
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[("x", "revoke box/token")]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        let t = *ctx.theme;
        let now = ctx.now_ms;
        let items = items(ctx);
        let (list_a, side) = w::split(area, 10);
        let promise_rows = u16::try_from(KEYS_PROMISE.len()).unwrap_or(u16::MAX).div_ceil(list_a.width.max(1)).min(3);
        let [promise, list_a] = Layout::vertical([Constraint::Length(promise_rows), Constraint::Min(0)]).areas(list_a);
        f.render_widget(Paragraph::new(Span::styled(KEYS_PROMISE, w::tone(t, Tone::Good))).wrap(Wrap { trim: true }), promise);
        self.cur.set_headers(items.iter().map(|i| matches!(i, Item::Head(..) | Item::Hint(_))).collect());
        self.cur.sync(items.len(), list_a);
        if items.is_empty() {
            w::empty(f, list_a, t, self.title(), w::no_match(t, ctx.filter));
        } else {
            let cw = list::table_widths(list_a, &COLS);
            let fit = |l: Line<'static>, i: usize| Cell::from(list::fit(l, cw.get(i).copied().unwrap_or(0)));
            let body = items.iter().map(|it| match it {
                Item::Head(title, n) => Row::new([Cell::from(w::muted(t, "──────────")), Cell::from(w::bold(format!("{title} · {n}")))]),
                Item::Hint(h) => Row::new([Cell::from(""), fit(Line::from(w::muted(t, *h)), 1)]),
                Item::Device(d) => {
                    let mut name = vec![Span::raw(clean(&d.name))];
                    if d.this_device {
                        name.push(w::muted(t, format!("{}this device", w::dot(t))));
                    }
                    Row::new([Cell::from(online(t, d.online)), fit(Line::from(name), 1), fit(Line::from(w::muted(t, clean(&d.roles.join(", ")))), 2)])
                }
                Item::Box(b) => Row::new([
                    Cell::from(online(t, b.online)),
                    fit(Line::raw(format!("box {}", clean(&b.id))), 1),
                    fit(Line::raw(format!("{}{}expires {}", clean(&b.project), w::dot(t), w::until(now, b.expires_at_ms))), 2),
                ]),
                Item::Token(b) => {
                    let cap = if b.cap_uusd == 0 { String::new() } else { format!("{}cap {}/box", w::dot(t), w::dollars(b.cap_uusd)) };
                    Row::new([
                        Cell::from(token_state(t, b, now)),
                        fit(Line::raw(format!("token {}", clean(&b.id))), 1),
                        fit(Line::raw(format!("{}{}{}/{} boxes{cap}{}expires {}", clean(&b.project), w::dot(t), b.boxes_enrolled, b.max_boxes, w::dot(t), w::until(now, b.expires_at_ms))), 2),
                    ])
                }
                Item::Key(x) => Row::new([
                    Cell::from(if x.present { w::badge(t, Tone::Good, t.glyph(Glyph::Ok), "present") } else { w::badge(t, Tone::Muted, t.glyph(Glyph::Stopped), "absent") }),
                    fit(Line::raw(clean(&x.provider)), 1),
                    fit(Line::from(w::muted(t, if x.models.is_empty() { "-".to_owned() } else { clean(&x.models.join(", ")) })), 2),
                ]),
            });
            let table = Table::new(body, COLS)
                .header(Row::new(["State", "Name", "Details"]).style(t.muted()))
                .row_highlight_style(t.selected())
                .highlight_symbol(list::marker(t))
                .block(w::block_focus(t, self.title()));
            f.render_stateful_widget(table, list_a, &mut self.cur.state);
        }
        let Some(side) = side else { return };
        let mut lines = vec![w::kv_span(t, "Lockdown", lockdown(t, &ctx.snap.me.lockdown)), Line::raw(""), Line::from(w::bold("Doctor"))];
        for s in doctor(t, ctx.snap, now) {
            lines.push(Line::from(vec![Span::raw("  "), s]));
        }
        lines.push(Line::from(vec![w::muted(t, "  full check: "), w::key("moochy doctor")]));
        match self.cur.selected().and_then(|i| items.get(i)) {
            Some(Item::Box(b)) => {
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![w::key("x"), Span::raw(format!(" revoke box {}", clean(&b.id)))]));
            }
            Some(Item::Token(b)) if !b.revoked => {
                lines.push(Line::raw(""));
                lines.push(Line::from(vec![w::key("x"), Span::raw(format!(" revoke token {} and every box it enrolled", clean(&b.id)))]));
            }
            _ => {}
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(w::block(t, "Safety")), side);
    }

    fn on_input(&mut self, input: &Input, ctx: &Ctx) -> Outcome {
        let items = items(ctx);
        self.cur.set_headers(items.iter().map(|i| matches!(i, Item::Head(..) | Item::Hint(_))).collect());
        if self.cur.on_input(input) {
            return Outcome::Redraw;
        }
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
            (Input::Char('x'), Some(Item::Token(b))) if !b.id.is_empty() && !b.revoked => {
                let id = clean(&b.id);
                Outcome::Confirm {
                    title: "Revoke this box token".into(),
                    body: format!(
                        "Revoke enrollment token {id} for {}? No new box can enroll with it, and the {} box(es) it enrolled are revoked now. Same as `moochy box token revoke {id}`.",
                        clean(&b.project),
                        b.boxes_enrolled
                    ),
                    action: Action::RevokeBoxToken(b.id.clone()),
                }
            }
            (Input::Char('x'), _) => Outcome::Toast("x revokes a cloud box or a box token: select one first".into()),
            _ => Outcome::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Me;
    use crate::widgets::test_util::{NOW, ctx, draw, themes};

    fn snap() -> Snapshot {
        Snapshot {
            me: Me { relay: "relay.moochy.dev".into(), connected: true, lockdown: Lockdown::Enforced("landlock+seccomp".into()), ..Me::default() },
            devices: vec![
                Device { id: "d_1".into(), name: "laptop".into(), roles: vec!["gateway".into(), "worker".into()], online: true, this_device: true },
                Device { id: "d_2".into(), name: "tower\u{1b}[2J".into(), roles: vec!["worker".into()], online: false, this_device: false },
            ],
            boxes: vec![BoxDevice { id: "d_box9".into(), project: "github/foo/bar".into(), expires_at_ms: NOW + 3_600_000, online: true }],
            box_tokens: vec![BoxToken { id: "bt_1".into(), project: "github/foo/bar".into(), expires_at_ms: NOW + 86_400_000, max_boxes: 3, boxes_enrolled: 1, ..BoxToken::default() }],
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
                let out = draw(&mut v, &ctx(&s, &t, ""), w, h).replace(" - ", " · ");
                for want in ["Devices · 2", "laptop", "offline", "Provider keys · 2", "present", "absent", "box d_box9", "Box tokens · 1", "token bt_1"] {
                    assert!(out.contains(want), "missing {want}:\n{out}");
                }
                assert!(out.contains("tower") && !out.contains('\u{1b}'), "{out}");
            }
        }
        let t = themes()[0];
        let out = draw(&mut DevicesView::default(), &ctx(&s, &t, ""), 160, 48);
        for want in ["this device", "expires in 1h", "locked down (landlock+seccomp)", "connected to relay.moochy.dev", "1 of 2 devices online", "1 cloud box expires within 24 h"] {
            assert!(out.contains(want), "missing {want}:\n{out}");
        }
    }

    #[test]
    fn empty_and_unsafe_states_say_what_to_do() {
        let s = Snapshot::default();
        let t = themes()[0];
        let mut v = DevicesView::default();
        let out = draw(&mut v, &ctx(&s, &t, ""), 160, 48);
        for want in ["moochy login", "moochy keys add", "moochy box token create", "not connected", "unknown", "no provider key"] {
            assert!(out.contains(want), "missing {want}:\n{out}");
        }
        let mut s = snap();
        s.me.lockdown = Lockdown::Unsafe;
        let out = draw(&mut v, &ctx(&s, &t, ""), 160, 48);
        assert!(out.contains("UNSAFE"), "{out}");
        s.me.lockdown = Lockdown::Failed("no landlock".into());
        let out = draw(&mut v, &ctx(&s, &t, ""), 160, 48);
        assert!(out.contains("not locked down: no landlock"), "{out}");
    }

    #[test]
    fn keys_promise_is_always_on_screen() {
        let s = snap();
        let e = Snapshot::default();
        for t in themes() {
            for (w, h) in [(80, 24), (160, 48)] {
                for snap in [&s, &e] {
                    let mut v = DevicesView::default();
                    let out = draw(&mut v, &ctx(snap, &t, ""), w, h);
                    assert!(out.contains(KEYS_PROMISE), "{out}");
                    let promise = out.find(KEYS_PROMISE).unwrap();
                    assert!(promise < out.find("Provider keys").unwrap(), "above the key list:\n{out}");
                }
            }
        }
    }

    #[test]
    fn revoke_only_on_a_box_or_token() {
        let s = snap();
        let t = themes()[0];
        let c = ctx(&s, &t, "");
        let mut v = DevicesView::default();
        draw(&mut v, &c, 160, 48);
        assert!(matches!(v.on_input(&Input::Char('x'), &c), Outcome::Toast(_)), "the cursor starts on a device, not the header");
        v.on_input(&Input::End, &c);
        let Outcome::Confirm { action, .. } = v.on_input(&Input::Char('x'), &c) else { panic!() };
        assert_eq!(action, Action::RevokeBoxToken("bt_1".into()));
        v.on_input(&Input::Up, &c); // over the "Box tokens" header, onto the box
        let Outcome::Confirm { action, body, .. } = v.on_input(&Input::Char('x'), &c) else { panic!() };
        assert_eq!(action, Action::RevokeBox("d_box9".into()));
        assert!(body.contains("github/foo/bar"));
        let out = draw(&mut v, &ctx(&s, &t, "box"), 160, 48);
        assert!(out.contains("Cloud boxes · 1") && !out.contains("laptop"), "{out}");
    }
}
