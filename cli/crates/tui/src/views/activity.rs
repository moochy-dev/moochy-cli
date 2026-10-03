//! The Activity tab (CONTRACT §20.2). Owner: mo-tui-donor. Skeleton by the integrator; replace freely.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};

use super::{Ctx, Input, Outcome, View};

#[derive(Default)]
pub struct ActivityView;

impl View for ActivityView {
    fn title(&self) -> &'static str {
        "Activity"
    }

    fn hints(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    fn render(&mut self, f: &mut Frame, area: Rect, ctx: &Ctx) {
        f.render_widget(Paragraph::new("").block(Block::default().borders(Borders::ALL).title(self.title()).style(ctx.theme.text())), area);
    }

    fn on_input(&mut self, _input: &Input, _ctx: &Ctx) -> Outcome {
        Outcome::Ignored
    }
}
