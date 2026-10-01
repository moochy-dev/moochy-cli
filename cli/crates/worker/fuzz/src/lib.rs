//! Shared helpers for the fuzz targets.
use moochy_worker::firewall::{Catalog, Level, Policy};
use moochy_worker::{Dialect, Effort, Flags};

pub const CAT: Catalog = Catalog { default_effort: Effort::High, max_output: 128_000, max_image_tokens: 1600, max_page_tokens: 3000 };

/// First byte selects dialect, level and flags; the rest is the input.
pub fn split(data: &[u8]) -> Option<(Dialect, Policy, &[u8])> {
    let (&sel, rest) = data.split_first()?;
    let dialect = if sel & 1 == 0 { Dialect::AnthropicMessages } else { Dialect::OpenAiChat };
    let level = if sel & 2 == 0 { Level::Strict } else { Level::Paranoid };
    let flags = Flags::parse(["images", "documents", "fast", "long_context"].iter().enumerate().filter(|(i, _)| sel & (4 << i) != 0).map(|(_, n)| *n)).ok()?;
    Some((dialect, Policy { level, flags, max_effort: Effort::Max }, rest))
}
