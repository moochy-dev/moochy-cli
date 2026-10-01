//! SSE/usage parser (both dialects, streamed and whole-body): no panic; the outcome and
//! events do not depend on how the bytes are chunked.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::stream::{Event, Outcome, StreamParser};
use moochy_worker::Dialect;

fn run(d: Dialect, stream: bool, b: &[u8], step: usize) -> Option<(Outcome, Vec<(u64, u64, u8)>)> {
    let mut p = StreamParser::new(d, stream);
    let mut ev = Vec::new();
    for c in b.chunks(step.max(1)) {
        p.feed(c, &mut |s, e| {
            let k = match e {
                Event::Other => 0,
                Event::ToolStart { .. } => 1,
                Event::ToolArgs { json, .. } => {
                    let _ = json.as_str();
                    2
                }
                Event::ToolEnd { .. } => 3,
                Event::Forbidden { .. } => 4,
                Event::Error => 5,
                Event::Stop => 6,
                Event::Invalid => 7,
            };
            ev.push((s.start, s.end, k));
        })
        .ok()?;
    }
    Some((p.finish(), ev))
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let d = if sel & 1 == 0 { Dialect::AnthropicMessages } else { Dialect::OpenAiChat };
    let stream = sel & 2 == 0;
    let step = usize::from(sel >> 2) + 1;
    let a = run(d, stream, rest, rest.len());
    let b = run(d, stream, rest, step);
    assert_eq!(a, b, "chunking changed the result");
});
