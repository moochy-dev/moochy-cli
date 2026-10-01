//! Canonical re-emission: no panic; accepted output is a fixed point, independent of chunking,
//! and never malformed for the strict parser when the input was not.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::reemit::{self, Reemitter};
use moochy_worker::stream::StreamParser;
use moochy_worker::Dialect;

fn malformed(d: Dialect, b: &[u8]) -> bool {
    let mut p = StreamParser::new(d, true);
    p.feed(b, &mut |_, _| {}).is_err() || p.finish().malformed
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let d = if sel & 1 == 0 { Dialect::AnthropicMessages } else { Dialect::OpenAiChat };
    let stream = sel & 2 == 0;
    let Ok(out) = reemit::reemit(d, stream, rest) else { return };
    assert_eq!(reemit::reemit(d, stream, &out).expect("canonical output must re-emit"), out);
    if stream {
        let mut r = Reemitter::new(d, true);
        let mut chunked = Vec::new();
        for c in rest.chunks(usize::from(sel >> 2) + 1) {
            r.push(c, &mut chunked).expect("chunking must not change acceptance");
        }
        r.finish(&mut chunked).expect("chunking must not change acceptance");
        assert_eq!(chunked, out);
        if !malformed(d, rest) {
            assert!(!malformed(d, &out));
        }
    }
});
