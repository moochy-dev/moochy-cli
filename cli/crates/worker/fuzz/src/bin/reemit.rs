//! Canonical re-emission: no panic; accepted output is a fixed point, independent of chunking,
//! and never malformed for the strict parser when the input was not. A216: every string the
//! output carries under a text-bearing key is reported by `visible_texts` (what the tripwire
//! scans), and `visible_texts` never panics on any parsed input.
#![no_main]
use libfuzzer_sys::fuzz_target;
use moochy_worker::reemit::{self, Reemitter};
use moochy_worker::stream::StreamParser;
use moochy_worker::json::{self, Kind, Val};
use moochy_worker::Dialect;

const TEXT_KEYS: &[&str] = &["text", "thinking", "content", "refusal", "reasoning", "reasoning_content", "cited_text", "document_title"];

fn written(v: Val<'_>, out: &mut Vec<String>) {
    match v.kind() {
        Kind::Obj => {
            for (k, x) in v.entries() {
                if x.kind() == Kind::Str && TEXT_KEYS.iter().any(|t| k.is_str(t)) {
                    out.push(x.as_str().expect("string").into_owned());
                } else {
                    written(x, out);
                }
            }
        }
        Kind::Arr => v.items().for_each(|x| written(x, out)),
        _ => {}
    }
}

/// Every text-key string of one canonical JSON document is in `visible_texts`.
fn covered(d: Dialect, stream: bool, doc: &[u8]) {
    let mut tape = Vec::new();
    let root = json::parse(doc, &mut tape).expect("canonical output is strict JSON").root();
    let mut seen = Vec::new();
    reemit::visible_texts(d, stream, root, &mut |t| seen.push(t.to_owned()));
    let mut w = Vec::new();
    written(root, &mut w);
    for t in w {
        assert!(seen.contains(&t), "text {t:?} written but not scanned");
    }
}

fn malformed(d: Dialect, b: &[u8]) -> bool {
    let mut p = StreamParser::new(d, true);
    p.feed(b, &mut |_, _| {}).is_err() || p.finish().malformed
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    let d = if sel & 1 == 0 { Dialect::AnthropicMessages } else { Dialect::OpenAiChat };
    let stream = sel & 2 == 0;
    let mut tape = Vec::new();
    if let Ok(doc) = json::parse(rest, &mut tape) {
        reemit::visible_texts(d, stream, doc.root(), &mut |_| {});
    }
    let Ok(out) = reemit::reemit(d, stream, rest) else { return };
    if stream {
        for ev in out.split(|b| *b == b'\n').filter_map(|l| l.strip_prefix(b"data: ")).filter(|l| *l != b"[DONE]") {
            covered(d, true, ev);
        }
    } else {
        covered(d, false, &out);
    }
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
