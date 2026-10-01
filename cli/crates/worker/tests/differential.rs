//! Parser differential vs a provider-style JSON stack (CONTRACT §1): Python's `json` (last key
//! wins, lenient numbers) must read every body the Worker forwards — fixture bodies, prepared
//! (mutated) provider bodies, re-emitted bodies and SSE event payloads — as exactly the tree our
//! strict parser validated, with no duplicate keys. Skips when python3 is absent.
#![allow(clippy::case_sensitive_file_extension_comparisons, clippy::map_unwrap_or, clippy::unwrap_used, clippy::indexing_slicing, clippy::panic, clippy::format_push_string)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use moochy_worker::firewall::{self, Catalog, Level, MaxPrice, Policy, Request};
use moochy_worker::json::{self, Kind, Val};
use moochy_worker::{Dialect, Effort, Flags, Provider, reemit};

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Sorted `path \t type \t value` leaves; strings as UTF-8 hex, floats as IEEE-754 bits.
fn listing(v: Val<'_>, path: &str, out: &mut Vec<String>) {
    match v.kind() {
        Kind::Null => out.push(format!("{path}\tnull\t")),
        Kind::Bool => out.push(format!("{path}\tbool\t{}", v.as_bool().unwrap())),
        Kind::Num => match v.as_i64() {
            Some(i) => out.push(format!("{path}\tint\t{i}")),
            None => out.push(format!("{path}\tfloat\t{:016x}", v.as_f64().unwrap().to_bits())),
        },
        Kind::Str => out.push(format!("{path}\tstr\t{}", hex(v.as_str().unwrap().as_bytes()))),
        Kind::Arr => {
            out.push(format!("{path}\tarr\t{}", v.items().count()));
            for (i, it) in v.items().enumerate() {
                listing(it, &format!("{path}/{i}"), out);
            }
        }
        Kind::Obj => {
            out.push(format!("{path}\tobj\t{}", v.entries().count()));
            for (k, x) in v.entries() {
                listing(x, &format!("{path}/{}", hex(k.as_str().unwrap().as_bytes())), out);
            }
        }
    }
}

const PY: &str = r#"
import json, sys, struct
def h(s): return s.encode('utf-8', 'surrogatepass').hex()
def dup_hook(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)): raise ValueError('duplicate key')
    return dict(pairs)
def walk(v, p, out):
    if v is None: out.append(f"{p}\tnull\t")
    elif isinstance(v, bool): out.append(f"{p}\tbool\t{'true' if v else 'false'}")
    elif isinstance(v, int): out.append(f"{p}\tint\t{v}")
    elif isinstance(v, float): out.append(f"{p}\tfloat\t{struct.pack('>d', v).hex()}")
    elif isinstance(v, str): out.append(f"{p}\tstr\t{h(v)}")
    elif isinstance(v, list):
        out.append(f"{p}\tarr\t{len(v)}")
        for i, x in enumerate(v): walk(x, f"{p}/{i}", out)
    else:
        out.append(f"{p}\tobj\t{len(v)}")
        for k, x in v.items(): walk(x, f"{p}/{h(k)}", out)
docs = sys.stdin.buffer.read().split(b'\x00')
for d in docs:
    if not d: continue
    try:
        v = json.loads(d.decode('utf-8'), object_pairs_hook=dup_hook)
        out = []; walk(v, '', out); out.sort()
        sys.stdout.write('\n'.join(out) + '\n\x1e\n')
    except Exception as e:
        sys.stdout.write(f'ERROR {e}\n\x1e\n')
"#;

fn bodies() -> Vec<(String, Vec<u8>)> {
    let cat = Catalog { default_effort: Effort::High, max_output: 128_000, max_image_tokens: 1600, max_page_tokens: 3000 };
    let pol = Policy { level: Level::Strict, flags: Flags::IMAGES.with(Flags::DOCUMENTS), max_effort: Effort::Max };
    let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut docs = Vec::new();
    let mut stack = vec![fx];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let b = std::fs::read(&p).unwrap();
            if name.ends_with(".sse") {
                // Every SSE `data:` payload that is JSON, as it would reach a client parser.
                for (i, line) in b.split(|c| *c == b'\n').enumerate() {
                    if let Some(d) = line.strip_prefix(b"data: ").filter(|d| d.first() == Some(&b'{')) {
                        docs.push((format!("{name}:{i}"), d.to_vec()));
                    }
                }
                let d = if name.contains("anthropic") || name.contains("_msg_") { Dialect::AnthropicMessages } else { Dialect::OpenAiChat };
                if let Ok(out) = reemit::reemit(d, true, &b) {
                    for (i, line) in out.split(|c| *c == b'\n').enumerate() {
                        if let Some(d) = line.strip_prefix(b"data: ").filter(|d| d.first() == Some(&b'{')) {
                            docs.push((format!("reemit {name}:{i}"), d.to_vec()));
                        }
                    }
                }
            } else if name.ends_with(".json") {
                docs.push((name.clone(), b.clone()));
                for d in [Dialect::AnthropicMessages, Dialect::OpenAiChat] {
                    if let Ok(out) = reemit::reemit(d, false, &b) {
                        docs.push((format!("reemit {name}"), out));
                    }
                    let pooled = firewall::pool_compatible(d, &b, &[]).map(|p| p.body).unwrap_or_else(|_| b.clone());
                    for p in [Provider::Anthropic, Provider::OpenRouter, Provider::DeepSeek, Provider::OpenAi, Provider::XAi] {
                        let r = Request {
                            provider: p,
                            dialect: d,
                            body: &pooled,
                            headers: &[],
                            policy: &pol,
                            catalog: &cat,
                            provider_model_id: "model-1",
                            user_pseudonym: "ps_\u{e9}\u{1f600}",
                            max_price: Some(MaxPrice { prompt_uusd_per_mtok: 1_250_000, completion_uusd_per_mtok: 15_000_001 }),
                        };
                        if let Ok(out) = firewall::prepare(&r) {
                            docs.push((format!("prepared {name} {p:?}"), out.body.to_vec()));
                        }
                    }
                }
            }
        }
    }
    // Edge cases: escapes, surrogate pairs, big/negative/zero numbers, floats.
    for e in [
        r#"{"a":"é😀\n\t\"\\\/","b":[-0,0,-9223372036854775808,9223372036854775807,1.5e300,-2.5E-300,0.1],"c":{}}"#,
        r#"{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"\u0000\u001f "}]}"#,
    ] {
        docs.push((format!("edge {e}"), e.as_bytes().to_vec()));
        let mut t = Vec::new();
        let mut canon = Vec::new();
        json::write(json::parse(e.as_bytes(), &mut t).unwrap().root(), &mut canon);
        docs.push((format!("canonical {e}"), canon));
    }
    docs
}

#[test]
fn python_reads_what_we_validated() {
    if Command::new("python3").arg("-c").arg("pass").status().map(|s| !s.success()).unwrap_or(true) {
        eprintln!("SKIP: python3 not available");
        return;
    }
    let docs = bodies();
    assert!(docs.len() > 100, "{}", docs.len());
    let mut input = Vec::new();
    for (_, d) in &docs {
        input.extend_from_slice(d);
        input.push(0);
    }
    let mut child = Command::new("python3").arg("-c").arg(PY).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let theirs: Vec<&str> = text.split("\n\u{1e}\n").filter(|s| !s.is_empty()).collect();
    assert_eq!(theirs.len(), docs.len());
    let mut checked = 0;
    for ((name, d), py) in docs.iter().zip(theirs) {
        let mut t = Vec::new();
        let Ok(doc) = json::parse(d, &mut t) else { continue }; // ours refused: nothing forwarded
        assert!(!py.starts_with("ERROR"), "{name}: python refused what we accepted: {py}");
        let mut ours = Vec::new();
        listing(doc.root(), "", &mut ours);
        ours.sort();
        assert_eq!(ours.join("\n"), py, "{name}: python reads a different tree");
        checked += 1;
    }
    println!("python differential: {checked} documents identical");
    assert!(checked > 100);
}
