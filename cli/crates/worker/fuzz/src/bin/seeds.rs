//! Writes the seed corpora (all crate fixtures) into <dir>/<target>/.
use std::path::Path;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: seeds <dir>");
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures");
    let mut files = Vec::new();
    let mut stack = vec![fx];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).expect("fixtures") {
            let p = e.expect("entry").path();
            if p.is_dir() { stack.push(p) } else { files.push(p) }
        }
    }
    for (i, f) in files.iter().enumerate() {
        let b = std::fs::read(f).expect("read");
        let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("x");
        let sse = name.ends_with(".sse");
        let openai = !(name.contains("anthropic") || name.contains("_msg_") || name.contains("claude"));
        let sel = u8::from(openai);
        let put = |target: &str, sel: u8, body: &[u8]| {
            let d = Path::new(&dir).join(target);
            std::fs::create_dir_all(&d).expect("mkdir");
            let mut v = vec![sel];
            v.extend_from_slice(body);
            std::fs::write(d.join(format!("{i:03}-{sel}-{name}")), v).expect("write");
        };
        put("stream", sel | if sse { 0 } else { 2 } | (7 << 2), &b);
        put("reemit", sel | if sse { 0 } else { 2 } | (5 << 2), &b);
        if name.ends_with(".json") && !name.contains("headers") {
            put("json", 0, &b);
            put("firewall", sel | 4 | 8, &b);
            put("inspect", 0, &b);
        }
    }
}
