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
    let urls = ["http://127.0.0.1:11434", "http://[::1]:8000/", "http://192.168.1.20:1234", "http://100.64.0.1:8080", "http://[fd00::1]:11434", "http://169.254.169.254", "http://[::ffff:10.0.0.1]:80", "https://gpu.local:443", "http://8.8.8.8", "https://abc123-8000.proxy.runpod.net", "https://[2001:4860::8888]:8443/", "https://203.0.113.7:8443", "https://[fe80::1%25eth0]:8443", "https://2130706433", "https://gpu.example.com.:443"];
    for (i, u) in urls.iter().enumerate() {
        let d = Path::new(&dir).join("local_url");
        std::fs::create_dir_all(&d).expect("mkdir");
        std::fs::write(d.join(format!("url{i}")), u).expect("write");
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
        if name.ends_with(".json") { put("json_diff", 0, &b); }
        put("stream", sel | if sse { 0 } else { 2 } | (7 << 2), &b);
        put("reemit", sel | if sse { 0 } else { 2 } | (5 << 2), &b);
        if name.ends_with(".json") && !name.contains("headers") {
            put("json", 0, &b);
            put("json_diff", 0, &b);
            put("firewall", sel | 4 | 8, &b);
            put("inspect", 0, &b);
        }
    }
}
