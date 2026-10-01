//! Writes the golden vectors: `cargo run -p moochy-proto --example vecgen -- ../spec/vectors`
//! (path relative to `cli/`). Output is deterministic; `tests/vectors.rs` fails on drift.
#![allow(clippy::pedantic, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod r#gen;

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "../../../spec/vectors".into());
    std::fs::create_dir_all(&dir).unwrap();
    for (name, v) in r#gen::all() {
        let path = std::path::Path::new(&dir).join(name);
        std::fs::write(&path, r#gen::render(&v)).unwrap();
        println!("wrote {}", path.display());
    }
}
