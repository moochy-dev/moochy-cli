//! The committed `spec/vectors/*.json` must be exactly what the library produces today.
//! Regenerate with `cargo run -p moochy-proto --example vecgen -- ../spec/vectors` (from `cli/`).
#![allow(clippy::pedantic, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "../examples/vecgen/gen.rs"]
mod r#gen;

#[test]
fn committed_vectors_match_library() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../spec/vectors");
    for (name, v) in r#gen::all() {
        let want = r#gen::render(&v);
        let got = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        assert!(got == want, "spec/vectors/{name} is stale: regenerate with the vecgen example");
    }
}
