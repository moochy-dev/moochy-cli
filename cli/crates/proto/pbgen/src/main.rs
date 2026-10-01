//! Regenerates `cli/crates/proto/src/pb/moochy.v1.rs` from `spec/proto/moochy/v1/link.proto`.
//! `--check`: generate into a temporary directory and fail (exit 1) if the committed file differs
//! (CI: generated code must be up to date, CONTRACT §12).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let committed = root.join("cli/crates/proto/src/pb");
    let check = std::env::args().any(|a| a == "--check");
    let out = if check { std::env::temp_dir().join(format!("moochy-pbgen-{}", std::process::id())) } else { committed.clone() };
    std::fs::create_dir_all(&out)?;
    tonic_prost_build::configure()
        // `bytes::Bytes` for every bytes field: ciphertext chunks cross into the data plane zero-copy.
        .bytes(".")
        .build_transport(false)
        .out_dir(&out)
        .compile_protos(&[root.join("spec/proto/moochy/v1/link.proto")], &[root.join("spec/proto")])?;
    if check {
        let same = std::fs::read(out.join("moochy.v1.rs"))? == std::fs::read(committed.join("moochy.v1.rs"))?;
        std::fs::remove_dir_all(&out)?;
        if !same {
            eprintln!("cli/crates/proto/src/pb is stale: run `cargo run` in cli/crates/proto/pbgen");
            std::process::exit(1);
        }
        println!("cli/crates/proto/src/pb is up to date");
    }
    Ok(())
}
