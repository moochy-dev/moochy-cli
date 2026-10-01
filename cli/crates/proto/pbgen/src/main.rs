//! Regenerates `cli/crates/proto/src/pb/moochy.v1.rs` from `spec/proto/moochy/v1/link.proto`.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    tonic_prost_build::configure()
        // `bytes::Bytes` for every bytes field: ciphertext chunks cross into the data plane zero-copy.
        .bytes(".")
        .build_transport(false)
        .out_dir(root.join("cli/crates/proto/src/pb"))
        .compile_protos(&[root.join("spec/proto/moochy/v1/link.proto")], &[root.join("spec/proto")])?;
    Ok(())
}
