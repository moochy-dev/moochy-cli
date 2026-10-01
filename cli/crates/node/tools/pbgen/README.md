Regenerates `src/pb/{link,local}.rs` (committed; builds never need protoc):

    PROTOC=$(which protoc) cargo run --manifest-path cli/crates/node/tools/pbgen/Cargo.toml -- "$PWD" /tmp/pbout
    cp /tmp/pbout/link/moochy.v1.rs cli/crates/node/src/pb/link.rs
    cp /tmp/pbout/local/moochy.v1.rs cli/crates/node/src/pb/local.rs

Run from the repo root. Pinned: protoc 36.2, tonic-prost-build 0.14.
