//! Generated protobuf/gRPC code (committed; regenerate with `tools/pbgen`).
//! `link`: spec/proto/moochy/v1/link.proto (client only, `bytes` = `Bytes`). `local`: local.proto.
//!
//! ponytail: `link` duplicates `moochy_proto::pb` because that copy predates the current
//! link.proto (repo_slug, sign_pub, key-log messages); once moochy-proto regenerates, re-export
//! it here and delete `pb/link.rs` and the two `Chunk` conversions.
#![allow(clippy::all, clippy::pedantic, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, missing_docs)]

pub mod link {
    include!("pb/link.rs");
}
pub mod local {
    include!("pb/local.rs");
}

/// Our `Chunk` → moochy-proto's (zero-copy: `ct` is a refcounted `Bytes`).
pub fn to_proto(c: link::Chunk) -> moochy_proto::pb::Chunk {
    moochy_proto::pb::Chunk { attempt: c.attempt, seq: c.seq, last: c.last, ct: c.ct }
}

pub fn from_proto(c: moochy_proto::pb::Chunk) -> link::Chunk {
    link::Chunk { attempt: c.attempt, seq: c.seq, last: c.last, ct: c.ct }
}
