//! `moochy-keylog`: the Node side of the Moochy key log (plan 06 §10, spec/KEYLOG.md).
//!
//! - [`merkle`]: RFC 6962/9162 hashing, inclusion and consistency proof verification
//! - [`note`]: signed-note checkpoint verification (C2SP tlog-checkpoint, Ed25519 ZIP-215)
//! - [`entry`]: exact record formats of the entry kinds
//! - [`webauthn`]: passkey owner keys (`webauthn-es256`): COSE key, assertion check
//! - [`state`]: the authority state machine and the two pure questions
//!   "is this worker key sealable for repo R" / "is this gateway allowed for repo R"
//! - [`tiles`]: C2SP tlog-tiles paths and bounded entry-bundle parsing
//! - [`mirror`]: full incremental mirror + monitor rules (own keys, owner actions, forks)
//! - [`monitor`]: the Node's async monitor loop over the relay link ([`LogLink`]), the
//!   shared fail-closed [`View`] for Gateways and Workers, persistence (see `WIRING.md`)
//! - [`cosig`]: witness cosignatures (C2SP tlog-cosignature v1)
//! - [`receipts`]: receipt transparency log inclusion
//! - [`projection`]: verify a donor-signed projection fetched by reference (`moochy verify`)
//! - `fetch` (feature `http`): blocking tile fetcher with size limits and timeouts
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

mod b64;
pub mod cosig;
pub mod entry;
#[cfg(feature = "http")]
pub mod fetch;
pub mod merkle;
pub mod mirror;
pub mod monitor;
pub mod note;
pub mod projection;
pub mod receipts;
pub mod state;
pub mod tiles;
pub mod webauthn;

pub use entry::{Entry, Kind};
pub use merkle::Hash;
pub use mirror::{Alert, AnchorStatus, Me, Mirror};
pub use monitor::{Event, LogLink, Monitor, View};
pub use note::{Checkpoint, NoteKey};
pub use state::{Code, State};

/// The one coarse error of this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Malformed input (record, note, tile, path, key).
    Format(&'static str),
    /// A signature did not verify.
    BadSig,
    /// The relay's checkpoint or entries are not consistent with the mirrored history
    /// (or with the anchor): evidence of a forked or rewritten log.
    Fork { size: u64 },
    /// Input larger than its bound.
    TooLarge,
    /// Transport failure (feature `http`).
    Io(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(w) => write!(f, "keylog: bad format: {w}"),
            Self::BadSig => f.write_str("keylog: bad signature"),
            Self::Fork { size } => {
                write!(f, "keylog: FORK: log is inconsistent at tree size {size}")
            }
            Self::TooLarge => f.write_str("keylog: input too large"),
            Self::Io(e) => write!(f, "keylog: io: {e}"),
        }
    }
}

impl std::error::Error for Error {}
