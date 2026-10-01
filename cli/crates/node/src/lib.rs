//! `moochy` node: CLI, config, keystore, relay link (gRPC + channel binding), gateway API door,
//! MCP door (stdio + Streamable HTTP), local control plane, worker-role orchestration.
//! Crypto plugs in through [`engine::Sealer`] (`moochy-proto`), provider execution through
//! [`engine::Executor`] (`moochy-worker`).
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)
)]

pub mod approve;
pub mod cli;
pub mod config;
pub mod ctl;
pub mod connect;
pub mod engine;
pub mod files;
pub mod gate;
pub mod gateway;
pub mod json;
pub mod keycheck;
pub mod keylog;
pub mod keystore;
pub mod link;
pub mod lockdown;
pub mod login;
pub mod mcp;
pub mod native;
pub mod node;
pub mod owner;
pub mod run;
pub mod pb;
pub mod scrub;
pub mod task;
pub mod tls;
pub mod util;
pub mod validator;
pub mod worker;
#[cfg(test)]
mod voice;
