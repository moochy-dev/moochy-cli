//! `moochy-worker`: everything that touches a provider or inspects provider traffic.
//!
//! Plain inputs in, events out; no dependency on `moochy-proto`. See `API.md` for the
//! public surface and how the node wires it.
//!
//! - [`firewall`]: strict JSON + per-adapter allowlist tables, route facts, safe mutations.
//! - [`provider`]: HTTP/2 + rustls adapters for anthropic, openrouter, deepseek, openai.
//! - [`stream`]: incremental SSE/JSON response parser: usage, model, tool-call boundaries.
//! - [`inspect`]: tool-call structural checks and tripwire (gateway side).
//! - [`validate`]: single-use request validator child + its parent-side client (CONTRACT §15.2).
//! - [`redact`]: provider-key redaction of everything that leaves the donor (A291).
//! - [`reemit`]: canonical re-emission of donor responses to the agent (CONTRACT §15.4).
//! - [`clean_text`]: strip terminal control sequences from displayed donor text.
//! - [`store`]: outbox, served-task set, local reservation counters (one crash-safe log).
#![forbid(unsafe_code)]

mod clean;
mod codec;
pub mod firewall;
pub mod inspect;
pub mod json;
pub mod provider;
pub mod redact;
pub mod reemit;
pub mod store;
pub mod stream;
pub mod validate;
mod tables;

pub use clean::clean_text;

use std::fmt;

/// API dialect a client speaks (route header `dialect`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dialect {
    AnthropicMessages,
    OpenAiChat,
    /// OpenAI Responses (`POST /v1/responses`, CONTRACT §18.6): passthrough to providers that
    /// speak it natively (OpenAI, xAI, OpenRouter); stateless only.
    OpenAiResponses,
}

impl Dialect {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "anthropic.messages" => Some(Self::AnthropicMessages),
            "openai.chat" => Some(Self::OpenAiChat),
            "openai.responses" => Some(Self::OpenAiResponses),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnthropicMessages => "anthropic.messages",
            Self::OpenAiChat => "openai.chat",
            Self::OpenAiResponses => "openai.responses",
        }
    }
}

/// A donor's provider (adapter).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Provider {
    Anthropic,
    OpenRouter,
    DeepSeek,
    OpenAi,
    /// xAI (Grok): OpenAI-compatible chat completions and Responses.
    XAi,
    /// A donor's own OpenAI-compatible inference server (Ollama, LM Studio, vLLM, llama.cpp
    /// server) on loopback or the LAN: free, goals counted in tokens (see `API.md`).
    Local,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "anthropic" => Some(Self::Anthropic),
            "openrouter" => Some(Self::OpenRouter),
            "deepseek" => Some(Self::DeepSeek),
            "openai" => Some(Self::OpenAi),
            "xai" => Some(Self::XAi),
            "local" => Some(Self::Local),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenRouter => "openrouter",
            Self::DeepSeek => "deepseek",
            Self::OpenAi => "openai",
            Self::XAi => "xai",
            Self::Local => "local",
        }
    }

    /// Whether this adapter serves `dialect` (07 §6.2), from [`provider::AdapterDef`].
    pub fn serves(self, dialect: Dialect) -> bool {
        provider::AdapterDef::of(self).path(dialect).is_some()
    }
}

/// Reasoning effort, ordered from cheapest to most expensive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    XHigh,
    Max,
}

impl Effort {
    const ALL: [(Self, &'static str); 7] = [
        (Self::None, "none"),
        (Self::Minimal, "minimal"),
        (Self::Low, "low"),
        (Self::Medium, "medium"),
        (Self::High, "high"),
        (Self::XHigh, "xhigh"),
        (Self::Max, "max"),
    ];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().find(|(_, n)| *n == s).map(|(e, _)| *e)
    }

    pub fn as_str(self) -> &'static str {
        Self::ALL.iter().find(|(e, _)| *e == self).map_or("none", |(_, n)| n)
    }
}

/// Donor opt-ins (pledge `policy.flags`) and the features a request uses (route `flags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct Flags(u8);

impl Flags {
    pub const NONE: Self = Self(0);
    pub const IMAGES: Self = Self(1);
    pub const DOCUMENTS: Self = Self(2);
    pub const FAST: Self = Self(4);
    pub const LONG_CONTEXT: Self = Self(8);
    pub const SERVICE_TIER: Self = Self(16);
    pub const INFERENCE_GEO: Self = Self(32);

    const NAMES: [(Self, &'static str); 6] = [
        (Self::IMAGES, "images"),
        (Self::DOCUMENTS, "documents"),
        (Self::FAST, "fast"),
        (Self::LONG_CONTEXT, "long_context"),
        (Self::SERVICE_TIER, "service_tier"),
        (Self::INFERENCE_GEO, "inference_geo"),
    ];

    /// Parse flag names; an unknown name is an error (fail closed).
    pub fn parse<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut f = Self::NONE;
        for n in names {
            let Some((v, _)) = Self::NAMES.iter().find(|(_, s)| *s == n) else {
                return Err(format!("unknown flag `{n}`"));
            };
            f = f.with(*v);
        }
        Ok(f)
    }

    pub fn names(self) -> Vec<&'static str> {
        Self::NAMES.iter().filter(|(v, _)| self.has(*v)).map(|(_, n)| *n).collect()
    }

    pub const fn has(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.names().join(","))
    }
}
