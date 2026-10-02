//! Canonical re-emission (CONTRACT §15.4, attacks A162/A145): the Gateway never passes donor
//! bytes to the agent verbatim. Every event of the decrypted donor stream is parsed (strict
//! JSON) into a typed form checked against a per-event allowlist and written back as
//! canonical bytes:
//! - SSE framing: `event: <type>\n` (Anthropic only) + `data: <json>\n\n`; LF only; no `id:`,
//!   `retry:` or comments; one `event:` and one `data:` line per event;
//! - JSON: members in schema order, minimal escapes, numbers re-validated, strings bounded,
//!   human-visible text passed through [`crate::clean_text`];
//! - unknown *optional* members are dropped (and counted); unknown event or block types,
//!   wrong types, oversize fields or events, duplicate keys, invalid UTF-8, CR-only line
//!   endings, `id:`/`retry:`/duplicate `event:` lines and truncated events fail closed.
//!
//! Stream-friendly: event by event, only the current event is buffered.

use std::fmt;
use std::io::Write as _;

use crate::clean::clean_text;
use crate::json::{self, Kind, Node, Val};
use crate::Dialect;

/// Largest SSE event (one `data:` payload) re-emitted (Responses `response.completed` events
/// carry the whole response object).
pub const MAX_EVENT: usize = 4 << 20;
/// Largest non-streamed body re-emitted.
pub const MAX_BODY: usize = 32 << 20;
const ID: usize = 256;
const TEXT: usize = 8 << 20;
const RAW: usize = 8 << 20;

/// Why an attempt must fail (map to the dialect's native retryable error, e.g. Anthropic
/// `overloaded_error` / OpenAI 502).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReemitError(pub &'static str);

impl fmt::Display for ReemitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "donor stream refused: {}", self.0)
    }
}

impl std::error::Error for ReemitError {}

fn fail<T>(why: &'static str) -> Result<T, ReemitError> {
    Err(ReemitError(why))
}

// ---------------------------------------------------------------------------------------
// Schema language

/// Output schema: what may appear and how it is written.
pub(crate) enum T {
    /// Human-visible text: cleaned of terminal controls, ≤ n bytes.
    Text(usize),
    /// Opaque string kept as is (signatures, JSON fragments, encrypted data), ≤ n bytes.
    Raw(usize),
    /// Identifier: `[A-Za-z0-9._:/@+-]`, 1..=n bytes.
    Ident(usize),
    /// Exactly this string.
    Lit(&'static str),
    U64,
    /// The integer 0 (OpenAI `choices[].index`: one choice only, `n > 1` is refused).
    Zero,
    /// Non-negative finite number (costs).
    Num,
    Bool,
    Null,
    /// The first alternative whose JSON kind matches.
    Or(&'static [T]),
    Arr(&'static T, usize),
    /// Closed object: written in this order; unknown members dropped and counted.
    Obj(&'static [M]),
    /// Object chosen by its `type`-like member; unknown tag fails.
    Tag(&'static str, &'static [(&'static str, T)]),
    /// Any JSON object, canonically re-serialized (complete tool inputs), ≤ n bytes.
    AnyObj(usize),
    /// Must be exactly `{}`.
    EmptyObj,
    /// Must be exactly `[]`.
    EmptyArr,
}

/// Object member: name, schema, required.
pub(crate) struct M(pub &'static str, pub T, pub bool);

fn ident_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:/@+-".contains(&b))
}

struct W<'o> {
    out: &'o mut Vec<u8>,
    dropped: u64,
}

impl W<'_> {
    fn emit(&mut self, t: &T, v: Val<'_>) -> Result<(), ReemitError> {
        match t {
            T::Text(max) => {
                let s = v.as_str().ok_or(ReemitError("text field is not a string"))?;
                if s.len() > *max {
                    return fail("text field too large");
                }
                json::push_str(self.out, &clean_text(&s));
            }
            T::Raw(max) => {
                let s = v.as_str().ok_or(ReemitError("field is not a string"))?;
                if s.len() > *max {
                    return fail("field too large");
                }
                json::push_str(self.out, &s);
            }
            T::Ident(max) => {
                let s = v.as_str().filter(|s| ident_ok(s, *max)).ok_or(ReemitError("bad identifier"))?;
                json::push_str(self.out, &s);
            }
            T::Lit(want) => {
                if !v.is_str(want) {
                    return fail("unexpected constant");
                }
                json::push_str(self.out, want);
            }
            T::U64 => {
                let n = v.as_u64().ok_or(ReemitError("expected a non-negative integer"))?;
                let _ = write!(self.out, "{n}");
            }
            T::Zero => {
                if v.as_u64() != Some(0) {
                    return fail("only choice 0 is allowed");
                }
                self.out.push(b'0');
            }
            T::Num => {
                let f = v.as_f64().filter(|f| f.is_finite() && *f >= 0.0).ok_or(ReemitError("expected a non-negative number"))?;
                let _ = f;
                self.out.extend_from_slice(v.raw().as_bytes());
            }
            T::Bool => {
                let b = v.as_bool().ok_or(ReemitError("expected a boolean"))?;
                self.out.extend_from_slice(if b { b"true" } else { b"false" });
            }
            T::Null => {
                if !v.is_null() {
                    return fail("expected null");
                }
                self.out.extend_from_slice(b"null");
            }
            T::Or(alts) => {
                let alt = alts.iter().find(|a| kind_of(a).is_none_or(|k| k == v.kind())).ok_or(ReemitError("field has the wrong type"))?;
                self.emit(alt, v)?;
            }
            T::Arr(item, max) => {
                if v.kind() != Kind::Arr {
                    return fail("expected an array");
                }
                self.out.push(b'[');
                for (i, it) in v.items().enumerate() {
                    if i >= *max {
                        return fail("array too long");
                    }
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.emit(item, it)?;
                }
                self.out.push(b']');
            }
            T::Obj(members) => self.obj(members, v)?,
            T::Tag(key, cases) => self.tagged(key, cases, v)?,
            T::AnyObj(max) => self.any_obj(*max, v)?,
            T::EmptyObj => {
                if v.kind() != Kind::Obj || v.entries().next().is_some() {
                    return fail("expected an empty object");
                }
                self.out.extend_from_slice(b"{}");
            }
            T::EmptyArr => {
                if v.kind() != Kind::Arr || v.items().next().is_some() {
                    return fail("expected an empty array");
                }
                self.out.extend_from_slice(b"[]");
            }
        }
        Ok(())
    }

    fn tagged(&mut self, key: &str, cases: &[(&'static str, T)], v: Val<'_>) -> Result<(), ReemitError> {
        if v.kind() != Kind::Obj {
            return fail("expected an object");
        }
        let tag = v.get(key).ok_or(ReemitError("missing type tag"))?;
        let (_, case) = cases.iter().find(|(name, _)| tag.is_str(name)).ok_or(ReemitError("unknown event or block type"))?;
        self.emit(case, v)
    }

    fn any_obj(&mut self, max: usize, v: Val<'_>) -> Result<(), ReemitError> {
        if v.kind() != Kind::Obj {
            return fail("expected an object");
        }
        let start = self.out.len();
        json::write(v, self.out);
        if self.out.len().saturating_sub(start) > max {
            return fail("object too large");
        }
        Ok(())
    }

    fn obj(&mut self, members: &[M], v: Val<'_>) -> Result<(), ReemitError> {
        if v.kind() != Kind::Obj {
            return fail("expected an object");
        }
        let known = v.entries().filter(|(k, _)| members.iter().any(|m| k.is_str(m.0))).count();
        let total = v.entries().count();
        self.dropped = self.dropped.saturating_add(u64::try_from(total.saturating_sub(known)).unwrap_or(0));
        self.out.push(b'{');
        let mut first = true;
        for m in members {
            match v.get(m.0) {
                Some(x) => {
                    if !std::mem::replace(&mut first, false) {
                        self.out.push(b',');
                    }
                    json::push_str(self.out, m.0);
                    self.out.push(b':');
                    self.emit(&m.1, x)?;
                }
                None if m.2 => return fail("required field missing"),
                None => {}
            }
        }
        self.out.push(b'}');
        Ok(())
    }
}

fn kind_of(t: &T) -> Option<Kind> {
    Some(match t {
        T::Text(_) | T::Raw(_) | T::Ident(_) | T::Lit(_) => Kind::Str,
        T::U64 | T::Zero | T::Num => Kind::Num,
        T::Bool => Kind::Bool,
        T::Null => Kind::Null,
        T::Or(_) => return None,
        T::Arr(..) | T::EmptyArr => Kind::Arr,
        T::Obj(_) | T::Tag(..) | T::AnyObj(_) | T::EmptyObj => Kind::Obj,
    })
}

// ---------------------------------------------------------------------------------------
// Allowlists

const OPT_U64: T = T::Or(&[T::Null, T::U64]);
const OPT_WORD: T = T::Or(&[T::Null, T::Ident(64)]);
const OPT_TEXT: T = T::Or(&[T::Null, T::Text(TEXT)]);

// --- Anthropic Messages ---

const A_CACHE_CREATION: T = T::Obj(&[M("ephemeral_5m_input_tokens", T::U64, false), M("ephemeral_1h_input_tokens", T::U64, false)]);
const A_ITERATION: T = T::Obj(&[
    M("type", T::Ident(64), false),
    M("input_tokens", OPT_U64, false),
    M("cache_creation_input_tokens", OPT_U64, false),
    M("cache_read_input_tokens", OPT_U64, false),
    M("cache_creation", T::Or(&[T::Null, A_CACHE_CREATION]), false),
    M("output_tokens", OPT_U64, false),
]);
const A_USAGE: T = T::Obj(&[
    M("input_tokens", OPT_U64, false),
    M("cache_creation_input_tokens", OPT_U64, false),
    M("cache_read_input_tokens", OPT_U64, false),
    M("cache_creation", T::Or(&[T::Null, A_CACHE_CREATION]), false),
    M("output_tokens", OPT_U64, false),
    M("service_tier", OPT_WORD, false),
    M("cost", T::Or(&[T::Null, T::Num]), false),
    M("iterations", T::Or(&[T::Null, T::Arr(&A_ITERATION, 1024)]), false),
]);

const A_CITATION: T = T::Obj(&[
    M("type", T::Ident(64), true),
    M("cited_text", T::Text(TEXT), false),
    M("document_index", T::U64, false),
    M("document_title", OPT_TEXT, false),
    M("start_char_index", T::U64, false),
    M("end_char_index", T::U64, false),
    M("start_page_number", T::U64, false),
    M("end_page_number", T::U64, false),
    M("start_block_index", T::U64, false),
    M("end_block_index", T::U64, false),
]);

const A_TEXT_BLOCK: T = T::Obj(&[M("type", T::Lit("text"), true), M("text", T::Text(TEXT), true), M("citations", T::Or(&[T::Null, T::Arr(&A_CITATION, 4096)]), false)]);
const A_THINKING_BLOCK: T = T::Obj(&[M("type", T::Lit("thinking"), true), M("thinking", T::Text(TEXT), true), M("signature", T::Raw(RAW), false)]);
const A_REDACTED_BLOCK: T = T::Obj(&[M("type", T::Lit("redacted_thinking"), true), M("data", T::Raw(RAW), true)]);

/// Streamed `content_block_start`: tool input must arrive through deltas (`{}` here).
const A_START_BLOCK: T = T::Tag(
    "type",
    &[
        ("text", A_TEXT_BLOCK),
        ("thinking", A_THINKING_BLOCK),
        ("redacted_thinking", A_REDACTED_BLOCK),
        (
            "tool_use",
            T::Obj(&[M("type", T::Lit("tool_use"), true), M("id", T::Ident(ID), true), M("name", T::Ident(128), true), M("input", T::EmptyObj, true)]),
        ),
    ],
);

const A_DELTA: T = T::Tag(
    "type",
    &[
        ("text_delta", T::Obj(&[M("type", T::Lit("text_delta"), true), M("text", T::Text(TEXT), true)])),
        ("input_json_delta", T::Obj(&[M("type", T::Lit("input_json_delta"), true), M("partial_json", T::Raw(RAW), true)])),
        ("thinking_delta", T::Obj(&[M("type", T::Lit("thinking_delta"), true), M("thinking", T::Text(TEXT), true)])),
        ("signature_delta", T::Obj(&[M("type", T::Lit("signature_delta"), true), M("signature", T::Raw(RAW), true)])),
        ("citations_delta", T::Obj(&[M("type", T::Lit("citations_delta"), true), M("citation", A_CITATION, true)])),
    ],
);

const A_MESSAGE_START: T = T::Obj(&[
    M("id", T::Ident(ID), true),
    M("type", T::Lit("message"), true),
    M("role", T::Lit("assistant"), true),
    M("model", T::Ident(ID), true),
    M("content", T::EmptyArr, true),
    M("stop_reason", OPT_WORD, false),
    M("stop_sequence", OPT_TEXT, false),
    M("usage", A_USAGE, true),
]);

const A_ERROR: T = T::Obj(&[M("type", T::Ident(64), true), M("message", T::Text(64 << 10), true)]);

/// One Anthropic SSE event (`data:` object, tag = `type` = the `event:` name).
pub(crate) const ANTHROPIC_EVENT: T = T::Tag(
    "type",
    &[
        ("message_start", T::Obj(&[M("type", T::Lit("message_start"), true), M("message", A_MESSAGE_START, true)])),
        ("content_block_start", T::Obj(&[M("type", T::Lit("content_block_start"), true), M("index", T::U64, true), M("content_block", A_START_BLOCK, true)])),
        ("content_block_delta", T::Obj(&[M("type", T::Lit("content_block_delta"), true), M("index", T::U64, true), M("delta", A_DELTA, true)])),
        ("content_block_stop", T::Obj(&[M("type", T::Lit("content_block_stop"), true), M("index", T::U64, true)])),
        (
            "message_delta",
            T::Obj(&[
                M("type", T::Lit("message_delta"), true),
                M("delta", T::Obj(&[M("stop_reason", OPT_WORD, false), M("stop_sequence", OPT_TEXT, false)]), true),
                M("usage", A_USAGE, false),
            ]),
        ),
        ("message_stop", T::Obj(&[M("type", T::Lit("message_stop"), true)])),
        ("ping", T::Obj(&[M("type", T::Lit("ping"), true)])),
        ("error", T::Obj(&[M("type", T::Lit("error"), true), M("error", A_ERROR, true)])),
    ],
);

/// Non-streamed Anthropic body (message or error).
pub(crate) const ANTHROPIC_BODY: T = T::Tag(
    "type",
    &[
        (
            "message",
            T::Obj(&[
                M("id", T::Ident(ID), true),
                M("type", T::Lit("message"), true),
                M("role", T::Lit("assistant"), true),
                M("model", T::Ident(ID), true),
                M(
                    "content",
                    T::Arr(
                        &T::Tag(
                            "type",
                            &[
                                ("text", A_TEXT_BLOCK),
                                ("thinking", A_THINKING_BLOCK),
                                ("redacted_thinking", A_REDACTED_BLOCK),
                                (
                                    "tool_use",
                                    T::Obj(&[M("type", T::Lit("tool_use"), true), M("id", T::Ident(ID), true), M("name", T::Ident(128), true), M("input", T::AnyObj(RAW), true)]),
                                ),
                            ],
                        ),
                        4096,
                    ),
                    true,
                ),
                M("stop_reason", OPT_WORD, false),
                M("stop_sequence", OPT_TEXT, false),
                M("usage", A_USAGE, true),
            ]),
        ),
        ("error", T::Obj(&[M("type", T::Lit("error"), true), M("error", A_ERROR, true)])),
    ],
);

// --- OpenAI chat completions (OpenAI, OpenRouter, DeepSeek, xAI) ---

const O_USAGE: T = T::Obj(&[
    M("prompt_tokens", T::U64, true),
    M("completion_tokens", T::U64, true),
    M("total_tokens", T::U64, false),
    M(
        "prompt_tokens_details",
        T::Or(&[
            T::Null,
            T::Obj(&[
                M("text_tokens", T::U64, false),
                M("audio_tokens", T::U64, false),
                M("image_tokens", T::U64, false),
                M("cached_tokens", T::U64, false),
                M("cache_write_tokens", T::U64, false),
            ]),
        ]),
        false,
    ),
    M(
        "completion_tokens_details",
        T::Or(&[
            T::Null,
            T::Obj(&[
                M("reasoning_tokens", T::U64, false),
                M("audio_tokens", T::U64, false),
                M("image_tokens", T::U64, false),
                M("accepted_prediction_tokens", T::U64, false),
                M("rejected_prediction_tokens", T::U64, false),
            ]),
        ]),
        false,
    ),
    M("prompt_cache_hit_tokens", T::U64, false),
    M("prompt_cache_miss_tokens", T::U64, false),
    M("cost", T::Num, false),
    M("is_byok", T::Bool, false),
    M("cost_in_usd_ticks", T::U64, false),
    M("num_sources_used", T::U64, false),
]);

/// llama.cpp / Ollama `timings` (local servers): numbers only; the usage fallback reads it.
const O_TIMINGS: T = T::Obj(&[
    M("cache_n", T::U64, false),
    M("prompt_n", T::U64, false),
    M("prompt_ms", T::Num, false),
    M("prompt_per_token_ms", T::Num, false),
    M("prompt_per_second", T::Num, false),
    M("predicted_n", T::U64, false),
    M("predicted_ms", T::Num, false),
    M("predicted_per_token_ms", T::Num, false),
    M("predicted_per_second", T::Num, false),
]);

const O_TOOL_CALL_DELTA: T = T::Obj(&[
    M("index", T::U64, true),
    M("id", T::Ident(ID), false),
    M("type", T::Lit("function"), false),
    M("function", T::Obj(&[M("name", T::Ident(128), false), M("arguments", T::Raw(RAW), false)]), false),
]);

const O_DELTA: T = T::Obj(&[
    M("role", T::Lit("assistant"), false),
    M("content", OPT_TEXT, false),
    M("reasoning_content", OPT_TEXT, false),
    M("reasoning", OPT_TEXT, false),
    M("refusal", OPT_TEXT, false),
    M("tool_calls", T::Or(&[T::Null, T::Arr(&O_TOOL_CALL_DELTA, 128)]), false),
]);

/// One OpenAI-style stream chunk (`data:` object). Errors (`{"error":…}`) use [`O_ERROR`].
pub(crate) const OPENAI_CHUNK: T = T::Obj(&[
    M("id", T::Ident(ID), true),
    M("object", T::Lit("chat.completion.chunk"), true),
    M("created", T::U64, true),
    M("model", T::Ident(ID), true),
    M("system_fingerprint", T::Or(&[T::Null, T::Ident(ID)]), false),
    M("service_tier", OPT_WORD, false),
    M("provider", T::Ident(ID), false),
    M(
        "choices",
        T::Arr(
            &T::Obj(&[
                M("index", T::Zero, true),
                M("delta", O_DELTA, true),
                M("finish_reason", OPT_WORD, false),
                M("native_finish_reason", OPT_WORD, false),
            ]),
            16,
        ),
        true,
    ),
    M("usage", T::Or(&[T::Null, O_USAGE]), false),
    M("timings", O_TIMINGS, false),
]);

pub(crate) const O_ERROR: T = T::Obj(&[M(
    "error",
    T::Obj(&[
        M("message", T::Text(64 << 10), true),
        M("type", T::Or(&[T::Null, T::Ident(64)]), false),
        M("code", T::Or(&[T::Null, T::Ident(64), T::U64]), false),
    ]),
    true,
)]);

/// Non-streamed OpenAI-style body.
pub(crate) const OPENAI_BODY: T = T::Obj(&[
    M("id", T::Ident(ID), true),
    M("object", T::Lit("chat.completion"), true),
    M("created", T::U64, true),
    M("model", T::Ident(ID), true),
    M("system_fingerprint", T::Or(&[T::Null, T::Ident(ID)]), false),
    M("service_tier", OPT_WORD, false),
    M("provider", T::Ident(ID), false),
    M(
        "choices",
        T::Arr(
            &T::Obj(&[
                M("index", T::Zero, true),
                M(
                    "message",
                    T::Obj(&[
                        M("role", T::Lit("assistant"), true),
                        M("content", OPT_TEXT, false),
                        M("reasoning_content", OPT_TEXT, false),
                        M("reasoning", OPT_TEXT, false),
                        M("refusal", OPT_TEXT, false),
                        M(
                            "tool_calls",
                            T::Or(&[
                                T::Null,
                                T::Arr(
                                    &T::Obj(&[
                                        M("id", T::Ident(ID), true),
                                        M("type", T::Lit("function"), true),
                                        M("function", T::Obj(&[M("name", T::Ident(128), true), M("arguments", T::Raw(RAW), true)]), true),
                                    ]),
                                    128,
                                ),
                            ]),
                            false,
                        ),
                    ]),
                    true,
                ),
                M("finish_reason", OPT_WORD, false),
                M("native_finish_reason", OPT_WORD, false),
            ]),
            16,
        ),
        true,
    ),
    M("usage", T::Or(&[T::Null, O_USAGE]), false),
    M("timings", O_TIMINGS, false),
]);

// --- OpenAI Responses (§18.6: OpenAI, xAI, OpenRouter) ---

const R_USAGE: T = T::Obj(&[
    M("input_tokens", T::U64, true),
    M("input_tokens_details", T::Or(&[T::Null, T::Obj(&[M("cached_tokens", T::U64, false)])]), false),
    M("output_tokens", T::U64, true),
    M("output_tokens_details", T::Or(&[T::Null, T::Obj(&[M("reasoning_tokens", T::U64, false)])]), false),
    M("total_tokens", T::U64, false),
    M("cost", T::Or(&[T::Null, T::Num]), false),
    M("is_byok", T::Bool, false),
    M("cost_in_usd_ticks", T::U64, false),
]);
const R_ERROR_OBJ: T = T::Obj(&[M("code", T::Or(&[T::Null, T::Ident(64)]), false), M("message", T::Text(64 << 10), true)]);
const R_OUT_TEXT: T = T::Obj(&[M("type", T::Lit("output_text"), true), M("text", T::Text(TEXT), true), M("annotations", T::EmptyArr, false)]);
const R_REFUSAL: T = T::Obj(&[M("type", T::Lit("refusal"), true), M("refusal", T::Text(TEXT), true)]);
const R_PART: T = T::Tag("type", &[("output_text", R_OUT_TEXT), ("refusal", R_REFUSAL)]);
const R_SUMMARY: T = T::Obj(&[M("type", T::Lit("summary_text"), true), M("text", T::Text(TEXT), true)]);
const R_REASONING_TEXT: T = T::Obj(&[M("type", T::Lit("reasoning_text"), true), M("text", T::Text(TEXT), true)]);

/// Output items. Hosted-tool items (`web_search_call`, `file_search_call`, `mcp_call`, …) are
/// absent: they fail the attempt.
const R_ITEM: T = T::Tag(
    "type",
    &[
        (
            "message",
            T::Obj(&[
                M("type", T::Lit("message"), true),
                M("id", T::Ident(ID), true),
                M("status", OPT_WORD, false),
                M("role", T::Lit("assistant"), true),
                M("content", T::Arr(&R_PART, 4096), true),
            ]),
        ),
        (
            "reasoning",
            T::Obj(&[
                M("type", T::Lit("reasoning"), true),
                M("id", T::Ident(ID), true),
                M("summary", T::Arr(&R_SUMMARY, 4096), true),
                M("content", T::Or(&[T::Null, T::Arr(&R_REASONING_TEXT, 4096)]), false),
                M("encrypted_content", T::Or(&[T::Null, T::Raw(RAW)]), false),
                M("status", OPT_WORD, false),
            ]),
        ),
        (
            "function_call",
            T::Obj(&[
                M("type", T::Lit("function_call"), true),
                M("id", T::Ident(ID), false),
                M("call_id", T::Ident(ID), true),
                M("name", T::Ident(128), true),
                M("arguments", T::Raw(RAW), true),
                M("status", OPT_WORD, false),
            ]),
        ),
        (
            "custom_tool_call",
            T::Obj(&[
                M("type", T::Lit("custom_tool_call"), true),
                M("id", T::Ident(ID), false),
                M("call_id", T::Ident(ID), true),
                M("name", T::Ident(128), true),
                M("input", T::Raw(RAW), true),
                M("status", OPT_WORD, false),
            ]),
        ),
    ],
);

/// The response object in streamed lifecycle events: no `output` (items reach the client only
/// through the gated `output_item` events, never a second, uninspected copy).
const R_RESPONSE_STREAM: T = T::Obj(&[
    M("id", T::Ident(ID), true),
    M("object", T::Lit("response"), true),
    M("created_at", T::Num, false),
    M("status", OPT_WORD, false),
    M("model", T::Ident(ID), false),
    M("usage", T::Or(&[T::Null, R_USAGE]), false),
    M("error", T::Or(&[T::Null, R_ERROR_OBJ]), false),
    M("incomplete_details", T::Or(&[T::Null, T::Obj(&[M("reason", T::Ident(64), false)])]), false),
]);

/// Non-streamed Responses body.
pub(crate) const RESPONSES_BODY: T = T::Obj(&[
    M("id", T::Ident(ID), true),
    M("object", T::Lit("response"), true),
    M("created_at", T::Num, false),
    M("status", OPT_WORD, false),
    M("model", T::Ident(ID), false),
    M("output", T::Arr(&R_ITEM, 4096), true),
    M("usage", T::Or(&[T::Null, R_USAGE]), false),
    M("error", T::Or(&[T::Null, R_ERROR_OBJ]), false),
    M("incomplete_details", T::Or(&[T::Null, T::Obj(&[M("reason", T::Ident(64), false)])]), false),
]);

const SEQ: M = M("sequence_number", T::U64, false);
const IID: M = M("item_id", T::Ident(ID), true);
const OIDX: M = M("output_index", T::U64, true);
const CIDX: M = M("content_index", T::U64, true);
const SIDX: M = M("summary_index", T::U64, true);

/// One Responses SSE event (tag = `type` = the `event:` name). Anything else fails closed.
pub(crate) const RESPONSES_EVENT: T = T::Tag(
    "type",
    &[
        ("response.created", T::Obj(&[M("type", T::Lit("response.created"), true), SEQ, M("response", R_RESPONSE_STREAM, true)])),
        ("response.in_progress", T::Obj(&[M("type", T::Lit("response.in_progress"), true), SEQ, M("response", R_RESPONSE_STREAM, true)])),
        ("response.completed", T::Obj(&[M("type", T::Lit("response.completed"), true), SEQ, M("response", R_RESPONSE_STREAM, true)])),
        ("response.incomplete", T::Obj(&[M("type", T::Lit("response.incomplete"), true), SEQ, M("response", R_RESPONSE_STREAM, true)])),
        ("response.failed", T::Obj(&[M("type", T::Lit("response.failed"), true), SEQ, M("response", R_RESPONSE_STREAM, true)])),
        ("response.output_item.added", T::Obj(&[M("type", T::Lit("response.output_item.added"), true), SEQ, OIDX, M("item", R_ITEM, true)])),
        ("response.output_item.done", T::Obj(&[M("type", T::Lit("response.output_item.done"), true), SEQ, OIDX, M("item", R_ITEM, true)])),
        ("response.content_part.added", T::Obj(&[M("type", T::Lit("response.content_part.added"), true), SEQ, IID, OIDX, CIDX, M("part", R_PART, true)])),
        ("response.content_part.done", T::Obj(&[M("type", T::Lit("response.content_part.done"), true), SEQ, IID, OIDX, CIDX, M("part", R_PART, true)])),
        ("response.output_text.delta", T::Obj(&[M("type", T::Lit("response.output_text.delta"), true), SEQ, IID, OIDX, CIDX, M("delta", T::Text(TEXT), true)])),
        ("response.output_text.done", T::Obj(&[M("type", T::Lit("response.output_text.done"), true), SEQ, IID, OIDX, CIDX, M("text", T::Text(TEXT), true)])),
        ("response.refusal.delta", T::Obj(&[M("type", T::Lit("response.refusal.delta"), true), SEQ, IID, OIDX, CIDX, M("delta", T::Text(TEXT), true)])),
        ("response.refusal.done", T::Obj(&[M("type", T::Lit("response.refusal.done"), true), SEQ, IID, OIDX, CIDX, M("refusal", T::Text(TEXT), true)])),
        (
            "response.function_call_arguments.delta",
            T::Obj(&[M("type", T::Lit("response.function_call_arguments.delta"), true), SEQ, IID, OIDX, M("delta", T::Raw(RAW), true)]),
        ),
        (
            "response.function_call_arguments.done",
            T::Obj(&[M("type", T::Lit("response.function_call_arguments.done"), true), SEQ, IID, OIDX, M("name", T::Ident(128), false), M("arguments", T::Raw(RAW), true)]),
        ),
        (
            "response.custom_tool_call_input.delta",
            T::Obj(&[M("type", T::Lit("response.custom_tool_call_input.delta"), true), SEQ, IID, OIDX, M("delta", T::Raw(RAW), true)]),
        ),
        (
            "response.custom_tool_call_input.done",
            T::Obj(&[M("type", T::Lit("response.custom_tool_call_input.done"), true), SEQ, IID, OIDX, M("input", T::Raw(RAW), true)]),
        ),
        (
            "response.reasoning_summary_part.added",
            T::Obj(&[M("type", T::Lit("response.reasoning_summary_part.added"), true), SEQ, IID, OIDX, SIDX, M("part", R_SUMMARY, true)]),
        ),
        (
            "response.reasoning_summary_part.done",
            T::Obj(&[M("type", T::Lit("response.reasoning_summary_part.done"), true), SEQ, IID, OIDX, SIDX, M("part", R_SUMMARY, true)]),
        ),
        (
            "response.reasoning_summary_text.delta",
            T::Obj(&[M("type", T::Lit("response.reasoning_summary_text.delta"), true), SEQ, IID, OIDX, SIDX, M("delta", T::Text(TEXT), true)]),
        ),
        (
            "response.reasoning_summary_text.done",
            T::Obj(&[M("type", T::Lit("response.reasoning_summary_text.done"), true), SEQ, IID, OIDX, SIDX, M("text", T::Text(TEXT), true)]),
        ),
        (
            "response.reasoning_text.delta",
            T::Obj(&[M("type", T::Lit("response.reasoning_text.delta"), true), SEQ, IID, OIDX, CIDX, M("delta", T::Text(TEXT), true)]),
        ),
        (
            "response.reasoning_text.done",
            T::Obj(&[M("type", T::Lit("response.reasoning_text.done"), true), SEQ, IID, OIDX, CIDX, M("text", T::Text(TEXT), true)]),
        ),
        (
            "error",
            T::Obj(&[
                M("type", T::Lit("error"), true),
                SEQ,
                M("code", T::Or(&[T::Null, T::Ident(64)]), false),
                M("message", T::Text(64 << 10), false),
                M("param", T::Or(&[T::Null, T::Text(1024)]), false),
                M("error", T::Or(&[T::Null, R_ERROR_OBJ]), false),
            ]),
        ),
    ],
);

// ---------------------------------------------------------------------------------------
// The re-emitter

/// Event-by-event canonical re-emission of one donor response (see module docs).
pub struct Reemitter {
    dialect: Dialect,
    stream: bool,
    line: Vec<u8>,
    data: Vec<u8>,
    event: Vec<u8>,
    has_data: bool,
    has_event: bool,
    tape: Vec<Node>,
    body: Vec<u8>,
    dropped: u64,
    events: u64,
    done: bool,
}

impl Reemitter {
    /// `stream` = SSE (else one JSON body, re-emitted at [`Reemitter::finish`]).
    pub fn new(dialect: Dialect, stream: bool) -> Self {
        Self {
            dialect,
            stream,
            line: Vec::new(),
            data: Vec::new(),
            event: Vec::new(),
            has_data: false,
            has_event: false,
            tape: Vec::new(),
            body: Vec::new(),
            dropped: 0,
            events: 0,
            done: false,
        }
    }

    /// Unknown optional members dropped so far (for logging/metrics).
    pub fn dropped_fields(&self) -> u64 {
        self.dropped
    }

    /// Canonical events written so far.
    pub fn events(&self) -> u64 {
        self.events
    }

    /// Feed decrypted donor bytes (any chunking); canonical bytes of every event completed by
    /// this chunk are appended to `out`. On an error `out` still holds exactly the complete
    /// canonical events before the refused one (none of it): deliver those, then fail the
    /// attempt and write nothing more. What the client gets never depends on chunking.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), ReemitError> {
        if self.done {
            return fail("bytes after the end of the response");
        }
        if !self.stream {
            if self.body.len().saturating_add(chunk.len()) > MAX_BODY {
                return fail("response body too large");
            }
            self.body.extend_from_slice(chunk);
            return Ok(());
        }
        let mut rest = chunk;
        while let Some(i) = rest.iter().position(|&b| b == b'\n') {
            let (part, tail) = rest.split_at(i);
            rest = tail.get(1..).unwrap_or_default();
            if self.line.is_empty() {
                self.on_line(part, out)?;
            } else {
                let mut carry = std::mem::take(&mut self.line);
                if carry.len().saturating_add(part.len()) > MAX_EVENT.saturating_add(16) {
                    return fail("SSE line too long");
                }
                carry.extend_from_slice(part);
                let r = self.on_line(&carry, out);
                carry.clear();
                self.line = carry;
                r?;
            }
        }
        if self.line.len().saturating_add(rest.len()) > MAX_EVENT.saturating_add(16) {
            return fail("SSE line too long");
        }
        self.line.extend_from_slice(rest);
        Ok(())
    }

    /// End of the response: a stream must end on an event boundary; a non-streamed body is
    /// validated and its canonical form appended to `out`.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), ReemitError> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        if self.stream {
            if !self.line.is_empty() || self.has_data || self.has_event {
                return fail("truncated SSE event");
            }
            return Ok(());
        }
        let body = std::mem::take(&mut self.body);
        let mut tape = std::mem::take(&mut self.tape);
        let doc = json::parse(&body, &mut tape).map_err(|_| ReemitError("response body is not strict JSON"))?;
        let root = doc.root();
        let schema = match self.dialect {
            Dialect::AnthropicMessages => &ANTHROPIC_BODY,
            Dialect::OpenAiChat if root.get("error").is_some() => &O_ERROR,
            Dialect::OpenAiChat => &OPENAI_BODY,
            Dialect::OpenAiResponses if root.get("object").is_none() && root.get("error").is_some() => &O_ERROR,
            Dialect::OpenAiResponses => &RESPONSES_BODY,
        };
        let mut w = W { out, dropped: 0 };
        let r = w.emit(schema, root);
        self.dropped = self.dropped.saturating_add(w.dropped);
        self.events = self.events.saturating_add(1);
        r
    }

    fn on_line(&mut self, line: &[u8], out: &mut Vec<u8>) -> Result<(), ReemitError> {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.contains(&b'\r') {
            return fail("CR-only line ending");
        }
        if line.is_empty() {
            return self.dispatch(out);
        }
        if line.first() == Some(&b':') {
            // Comment (OpenRouter keep-alives): dropped, never forwarded.
            self.dropped = self.dropped.saturating_add(1);
            return Ok(());
        }
        let (field, value) = match line.iter().position(|&b| b == b':') {
            Some(c) => {
                let (f, v) = line.split_at(c);
                let v = v.get(1..).unwrap_or_default();
                (f, v.strip_prefix(b" ").unwrap_or(v))
            }
            None => (line, &b""[..]),
        };
        match field {
            b"data" => {
                if self.has_data {
                    return fail("more than one data line in an event");
                }
                if value.len() > MAX_EVENT {
                    return fail("SSE event too large");
                }
                self.data.clear();
                self.data.extend_from_slice(value);
                self.has_data = true;
            }
            b"event" => {
                if self.has_event || self.dialect == Dialect::OpenAiChat {
                    return fail("unexpected event line");
                }
                if value.len() > 64 {
                    return fail("event name too long");
                }
                self.event.clear();
                self.event.extend_from_slice(value);
                self.has_event = true;
            }
            _ => return fail("unexpected SSE field (id, retry or unknown)"),
        }
        Ok(())
    }

    fn dispatch(&mut self, out: &mut Vec<u8>) -> Result<(), ReemitError> {
        if !self.has_data {
            if self.has_event {
                return fail("event without data");
            }
            return Ok(()); // blank line(s) between events
        }
        self.has_data = false;
        let has_event = std::mem::replace(&mut self.has_event, false);
        if self.dialect == Dialect::OpenAiChat && self.data.as_slice() == b"[DONE]" {
            out.extend_from_slice(b"data: [DONE]\n\n");
            self.events = self.events.saturating_add(1);
            return Ok(());
        }
        // Responses streams end with `response.completed`; a stray `[DONE]` is not forwarded.
        if self.dialect == Dialect::OpenAiResponses && self.data.as_slice() == b"[DONE]" && !has_event {
            self.dropped = self.dropped.saturating_add(1);
            return Ok(());
        }
        let mut tape = std::mem::take(&mut self.tape);
        let start = out.len();
        let r = (|| {
            let doc = json::parse(&self.data, &mut tape).map_err(|_| ReemitError("event is not strict JSON"))?;
            let root = doc.root();
            let mut w = W { out: &mut *out, dropped: 0 };
            match self.dialect {
                Dialect::AnthropicMessages | Dialect::OpenAiResponses => {
                    let ty = root.get("type").and_then(Val::as_str).ok_or(ReemitError("event without a type"))?;
                    if has_event && self.event.as_slice() != ty.as_bytes() {
                        return fail("event name does not match the data type");
                    }
                    if !ident_ok(&ty, 64) {
                        return fail("bad event type");
                    }
                    w.out.extend_from_slice(b"event: ");
                    w.out.extend_from_slice(ty.as_bytes());
                    w.out.extend_from_slice(b"\ndata: ");
                    w.emit(if self.dialect == Dialect::AnthropicMessages { &ANTHROPIC_EVENT } else { &RESPONSES_EVENT }, root)?;
                }
                Dialect::OpenAiChat => {
                    w.out.extend_from_slice(b"data: ");
                    let schema = if root.get("error").is_some() { &O_ERROR } else { &OPENAI_CHUNK };
                    w.emit(schema, root)?;
                }
            }
            w.out.extend_from_slice(b"\n\n");
            Ok(w.dropped)
        })();
        self.tape = tape;
        match r {
            Ok(d) => {
                self.dropped = self.dropped.saturating_add(d);
                self.events = self.events.saturating_add(1);
                Ok(())
            }
            Err(e) => {
                out.truncate(start);
                Err(e)
            }
        }
    }
}

/// Every human-visible text field ([`T::Text`]) that the re-emitter writes for one parsed
/// stream event (`stream`, the JSON of its `data:` line) or whole body, in order and cleaned
/// as the client will see it. This is what the tripwire must scan (A216): it walks the
/// re-emission allowlists themselves, so every text-bearing field the client can receive is
/// covered, with no raw-byte prefilter. Fields the re-emitter would refuse are skipped (the
/// event fails re-emission anyway); opaque fields (signatures, tool arguments) are not text.
pub fn visible_texts(dialect: Dialect, stream: bool, root: Val<'_>, f: &mut dyn FnMut(&str)) {
    let schema = match (dialect, stream) {
        (Dialect::AnthropicMessages, true) => &ANTHROPIC_EVENT,
        (Dialect::AnthropicMessages, false) => &ANTHROPIC_BODY,
        (Dialect::OpenAiChat, _) if root.get("error").is_some() => &O_ERROR,
        (Dialect::OpenAiChat, true) => &OPENAI_CHUNK,
        (Dialect::OpenAiChat, false) => &OPENAI_BODY,
        (Dialect::OpenAiResponses, true) => &RESPONSES_EVENT,
        (Dialect::OpenAiResponses, false) if root.get("object").is_none() && root.get("error").is_some() => &O_ERROR,
        (Dialect::OpenAiResponses, false) => &RESPONSES_BODY,
    };
    visit(schema, root, f);
}

fn visit(t: &T, v: Val<'_>, f: &mut dyn FnMut(&str)) {
    match t {
        T::Text(_) => {
            if let Some(s) = v.as_str() {
                f(&clean_text(&s));
            }
        }
        T::Or(alts) => {
            if let Some(a) = alts.iter().find(|a| kind_of(a).is_none_or(|k| k == v.kind())) {
                visit(a, v, f);
            }
        }
        T::Arr(item, _) => {
            if v.kind() == Kind::Arr {
                for it in v.items() {
                    visit(item, it, f);
                }
            }
        }
        T::Obj(members) => {
            if v.kind() == Kind::Obj {
                for m in *members {
                    if let Some(x) = v.get(m.0) {
                        visit(&m.1, x, f);
                    }
                }
            }
        }
        T::Tag(key, cases) => {
            if v.kind() == Kind::Obj
                && let Some(tag) = v.get(key)
                && let Some((_, case)) = cases.iter().find(|(name, _)| tag.is_str(name))
            {
                visit(case, v, f);
            }
        }
        T::Raw(_) | T::Ident(_) | T::Lit(_) | T::U64 | T::Zero | T::Num | T::Bool | T::Null | T::AnyObj(_) | T::EmptyObj | T::EmptyArr => {}
    }
}

/// One-shot re-emission of a whole response (tests, non-streamed bodies).
pub fn reemit(dialect: Dialect, stream: bool, input: &[u8]) -> Result<Vec<u8>, ReemitError> {
    let mut r = Reemitter::new(dialect, stream);
    let mut out = Vec::with_capacity(input.len());
    r.push(input, &mut out)?;
    r.finish(&mut out)?;
    Ok(out)
}
