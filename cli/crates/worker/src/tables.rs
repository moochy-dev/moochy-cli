//! Firewall allowlists as data (plan 06 §7). Anything not listed is rejected.
//! Widening an allowlist needs two-person review (06 §7.3): keep diffs here small.

use crate::{Flags, Provider};
use crate::firewall::{F, Hook, R};

// --- Anthropic Messages (06 §7.1) ------------------------------------------------------

pub(crate) const ANTHROPIC_VERSIONS: &[&str] = &["2023-06-01"];
pub(crate) const ANTHROPIC_VERSION_DEFAULT: &str = "2023-06-01";

/// `anthropic-beta` values that only change plain inference; gated ones need the flag.
/// Absent on purpose: files, code execution, MCP client, web fetch/search, skills,
/// context management, OAuth (they touch account data, run code, or bill extra).
pub(crate) const ANTHROPIC_BETAS: &[(&str, Flags)] = &[
    ("prompt-caching-2024-07-31", Flags::NONE),
    ("extended-cache-ttl-2025-04-11", Flags::NONE),
    ("interleaved-thinking-2025-05-14", Flags::NONE),
    ("fine-grained-tool-streaming-2025-05-14", Flags::NONE),
    ("token-efficient-tools-2025-02-19", Flags::NONE),
    ("output-128k-2025-02-19", Flags::NONE),
    ("claude-code-20250219", Flags::NONE),
    ("computer-use-2024-10-22", Flags::NONE),
    ("computer-use-2025-01-24", Flags::NONE),
    ("computer-use-2025-11-24", Flags::NONE),
    ("structured-outputs-2025-11-13", Flags::NONE),
    ("effort-2025-11-24", Flags::NONE),
    // Observed in Claude Code 2.1.287 traffic (tests/fixtures/clients); they enable exactly the
    // allowlisted plain-inference features above. [review: allowlist widening, 06 §7.3]
    ("context-management-2025-06-27", Flags::NONE),
    ("mid-conversation-system-2026-04-07", Flags::NONE),
    ("per-turn-control-2026-07-01", Flags::NONE),
    ("context-1m-2025-08-07", Flags::LONG_CONTEXT),
];

const CACHE_CONTROL: R = R::Hook(
    Hook::CacheControl,
    &R::Obj(&[F("type", R::Enum(&["ephemeral"]), true), F("ttl", R::Enum(&["5m", "1h"]), false)]),
);
const CC: F = F("cache_control", CACHE_CONTROL, false);

const TEXT_BLOCK: R = R::Obj(&[F("text", R::Str, true), CC]);

const IMAGE_BLOCK: R = R::Hook(
    Hook::Image,
    &R::Obj(&[
        F(
            "source",
            R::Tagged {
                key: "type",
                cases: &[
                    (
                        "base64",
                        R::Obj(&[
                            F("media_type", R::Enum(&["image/jpeg", "image/png", "image/gif", "image/webp"]), true),
                            F("data", R::Hook(Hook::B64, &R::Str), true),
                        ]),
                    ),
                    ("url", R::Deny("URL sources make the provider fetch URLs")),
                    ("file", R::Deny("file-id sources read the donor's file store")),
                ],
            },
            true,
        ),
        CC,
    ]),
);

const DOCUMENT_BLOCK: R = R::Hook(
    Hook::Document,
    &R::Obj(&[
        F(
            "source",
            R::Tagged {
                key: "type",
                cases: &[
                    ("text", R::Obj(&[F("media_type", R::Enum(&["text/plain"]), true), F("data", R::Str, true)])),
                    (
                        "content",
                        R::Obj(&[F(
                            "content",
                            R::OneOf(&[R::Str, R::Arr(&R::Tagged { key: "type", cases: &[("text", TEXT_BLOCK)] })]),
                            true,
                        )]),
                    ),
                    // R3: PDFs need the `documents` flag (Document hook) and ≤ 100 pages in total.
                    ("base64", R::Obj(&[F("media_type", R::Enum(&["application/pdf"]), true), F("data", R::Hook(Hook::Pdf, &R::Str), true)])),
                    ("url", R::Deny("URL sources make the provider fetch URLs")),
                    ("file", R::Deny("file-id sources read the donor's file store")),
                ],
            },
            true,
        ),
        F("title", R::Str, false),
        F("context", R::Str, false),
        F("citations", R::Obj(&[F("enabled", R::Bool, true)]), false),
        CC,
    ]),
);

const SERVER_BLOCK: R = R::Deny("server-side tool blocks run on the donor's account");

/// Blocks allowed inside `tool_result.content` (nested recursion: same rules as top level).
const TOOL_RESULT_CONTENT: R = R::OneOf(&[
    R::Str,
    R::Arr(&R::Tagged { key: "type", cases: &[("text", TEXT_BLOCK), ("image", IMAGE_BLOCK), ("document", DOCUMENT_BLOCK)] }),
]);

const CONTENT_BLOCK: R = R::Tagged {
    key: "type",
    cases: &[
        ("text", TEXT_BLOCK),
        ("image", IMAGE_BLOCK),
        ("document", DOCUMENT_BLOCK),
        ("tool_use", R::Obj(&[F("id", R::Str, true), F("name", R::Str, true), F("input", R::Any, true), CC])),
        (
            "tool_result",
            R::Obj(&[
                F("tool_use_id", R::Str, true),
                F("content", TOOL_RESULT_CONTENT, false),
                F("is_error", R::Bool, false),
                CC,
            ]),
        ),
        ("thinking", R::Obj(&[F("thinking", R::Str, true), F("signature", R::Str, false)])),
        ("redacted_thinking", R::Obj(&[F("data", R::Str, true)])),
        ("server_tool_use", SERVER_BLOCK),
        ("web_search_tool_result", SERVER_BLOCK),
        ("web_fetch_tool_result", SERVER_BLOCK),
        ("code_execution_tool_result", SERVER_BLOCK),
        ("bash_code_execution_tool_result", SERVER_BLOCK),
        ("text_editor_code_execution_tool_result", SERVER_BLOCK),
        ("tool_search_tool_result", SERVER_BLOCK),
        ("mcp_tool_use", R::Deny("MCP blocks make the provider call arbitrary servers")),
        ("mcp_tool_result", R::Deny("MCP blocks make the provider call arbitrary servers")),
        ("container_upload", R::Deny("containers are server-side execution environments")),
    ],
};

/// Conversation turns. `system` turns (Claude Code's mid-conversation reminders, beta
/// `mid-conversation-system-*`) are text only. [review: allowlist widening, 06 §7.3]
const MESSAGE: R = R::Tagged {
    key: "role",
    cases: &[
        ("user", R::Obj(&[F("content", R::OneOf(&[R::Str, R::Arr(&CONTENT_BLOCK)]), true)])),
        ("assistant", R::Obj(&[F("content", R::OneOf(&[R::Str, R::Arr(&CONTENT_BLOCK)]), true)])),
        (
            "system",
            R::Obj(&[
                F("content", R::OneOf(&[R::Str, R::Arr(&R::Tagged { key: "type", cases: &[("text", TEXT_BLOCK)] })]), true),
                // Per-turn effort (beta `per-turn-control-*`): the effective effort is the max.
                F("output_config", R::Obj(&[F("effort", R::Hook(Hook::TurnEffort, &R::Enum(&["low", "medium", "high", "xhigh", "max"])), false)]), false),
            ]),
        ),
    ],
};

/// `context_management`: only edits that *remove* old content server-side (thinking blocks,
/// tool uses); no execution, no account data, lower cost. [review: allowlist widening, 06 §7.3]
const CONTEXT_EDIT: R = R::Tagged {
    key: "type",
    cases: &[
        ("clear_thinking_*", R::Obj(&[F("keep", R::Any, false)])),
        (
            "clear_tool_uses_*",
            R::Obj(&[
                F("trigger", R::Any, false),
                F("keep", R::Any, false),
                F("clear_at_least", R::Any, false),
                F("exclude_tools", R::Arr(&R::Str), false),
                F("clear_tool_inputs", R::Any, false),
            ]),
        ),
    ],
};

const CUSTOM_TOOL: R = R::Obj(&[
    F("name", R::Str, true),
    F("description", R::Str, false),
    F("input_schema", R::Any, true),
    F("strict", R::Bool, false),
    CC,
]);

const SERVER_TOOL: R = R::Deny("server-executed tools run or bill on the donor's account");

/// Custom tools and Anthropic-defined *client-executed* tools only.
const TOOL: R = R::Tagged {
    key: "type",
    cases: &[
        ("", CUSTOM_TOOL),
        ("custom", CUSTOM_TOOL),
        ("bash_*", R::Obj(&[F("name", R::Enum(&["bash"]), true), CC])),
        (
            "text_editor_*",
            R::Obj(&[
                F("name", R::Enum(&["str_replace_editor", "str_replace_based_edit_tool"]), true),
                F("max_characters", R::UInt, false),
                CC,
            ]),
        ),
        ("memory_*", R::Obj(&[F("name", R::Enum(&["memory"]), true), CC])),
        (
            "computer_*",
            R::Obj(&[
                F("name", R::Enum(&["computer"]), true),
                F("display_width_px", R::UInt, true),
                F("display_height_px", R::UInt, true),
                F("display_number", R::UInt, false),
                F("enable_zoom", R::Bool, false),
                CC,
            ]),
        ),
        ("web_search_*", SERVER_TOOL),
        ("web_fetch_*", SERVER_TOOL),
        ("code_execution_*", SERVER_TOOL),
        ("tool_search_tool_*", SERVER_TOOL),
        ("mcp_toolset", R::Deny("MCP toolsets make the provider call arbitrary servers")),
    ],
};

const PARALLEL: F = F("disable_parallel_tool_use", R::Bool, false);

pub(crate) static ANTHROPIC: R = R::Obj(&[
    F("model", R::Str, true),
    F("messages", R::Arr(&MESSAGE), true),
    F("max_tokens", R::UInt, true),
    F("system", R::OneOf(&[R::Str, R::Arr(&R::Tagged { key: "type", cases: &[("text", TEXT_BLOCK)] })]), false),
    F("metadata", R::Obj(&[F("user_id", R::Str, false)]), false),
    F("stop_sequences", R::Arr(&R::Str), false),
    F("stream", R::Bool, false),
    F("temperature", R::Num, false),
    F("top_p", R::Num, false),
    F("top_k", R::UInt, false),
    F("tools", R::Arr(&TOOL), false),
    F(
        "tool_choice",
        R::Tagged {
            key: "type",
            cases: &[
                ("auto", R::Obj(&[PARALLEL])),
                ("any", R::Obj(&[PARALLEL])),
                ("none", R::Obj(&[])),
                ("tool", R::Obj(&[F("name", R::Str, true), PARALLEL])),
            ],
        },
        false,
    ),
    F(
        "thinking",
        R::Tagged {
            key: "type",
            cases: &[
                ("enabled", R::Obj(&[F("budget_tokens", R::UInt, true), F("display", R::Enum(&["summarized", "omitted"]), false)])),
                ("adaptive", R::Obj(&[F("display", R::Enum(&["summarized", "omitted"]), false)])),
                ("disabled", R::Obj(&[])),
            ],
        },
        false,
    ),
    F(
        "output_config",
        R::Obj(&[
            F("effort", R::Enum(&["low", "medium", "high", "xhigh", "max"]), false),
            F("format", R::Tagged { key: "type", cases: &[("json_schema", R::Obj(&[F("schema", R::Any, true)]))] }, false),
        ]),
        false,
    ),
    CC,
    F("speed", R::Hook(Hook::Speed, &R::Enum(&["standard", "fast"])), false),
    F("service_tier", R::Hook(Hook::ServiceTier, &R::Enum(&["auto", "standard_only"])), false),
    F("inference_geo", R::Hook(Hook::InferenceGeo, &R::Str), false),
    F("mcp_servers", R::Deny("the provider would connect to arbitrary servers on the donor's behalf"), false),
    F("container", R::Deny("containers are server-side execution environments"), false),
    F("context_management", R::Obj(&[F("edits", R::Arr(&CONTEXT_EDIT), false)]), false),
    F(
        "safeguards",
        R::Deny("server-side safety classifiers are extra billed model calls on the donor's account and carry the maintainer's local paths (the Gateway strips them)"),
        false,
    ),
    F("provider", R::Deny("upstream routing is set by the Worker"), false),
    F("models", R::Deny("fallback model lists would bill models outside the pledge"), false),
]);

// --- OpenAI chat completions (06 §7.2): OpenAI, OpenRouter, DeepSeek -------------------

const OAI_CC: F = F("cache_control", CACHE_CONTROL, false);
const OAI_TEXT: R = R::Obj(&[F("text", R::Str, true), OAI_CC]);
const OAI_TEXT_PARTS: R = R::OneOf(&[R::Str, R::Arr(&R::Tagged { key: "type", cases: &[("text", OAI_TEXT)] })]);

const OAI_USER_PART: R = R::Tagged {
    key: "type",
    cases: &[
        ("text", OAI_TEXT),
        (
            "image_url",
            R::Hook(
                Hook::Image,
                &R::Obj(&[F(
                    "image_url",
                    R::Obj(&[F("url", R::Hook(Hook::DataUrl, &R::Str), true), F("detail", R::Enum(&["auto", "low", "high"]), false)]),
                    true,
                )]),
            ),
        ),
        ("input_audio", R::Deny("audio input is not allowed")),
        ("file", R::Deny("file inputs read the donor's file store")),
    ],
};

const OAI_TOOL_CALL: R = R::Tagged {
    key: "type",
    cases: &[(
        "function",
        R::Obj(&[F("id", R::Str, true), F("function", R::Obj(&[F("name", R::Str, true), F("arguments", R::Str, true)]), true)]),
    )],
};

const OAI_SYSTEM: R = R::Obj(&[F("content", OAI_TEXT_PARTS, true), F("name", R::Str, false)]);

const OAI_MESSAGE: R = R::Tagged {
    key: "role",
    cases: &[
        ("system", OAI_SYSTEM),
        ("developer", OAI_SYSTEM),
        ("user", R::Obj(&[F("content", R::OneOf(&[R::Str, R::Arr(&OAI_USER_PART)]), true), F("name", R::Str, false)])),
        (
            "assistant",
            R::Obj(&[
                F(
                    "content",
                    R::OneOf(&[
                        R::Null,
                        R::Str,
                        R::Arr(&R::Tagged { key: "type", cases: &[("text", OAI_TEXT), ("refusal", R::Obj(&[F("refusal", R::Str, true)]))] }),
                    ]),
                    false,
                ),
                F("name", R::Str, false),
                F("tool_calls", R::Arr(&OAI_TOOL_CALL), false),
                F("refusal", R::OneOf(&[R::Null, R::Str]), false),
                F("audio", R::Deny("audio is not allowed"), false),
                F("function_call", R::Deny("legacy function calls are not allowed"), false),
            ]),
        ),
        ("tool", R::Obj(&[F("tool_call_id", R::Str, true), F("content", OAI_TEXT_PARTS, true)])),
        ("function", R::Deny("legacy function messages are not allowed")),
    ],
};

const HOSTED_TOOL: R = R::Deny("hosted tools run or bill on the donor's account");

const OAI_TOOL: R = R::Tagged {
    key: "type",
    cases: &[
        (
            "function",
            R::Obj(&[F(
                "function",
                R::Obj(&[F("name", R::Str, true), F("description", R::Str, false), F("parameters", R::Any, false), F("strict", R::Bool, false)]),
                true,
            )]),
        ),
        ("web_search", HOSTED_TOOL),
        ("web_search_preview", HOSTED_TOOL),
        ("file_search", HOSTED_TOOL),
        ("code_interpreter", HOSTED_TOOL),
        ("computer_use_preview", HOSTED_TOOL),
        ("image_generation", HOSTED_TOOL),
        ("mcp", R::Deny("MCP tools make the provider call arbitrary servers")),
    ],
};

pub(crate) static OPENAI: R = R::Obj(&[
    F("model", R::Str, true),
    F("messages", R::Arr(&OAI_MESSAGE), true),
    F("max_tokens", R::UInt, false),
    F("max_completion_tokens", R::UInt, false),
    F("temperature", R::Num, false),
    F("top_p", R::Num, false),
    F("frequency_penalty", R::Num, false),
    F("presence_penalty", R::Num, false),
    F("stop", R::OneOf(&[R::Null, R::Str, R::Arr(&R::Str)]), false),
    F("stream", R::Bool, false),
    F("stream_options", R::Obj(&[F("include_usage", R::Bool, false)]), false),
    F("seed", R::Num, false),
    F("tools", R::Arr(&OAI_TOOL), false),
    F(
        "tool_choice",
        R::OneOf(&[
            R::Enum(&["none", "auto", "required"]),
            R::Tagged { key: "type", cases: &[("function", R::Obj(&[F("function", R::Obj(&[F("name", R::Str, true)]), true)]))] },
        ]),
        false,
    ),
    F("parallel_tool_calls", R::Bool, false),
    F(
        "response_format",
        R::Tagged {
            key: "type",
            cases: &[
                ("text", R::Obj(&[])),
                ("json_object", R::Obj(&[])),
                (
                    "json_schema",
                    R::Obj(&[F(
                        "json_schema",
                        R::Obj(&[F("name", R::Str, true), F("description", R::Str, false), F("schema", R::Any, false), F("strict", R::Bool, false)]),
                        true,
                    )]),
                ),
            ],
        },
        false,
    ),
    F("reasoning_effort", R::Enum(&["none", "minimal", "low", "medium", "high", "xhigh"]), false),
    F("verbosity", R::Enum(&["low", "medium", "high"]), false),
    F("user", R::Str, false),
    F("safety_identifier", R::Str, false),
    F("prompt_cache_key", R::Str, false),
    F("store", R::Bool, false),
    F("n", R::Hook(Hook::One, &R::UInt), false),
    F("logprobs", R::Bool, false),
    F("top_logprobs", R::UInt, false),
    F("logit_bias", R::Any, false),
    F("modalities", R::Arr(&R::Enum(&["text"])), false),
    F("audio", R::Deny("audio output is not allowed"), false),
    F("prediction", R::Deny("predicted outputs are billed as output"), false),
    F("service_tier", R::Deny("the service tier is the donor's call"), false),
    F("web_search_options", R::Deny("web search runs on the donor's account"), false),
    F("search_parameters", R::Deny("live search is billed per source on the donor's account"), false),
    F("deferred", R::Deny("deferred completions are stored and fetched later"), false),
    F("metadata", R::Deny("stored-completion metadata is not allowed"), false),
    F("functions", R::Deny("legacy functions are not allowed"), false),
    F("function_call", R::Deny("legacy functions are not allowed"), false),
    F("models", R::Deny("fallback model lists would bill models outside the pledge"), false),
    F("route", R::Deny("fallback routing would bill models outside the pledge"), false),
    F("plugins", R::Deny("plugins (web search, file parsing) bill extra on the donor's account"), false),
    F("provider", R::Deny("upstream routing is set by the Worker"), false),
    F("transforms", R::Deny("prompt transforms are not in the allowlist"), false),
    F("usage", R::Deny("usage reporting is set by the Worker"), false),
    F("reasoning", R::Deny("use `reasoning_effort`"), false),
]);

/// Per-provider top-level denies on top of the dialect table (fail closed on fields the
/// provider does not document; its paid add-ons are already unknown to the table:
/// `search_parameters`, `web_search_options`, `deferred`, server-side tools).
pub(crate) fn provider_denies(p: Provider) -> &'static [(&'static str, &'static str)] {
    match p {
        Provider::XAi => &[
            ("store", "not part of the xAI chat completions API"),
            ("modalities", "not part of the xAI chat completions API"),
            ("verbosity", "not part of the xAI chat completions API"),
            ("logit_bias", "unsupported by xAI"),
        ],
        Provider::Local => &[
            ("store", "not part of a local inference server's API"),
            ("modalities", "not part of a local inference server's API"),
            ("verbosity", "not part of a local inference server's API"),
        ],
        _ => &[],
    }
}

/// Top-level members the Gateway strips before sealing (see `firewall::pool_compatible`): a
/// pooled donor would refuse them, and the client keeps working without them.
pub(crate) const POOL_STRIP: &[&str] = &["safeguards"];
