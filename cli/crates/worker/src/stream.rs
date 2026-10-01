//! Incremental provider response parser (plan 05 §3, 03 §12.3, 06 §8).
//!
//! Feed it every chunk exactly as received; the chunk bytes themselves are never copied
//! or altered (the node seals and forwards them as-is, flushing per chunk). The parser
//! splits SSE events, strict-parses each event's JSON into a reused tape, and reports:
//! - usage (with cache fields, DeepSeek hit/miss, OpenRouter `usage.cost`), reported
//!   model and response id;
//! - tool-call block boundaries (Anthropic `tool_use`, OpenAI `tool_calls` by index), so
//!   the Worker can sign a progress checkpoint after any chunk that closed a block, and the
//!   Gateway can hold tool-call events until their end;
//! - forbidden server-side blocks and provider error events.
//!
//! After warm-up (buffers at their high-water mark) a chunk costs no heap allocation,
//! except for the one-time copies of the model and id strings.

use crate::Dialect;
use crate::json::{self, Kind, Node, Val};

/// Largest single SSE event (one `data:` payload).
pub const MAX_EVENT: usize = 4 << 20;
/// Largest non-streamed JSON response body.
pub const MAX_JSON_BODY: usize = 32 << 20;

/// Usage in receipt terms (05 §3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub cache_write_5m: u64,
    pub cache_write_1h: u64,
    pub cache_read: u64,
    /// Final usage was not seen (stream cut, cancelled, unparsable): settle pessimistically.
    pub estimated: bool,
    /// Provider-charged cost in µ$, rounded up (OpenRouter `usage.cost`).
    pub provider_cost_uusd: Option<u64>,
}

/// Byte range of one SSE event in the response stream (absolute offsets). Spans are
/// contiguous: every byte up to the last blank line belongs to exactly one span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    pub end: u64,
}

/// What one SSE event means. An event may produce several items (OpenAI chunks can end
/// one tool call and start the next); all items of one event share its [`Span`].
#[derive(Clone, Copy)]
pub enum Event<'a> {
    /// Text, thinking, pings, comments, metadata: forward immediately.
    Other,
    ToolStart { index: u32, id: Option<Val<'a>>, name: Option<Val<'a>> },
    /// A fragment of the tool input JSON (a JSON string value; decode with `as_str`).
    ToolArgs { index: u32, json: Val<'a> },
    ToolEnd { index: u32 },
    /// A block type the firewall forbids (`server_tool_use`, `mcp_tool_use`, server tool results).
    Forbidden { block_type: Val<'a> },
    /// Provider error event mid-stream.
    Error,
    /// End of message (`message_stop` / `[DONE]`).
    Stop,
    /// An event this parser cannot fully account for (unparsable or duplicate-key JSON,
    /// stray `\r`, BOM, tool input outside the delta stream, deltas for closed or unknown
    /// tool blocks, extra choices, unindexed or reopened tool calls). **Fail closed:** the
    /// Gateway must not forward it and should fail the task; usage becomes estimated.
    Invalid,
}

/// Most tool-call blocks open at once (bounds the per-stream index set).
const MAX_OPEN_TOOLS: usize = 64;

/// Per-chunk summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chunk {
    /// Tool-call blocks that ended inside this chunk: sign a progress checkpoint after it.
    pub tool_ends: u32,
    /// Complete SSE events in this chunk.
    pub events: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamError {
    EventTooLarge,
    BodyTooLarge,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EventTooLarge => "provider SSE event exceeds 4 MiB",
            Self::BodyTooLarge => "provider response exceeds 32 MiB",
        })
    }
}

impl std::error::Error for StreamError {}

/// Snapshot of what the response said so far (call [`StreamParser::finish`] at the end,
/// or at any time when the stream is cut).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub usage: Usage,
    /// `model_reported` (03 §12.1).
    pub model: Option<String>,
    /// Provider message/response id (fallback provider request id).
    pub id: Option<String>,
    /// The end-of-message marker was seen.
    pub complete: bool,
    pub provider_error: bool,
    /// A forbidden block type appeared (06 §8 structural check).
    pub forbidden: bool,
    /// At least one [`Event::Invalid`] was emitted.
    pub malformed: bool,
    /// Offset of the first byte not covered by any span (unterminated tail).
    pub tail: u64,
}

#[derive(Clone, Copy, Default)]
struct AnthUsage {
    input: Option<u64>,
    output: Option<u64>,
    cc_total: Option<u64>,
    cc_5m: Option<u64>,
    cc_1h: Option<u64>,
    cache_read: Option<u64>,
}

impl AnthUsage {
    /// Overlay the fields present in `u` (message_delta counts are cumulative).
    fn overlay(&mut self, u: Val<'_>) {
        let g = |k: &str| u.get(k).and_then(Val::as_u64);
        let cc = u.get("cache_creation");
        let gc = |k: &str| cc.and_then(|c| c.get(k)).and_then(Val::as_u64);
        self.input = g("input_tokens").or(self.input);
        self.output = g("output_tokens").or(self.output);
        self.cc_total = g("cache_creation_input_tokens").or(self.cc_total);
        self.cache_read = g("cache_read_input_tokens").or(self.cache_read);
        self.cc_5m = gc("ephemeral_5m_input_tokens").or(self.cc_5m);
        self.cc_1h = gc("ephemeral_1h_input_tokens").or(self.cc_1h);
    }

    fn add(&mut self, o: &Self) {
        let s = |a: Option<u64>, b: Option<u64>| match (a, b) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
        };
        self.input = s(self.input, o.input);
        self.output = s(self.output, o.output);
        self.cc_total = s(self.cc_total, o.cc_total);
        self.cc_5m = s(self.cc_5m, o.cc_5m);
        self.cc_1h = s(self.cc_1h, o.cc_1h);
        self.cache_read = s(self.cache_read, o.cache_read);
    }
}

#[derive(Default)]
struct State {
    model: Option<String>,
    id: Option<String>,
    anth: AnthUsage,
    /// Sum over `usage.iterations` (server-side iterations such as compaction).
    iterations: Option<AnthUsage>,
    /// OpenAI-style final usage.
    oa: Option<Usage>,
    /// Anthropic: `usage.cost` if a compatible endpoint reports it.
    anth_cost: Option<u64>,
    final_usage: bool,
    open_tools: Vec<u32>,
    oa_open: Option<u32>,
    done: bool,
    error: bool,
    forbidden: bool,
    malformed: bool,
    tainted: bool,
    out_bytes: u64,
    /// OpenAI: highest tool-call index started (indices only move forward).
    oa_last: Option<u32>,
}

fn invalid(st: &mut State, span: Span, sink: &mut dyn FnMut(Span, Event<'_>)) {
    st.malformed = true;
    st.tainted = true;
    sink(span, Event::Invalid);
}

pub struct StreamParser {
    dialect: Dialect,
    stream: bool,
    line: Vec<u8>,
    data: Vec<u8>,
    has_data: bool,
    /// The current event contained a line we refuse to interpret.
    bad_line: bool,
    tape: Vec<Node>,
    pos: u64,
    ev_start: u64,
    parsed_body: bool,
    st: State,
}

fn u32_of(v: Option<Val<'_>>) -> Option<u32> {
    v.and_then(Val::as_u64).and_then(|n| u32::try_from(n).ok())
}

fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl StreamParser {
    /// `stream` = the request's `stream` flag (SSE) or a single JSON body.
    pub fn new(dialect: Dialect, stream: bool) -> Self {
        Self {
            dialect,
            stream,
            line: Vec::new(),
            data: Vec::new(),
            has_data: false,
            bad_line: false,
            tape: Vec::new(),
            pos: 0,
            ev_start: 0,
            parsed_body: false,
            st: State::default(),
        }
    }

    /// Feed one chunk. `sink` receives every event's span and meaning (pass `|_, _| {}` if
    /// you only need the summary). An error means the response is out of bounds: abort it.
    pub fn feed(&mut self, chunk: &[u8], sink: &mut dyn FnMut(Span, Event<'_>)) -> Result<Chunk, StreamError> {
        let mut out = Chunk::default();
        if !self.stream {
            if self.data.len().saturating_add(chunk.len()) > MAX_JSON_BODY {
                return Err(StreamError::BodyTooLarge);
            }
            self.data.extend_from_slice(chunk);
            self.pos = self.pos.saturating_add(len64(chunk.len()));
            return Ok(out);
        }
        let mut rest = chunk;
        while !rest.is_empty() {
            let Some(i) = rest.iter().position(|&b| b == b'\n') else {
                if self.line.len().saturating_add(rest.len()) > MAX_EVENT {
                    return Err(StreamError::EventTooLarge);
                }
                self.line.extend_from_slice(rest);
                self.pos = self.pos.saturating_add(len64(rest.len()));
                break;
            };
            let (part, tail) = rest.split_at(i);
            rest = tail.get(1..).unwrap_or_default();
            self.pos = self.pos.saturating_add(len64(i.saturating_add(1)));
            if self.line.is_empty() {
                self.on_line(part, sink, &mut out)?;
            } else {
                let mut carry = std::mem::take(&mut self.line);
                carry.extend_from_slice(part);
                let r = self.on_line(&carry, sink, &mut out);
                carry.clear();
                self.line = carry;
                r?;
            }
        }
        Ok(out)
    }

    fn on_line(&mut self, line: &[u8], sink: &mut dyn FnMut(Span, Event<'_>), out: &mut Chunk) -> Result<(), StreamError> {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            let span = Span { start: self.ev_start, end: self.pos };
            self.ev_start = self.pos;
            out.events = out.events.saturating_add(1);
            if std::mem::replace(&mut self.bad_line, false) {
                self.has_data = false;
                self.data.clear();
                invalid(&mut self.st, span, sink);
            } else if self.has_data {
                self.has_data = false;
                self.dispatch(span, sink, out);
                self.data.clear();
            } else {
                sink(span, Event::Other);
            }
            return Ok(());
        }
        // The SSE spec also ends lines at a lone CR and strips a BOM; providers never send
        // either, so instead of a second line-splitting rule we refuse them (no differential).
        if line.contains(&b'\r') || line.starts_with(b"\xEF\xBB\xBF") {
            self.bad_line = true;
            return Ok(());
        }
        if line.first() == Some(&b':') {
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
        if field == b"data" {
            if self.data.len().saturating_add(value.len()).saturating_add(1) > MAX_EVENT {
                return Err(StreamError::EventTooLarge);
            }
            if self.has_data {
                self.data.push(b'\n');
            }
            self.data.extend_from_slice(value);
            self.has_data = true;
        }
        Ok(())
    }

    fn dispatch(&mut self, span: Span, sink: &mut dyn FnMut(Span, Event<'_>), out: &mut Chunk) {
        if self.dialect == Dialect::OpenAiChat && self.data.as_slice() == b"[DONE]" {
            self.st.done = true;
            sink(span, Event::Stop);
            return;
        }
        let mut tape = std::mem::take(&mut self.tape);
        let data_len = len64(self.data.len());
        match json::parse(&self.data, &mut tape) {
            Ok(doc) => {
                let ends = match self.dialect {
                    Dialect::AnthropicMessages => anthropic_event(&mut self.st, doc.root(), data_len, span, sink),
                    Dialect::OpenAiChat => openai_chunk(&mut self.st, doc.root(), data_len, span, sink),
                };
                out.tool_ends = out.tool_ends.saturating_add(ends);
            }
            Err(_) => invalid(&mut self.st, span, sink),
        }
        self.tape = tape;
    }

    /// Final (or, after a cut, best-effort) outcome. Idempotent.
    pub fn finish(&mut self) -> Outcome {
        if !self.stream && !self.parsed_body {
            self.parsed_body = true;
            let mut tape = std::mem::take(&mut self.tape);
            match json::parse(&self.data, &mut tape) {
                Ok(doc) => whole_body(&mut self.st, self.dialect, doc.root()),
                Err(_) => self.st.tainted = true,
            }
            self.tape = tape;
        }
        let st = &self.st;
        let mut usage = match self.dialect {
            Dialect::AnthropicMessages => {
                let a = st.iterations.unwrap_or(st.anth);
                let (w5, w1) = if a.cc_5m.is_some() || a.cc_1h.is_some() {
                    (a.cc_5m.unwrap_or(0), a.cc_1h.unwrap_or(0))
                } else {
                    (a.cc_total.unwrap_or(0), 0)
                };
                Usage {
                    input: a.input.unwrap_or(0),
                    output: a.output.unwrap_or(0),
                    cache_write_5m: w5,
                    cache_write_1h: w1,
                    cache_read: a.cache_read.unwrap_or(0),
                    estimated: !st.final_usage,
                    provider_cost_uusd: st.anth_cost,
                }
            }
            Dialect::OpenAiChat => {
                // Some providers (xAI) send cumulative usage in every chunk: only a stream
                // that really ended (`[DONE]`, or a whole JSON body) has final usage.
                let mut u = st.oa.unwrap_or(Usage { estimated: true, ..Usage::default() });
                u.estimated |= !st.done;
                u
            }
        };
        if st.tainted {
            usage.estimated = true;
        }
        if usage.estimated {
            // ponytail: ~4 bytes of SSE payload per output token; estimated receipts settle
            // pessimistically at the reservation anyway (05 §5.2).
            usage.output = usage.output.max(st.out_bytes.div_ceil(4));
        }
        Outcome {
            usage,
            model: st.model.clone(),
            id: st.id.clone(),
            complete: st.done,
            provider_error: st.error,
            forbidden: st.forbidden,
            malformed: st.malformed,
            tail: if self.stream { self.ev_start } else { self.pos },
        }
    }
}

fn set_once(slot: &mut Option<String>, v: Option<Val<'_>>) {
    if slot.is_none()
        && let Some(s) = v.and_then(Val::as_str).filter(|s| !s.is_empty() && s.len() <= 256)
    {
        *slot = Some(s.into_owned());
    }
}

const PLAIN_BLOCKS: [&str; 3] = ["text", "thinking", "redacted_thinking"];

fn anthropic_event(st: &mut State, v: Val<'_>, data_len: u64, span: Span, sink: &mut dyn FnMut(Span, Event<'_>)) -> u32 {
    let Some(ty) = v.get("type") else {
        invalid(st, span, sink);
        return 0;
    };
    let index = u32_of(v.get("index"));
    if ty.is_str("content_block_delta") {
        let d = v.get("delta");
        let pj = d.and_then(|d| d.get("partial_json"));
        let is_json = pj.is_some() || d.and_then(|d| d.get("type")).is_some_and(|t| t.is_str("input_json_delta"));
        match (index, pj) {
            (Some(i), Some(pj)) if pj.kind() == Kind::Str && st.open_tools.contains(&i) => sink(span, Event::ToolArgs { index: i, json: pj }),
            // Tool input for a block that is not an open tool_use block: refuse.
            _ if is_json || index.is_some_and(|i| st.open_tools.contains(&i)) => invalid(st, span, sink),
            _ => {
                st.out_bytes = st.out_bytes.saturating_add(data_len);
                sink(span, Event::Other);
            }
        }
    } else if ty.is_str("content_block_start") {
        let cb = v.get("content_block").filter(|c| c.kind() == Kind::Obj);
        let bt = cb.and_then(|c| c.get("type"));
        match (bt, index) {
            (Some(t), Some(i)) if t.is_str("tool_use") => {
                // Real streams send `"input":{}` here; input smuggled into the start event
                // would bypass delta assembly and inspection.
                let empty_input = cb.and_then(|c| c.get("input")).is_none_or(|x| x.kind() == Kind::Obj && x.entries().next().is_none());
                if !empty_input || st.open_tools.contains(&i) || st.open_tools.len() >= MAX_OPEN_TOOLS {
                    invalid(st, span, sink);
                    return 0;
                }
                st.open_tools.push(i);
                sink(span, Event::ToolStart { index: i, id: cb.and_then(|c| c.get("id")), name: cb.and_then(|c| c.get("name")) });
            }
            (Some(t), Some(i)) if PLAIN_BLOCKS.iter().any(|p| t.is_str(p)) && !st.open_tools.contains(&i) => sink(span, Event::Other),
            (Some(t), Some(_)) if !PLAIN_BLOCKS.iter().any(|p| t.is_str(p)) => {
                st.forbidden = true;
                sink(span, Event::Forbidden { block_type: t });
            }
            _ => invalid(st, span, sink),
        }
    } else if ty.is_str("content_block_stop") {
        if let Some(p) = index.and_then(|i| st.open_tools.iter().position(|&o| o == i)) {
            let i = st.open_tools.swap_remove(p);
            sink(span, Event::ToolEnd { index: i });
            return 1;
        }
        sink(span, Event::Other);
    } else if ty.is_str("message_start") {
        let m = v.get("message");
        // Content must arrive as blocks; a pre-filled message could carry a tool call.
        if m.and_then(|m| m.get("content")).is_some_and(|c| c.kind() != Kind::Arr || c.items().next().is_some()) {
            invalid(st, span, sink);
            return 0;
        }
        set_once(&mut st.id, m.and_then(|m| m.get("id")));
        set_once(&mut st.model, m.and_then(|m| m.get("model")));
        if let Some(u) = m.and_then(|m| m.get("usage")) {
            anth_usage(st, u);
        }
        sink(span, Event::Other);
    } else if ty.is_str("message_delta") {
        if let Some(u) = v.get("usage") {
            anth_usage(st, u);
            st.final_usage = true;
        }
        sink(span, Event::Other);
    } else if ty.is_str("message_stop") {
        st.done = true;
        sink(span, Event::Stop);
    } else if ty.is_str("error") {
        st.error = true;
        sink(span, Event::Error);
    } else {
        sink(span, Event::Other);
    }
    0
}

fn anth_usage(st: &mut State, u: Val<'_>) {
    st.anth.overlay(u);
    if let Some(its) = u.get("iterations").filter(|i| i.items().next().is_some()) {
        let mut sum = AnthUsage::default();
        for it in its.items() {
            let mut one = AnthUsage::default();
            one.overlay(it);
            sum.add(&one);
        }
        st.iterations = Some(sum);
    }
    if let Some(c) = u.get("cost").filter(|c| !c.is_null()) {
        match decimal_to_uusd_ceil(c.raw()).filter(|_| c.kind() == Kind::Num) {
            Some(x) => st.anth_cost = Some(x),
            None => st.tainted = true,
        }
    }
}

fn openai_chunk(st: &mut State, v: Val<'_>, data_len: u64, span: Span, sink: &mut dyn FnMut(Span, Event<'_>)) -> u32 {
    if v.get("error").is_some_and(|e| !e.is_null()) {
        st.error = true;
        sink(span, Event::Error);
        return 0;
    }
    set_once(&mut st.id, v.get("id"));
    set_once(&mut st.model, v.get("model"));
    let mut ends = 0u32;
    let mut emitted = false;
    let choices = v.get("choices");
    // Refuse what the tool-call tracker cannot account for (n > 1 is denied upstream).
    let bad = choices.is_some_and(|ch| {
        ch.items().any(|c| {
            let d = c.get("delta");
            c.get("index").and_then(Val::as_u64) != Some(0)
                || c.get("message").is_some()
                || d.and_then(|d| d.get("function_call")).is_some_and(|f| !f.is_null())
                || d.and_then(|d| d.get("tool_calls")).is_some_and(|t| t.kind() != Kind::Arr && !t.is_null())
        })
    });
    if bad {
        invalid(st, span, sink);
        return 0;
    }
    for c in choices.map(Val::items).into_iter().flatten() {
        let d = c.get("delta");
        for tc in d.and_then(|d| d.get("tool_calls")).map(Val::items).into_iter().flatten() {
            let f = tc.get("function");
            let name = f.and_then(|f| f.get("name"));
            let Some(i) = u32_of(tc.get("index")) else {
                invalid(st, span, sink);
                return ends;
            };
            if st.oa_open == Some(i) {
                if name.is_some_and(|n| n.kind() != Kind::Null && !n.raw().is_empty()) {
                    invalid(st, span, sink); // a second name for the same call
                    return ends;
                }
            } else {
                if st.oa_last.is_some_and(|last| i <= last) {
                    invalid(st, span, sink); // reopened or out-of-order tool call
                    return ends;
                }
                if let Some(prev) = st.oa_open {
                    ends = ends.saturating_add(1);
                    sink(span, Event::ToolEnd { index: prev });
                }
                st.oa_open = Some(i);
                st.oa_last = Some(i);
                sink(span, Event::ToolStart { index: i, id: tc.get("id"), name });
            }
            if let Some(a) = f.and_then(|f| f.get("arguments")).filter(|a| a.kind() == Kind::Str) {
                sink(span, Event::ToolArgs { index: i, json: a });
            }
            emitted = true;
        }
        if d.is_some_and(|d| ["content", "reasoning_content", "reasoning"].iter().any(|k| d.get(k).is_some_and(|x| x.kind() == Kind::Str))) {
            st.out_bytes = st.out_bytes.saturating_add(data_len);
        }
        if c.get("finish_reason").is_some_and(|f| !f.is_null())
            && let Some(prev) = st.oa_open.take()
        {
            ends = ends.saturating_add(1);
            sink(span, Event::ToolEnd { index: prev });
            emitted = true;
        }
    }
    if let Some(u) = v.get("usage").filter(|u| u.kind() == Kind::Obj) {
        oa_usage(st, u);
    }
    if !emitted {
        sink(span, Event::Other);
    }
    ends
}

fn oa_usage(st: &mut State, u: Val<'_>) {
    let g = |v: Option<Val<'_>>, k: &str| v.and_then(|v| v.get(k)).and_then(Val::as_u64);
    let prompt = g(Some(u), "prompt_tokens");
    let completion = g(Some(u), "completion_tokens");
    let total = g(Some(u), "total_tokens");
    let details = u.get("prompt_tokens_details");
    let cached = g(details, "cached_tokens").unwrap_or(0);
    let write = g(details, "cache_write_tokens").unwrap_or(0);
    let (hit, miss) = (g(Some(u), "prompt_cache_hit_tokens"), g(Some(u), "prompt_cache_miss_tokens"));
    let mut est = prompt.is_none() || completion.is_none();
    let prompt = prompt.unwrap_or(0);
    let (input, cache_read, cache_write) = if hit.is_some() || miss.is_some() {
        // DeepSeek: cache-miss tokens are the uncached input.
        let hit = hit.unwrap_or(0);
        (miss.unwrap_or_else(|| prompt.saturating_sub(hit)), hit, 0)
    } else {
        match prompt.checked_sub(cached).and_then(|p| p.checked_sub(write)) {
            Some(i) => (i, cached, write),
            None => {
                est = true;
                (prompt, cached, write)
            }
        }
    };
    let mut cost = match u.get("cost").filter(|c| !c.is_null()) {
        None => None,
        Some(c) => {
            let x = decimal_to_uusd_ceil(c.raw()).filter(|_| c.kind() == Kind::Num);
            est |= x.is_none();
            x
        }
    };
    // xAI: integer `cost_in_usd_ticks`, 10^10 ticks per dollar = 10^4 ticks per µ$.
    if let Some(t) = u.get("cost_in_usd_ticks").filter(|c| !c.is_null()) {
        let x = t.as_u64().map(|t| t.div_ceil(10_000));
        est |= x.is_none();
        cost = cost.max(x);
    }
    // Output must include reasoning. OpenAI-style counts it inside `completion_tokens`;
    // xAI does not (total = prompt + completion + reasoning). `total − prompt` covers both
    // and never undercounts.
    let output = completion.unwrap_or(0).max(total.map_or(0, |t| t.saturating_sub(prompt)));
    st.oa = Some(Usage {
        input,
        output,
        cache_write_5m: cache_write,
        cache_write_1h: 0,
        cache_read,
        estimated: est,
        provider_cost_uusd: cost,
    });
}

fn whole_body(st: &mut State, dialect: Dialect, v: Val<'_>) {
    match dialect {
        Dialect::AnthropicMessages => {
            if v.get("type").is_some_and(|t| t.is_str("error")) {
                st.error = true;
                return;
            }
            set_once(&mut st.id, v.get("id"));
            set_once(&mut st.model, v.get("model"));
            for b in v.get("content").map(Val::items).into_iter().flatten() {
                if let Some(t) = b.get("type")
                    && !t.is_str("tool_use")
                    && !PLAIN_BLOCKS.iter().any(|p| t.is_str(p))
                {
                    st.forbidden = true;
                }
            }
            if let Some(u) = v.get("usage") {
                anth_usage(st, u);
                st.final_usage = true;
                st.done = true;
            }
        }
        Dialect::OpenAiChat => {
            if v.get("error").is_some_and(|e| !e.is_null()) {
                st.error = true;
                return;
            }
            set_once(&mut st.id, v.get("id"));
            set_once(&mut st.model, v.get("model"));
            if let Some(u) = v.get("usage").filter(|u| u.kind() == Kind::Obj) {
                oa_usage(st, u);
                st.done = true;
            }
        }
    }
}

/// `ceil(value × 10^6)` for a non-negative JSON decimal (dollars → µ$), exact integer math.
pub fn decimal_to_uusd_ceil(s: &str) -> Option<u64> {
    const KEEP: u32 = 30;
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let (mant, exp) = match s.find(['e', 'E']) {
        Some(i) => (s.get(..i)?, s.get(i.checked_add(1)?..)?.parse::<i64>().ok()?.clamp(-100_000, 100_000)),
        None => (s, 0),
    };
    let (ip, fp) = mant.split_once('.').unwrap_or((mant, ""));
    let mut scale = exp.checked_sub(i64::try_from(fp.len()).ok()?)?;
    let (mut d, mut sig, mut dropped) = (0u128, 0u32, false);
    for c in ip.chars().chain(fp.chars()) {
        let digit = c.to_digit(10)?;
        if sig == 0 && digit == 0 {
            continue;
        }
        if sig < KEEP {
            d = d.checked_mul(10)?.checked_add(u128::from(digit))?;
            sig = sig.saturating_add(1);
        } else {
            scale = scale.checked_add(1)?;
            dropped |= digit != 0;
        }
    }
    if d == 0 {
        return Some(0);
    }
    if neg {
        return None;
    }
    let shift = scale.checked_add(6)?;
    if shift >= 0 {
        if dropped {
            return None;
        }
        let p = 10u128.checked_pow(u32::try_from(shift).ok()?)?;
        return u64::try_from(d.checked_mul(p)?).ok();
    }
    let k = u32::try_from(shift.checked_neg()?).ok()?;
    let Some(p) = 10u128.checked_pow(k) else {
        return Some(1);
    };
    let q = d.checked_div(p)?;
    let r = d.checked_rem(p)?;
    u64::try_from(q.checked_add(u128::from(r != 0 || dropped))?).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decimal() {
        let f = decimal_to_uusd_ceil;
        assert_eq!(f("0"), Some(0));
        assert_eq!(f("-0.0"), Some(0));
        assert_eq!(f("1"), Some(1_000_000));
        assert_eq!(f("0.000123"), Some(123));
        assert_eq!(f("0.0001231"), Some(124));
        assert_eq!(f("1.5e-3"), Some(1500));
        assert_eq!(f("1E2"), Some(100_000_000));
        assert_eq!(f("0.00000000001"), Some(1));
        assert_eq!(f("1e-300"), Some(1));
        assert_eq!(f("0.000001000000000000000000000000000000001"), Some(2));
        assert_eq!(f("-0.5"), None);
        assert_eq!(f("1e30"), None);
        assert_eq!(f("18446744073709.551615"), Some(u64::MAX));
        assert_eq!(f("18446744073709.551616"), None);
    }
}
