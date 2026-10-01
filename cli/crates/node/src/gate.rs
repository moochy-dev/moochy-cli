//! Gateway tool-call gate (06 §8, 03 §12.3): forwards the provider's original bytes event by
//! event, holds every tool-call block until its end, checks it (`ToolSet::check_call`: declared
//! name, schema, tripwire) and releases it only once a verified progress checkpoint covers it;
//! otherwise the block is replaced by a visible `[moochy]` text. `Invalid` / `Forbidden` stream
//! events fail the task (fail closed).

use crate::engine::Dialect;
use bytes::{Bytes, BytesMut};
use moochy_worker::inspect::{ToolSet, Verdict, response_tool_calls};
use moochy_worker::stream::{Event, StreamParser};
use serde_json::{Value, json};
use std::collections::VecDeque;

enum Out {
    Bytes(Bytes),
    Tool { seq: u32, bytes: Bytes, index: u32, block: Option<String> },
}

struct Hold {
    start: u64,
    open: u32,
    closing: Option<u64>,
    first_index: u32,
    calls: Vec<(u32, String, Vec<u8>)>,
}

enum K {
    Pass,
    Start(u32, String),
    Args(u32, String),
    End,
    Fail(&'static str),
}

pub struct Gate {
    dialect: Dialect,
    stream: bool,
    parser: StreamParser,
    tools: Option<ToolSet>,
    buf: BytesMut,
    base: u64,
    hold: Option<Hold>,
    out: VecDeque<Out>,
    last_seq: u32,
    items: Vec<(u64, u64, K)>,
}

const MAX_TOOL_INPUT: usize = 4 << 20;

impl Gate {
    pub fn new(dialect: Dialect, stream: bool, request: &[u8]) -> Self {
        Self {
            dialect,
            stream,
            parser: StreamParser::new(dialect.worker(), stream),
            tools: ToolSet::from_request(dialect.worker(), request).ok(),
            buf: BytesMut::new(),
            base: 0,
            hold: None,
            out: VecDeque::new(),
            last_seq: 0,
            items: Vec::new(),
        }
    }

    fn verdict(&self, name: &str, input: &[u8]) -> Option<String> {
        match self.tools.as_ref().map(|t| t.check_call(name, input)) {
            Some(Verdict::Allow) => None,
            Some(Verdict::Block(r)) => Some(r),
            None => Some("the request declared no usable tools".into()),
        }
    }

    /// Push one decrypted chunk. `Err(reason)` = fail the task.
    pub fn push(&mut self, seq: u32, pt: &[u8]) -> Result<(), &'static str> {
        self.last_seq = seq;
        self.buf.extend_from_slice(pt);
        if !self.stream {
            return Ok(());
        }
        let mut items = std::mem::take(&mut self.items);
        items.clear();
        let r = self.parser.feed(pt, &mut |span, ev| {
            let k = match ev {
                Event::Other | Event::Stop | Event::Error => K::Pass,
                Event::ToolStart { index, name, .. } => K::Start(index, name.and_then(moochy_worker::json::Val::as_str).map(std::borrow::Cow::into_owned).unwrap_or_default()),
                Event::ToolArgs { index, json } => K::Args(index, json.as_str().map(std::borrow::Cow::into_owned).unwrap_or_default()),
                Event::ToolEnd { .. } => K::End,
                Event::Forbidden { .. } => K::Fail("forbidden block type in the response"),
                Event::Invalid => K::Fail("malformed provider stream"),
            };
            items.push((span.start, span.end, k));
        });
        if r.is_err() {
            return Err("provider event too large");
        }
        let mut emit_to = self.base;
        for (start, end, k) in items.drain(..) {
            // A closed tool block ends when an event past it begins (a shared span may restart it).
            if let Some(h) = &self.hold
                && h.closing.is_some_and(|c| start >= c)
            {
                self.close_hold(seq);
                emit_to = self.base;
            }
            match k {
                K::Fail(why) => return Err(why),
                K::Pass => {
                    if self.hold.is_none() {
                        emit_to = emit_to.max(end);
                    }
                }
                K::Start(index, name) => {
                    if let Some(h) = &mut self.hold {
                        h.closing = None;
                        h.open = h.open.saturating_add(1);
                        h.calls.push((index, name, Vec::new()));
                    } else {
                        self.emit_until(start);
                        self.hold = Some(Hold { start, open: 1, closing: None, first_index: index, calls: vec![(index, name, Vec::new())] });
                    }
                }
                K::Args(index, frag) => {
                    if let Some(c) = self.hold.as_mut().and_then(|h| h.calls.iter_mut().rev().find(|c| c.0 == index)) {
                        if c.2.len().saturating_add(frag.len()) > MAX_TOOL_INPUT {
                            return Err("tool input too large");
                        }
                        c.2.extend_from_slice(frag.as_bytes());
                    }
                }
                K::End => {
                    if let Some(h) = &mut self.hold {
                        h.open = h.open.saturating_sub(1);
                        if h.open == 0 {
                            h.closing = Some(end);
                        }
                    }
                }
            }
        }
        self.items = items;
        if self.hold.as_ref().is_some_and(|h| h.closing.is_some()) {
            self.close_hold(seq);
        } else if self.hold.is_none() {
            self.emit_until(emit_to);
        }
        Ok(())
    }

    fn emit_until(&mut self, abs: u64) {
        let n = usize::try_from(abs.saturating_sub(self.base)).unwrap_or(0).min(self.buf.len());
        if n > 0 {
            self.out.push_back(Out::Bytes(self.buf.split_to(n).freeze()));
            self.base = self.base.saturating_add(n as u64);
        }
    }

    fn close_hold(&mut self, seq: u32) {
        let Some(h) = self.hold.take() else { return };
        let end = h.closing.unwrap_or(self.base.saturating_add(self.buf.len() as u64));
        self.emit_until(h.start);
        let n = usize::try_from(end.saturating_sub(self.base)).unwrap_or(0).min(self.buf.len());
        let bytes = self.buf.split_to(n).freeze();
        self.base = self.base.saturating_add(n as u64);
        let block = h.calls.iter().find_map(|(_, name, input)| self.verdict(name, input));
        self.out.push_back(Out::Tool { seq, bytes, index: h.first_index, block });
    }

    fn replacement(&self, index: u32, reason: &str) -> Bytes {
        let text = format!("[moochy] a tool call from a donor's model was withheld: {reason}");
        Bytes::from(match self.dialect {
            Dialect::Anthropic => format!(
                "event: content_block_start\ndata: {}\n\nevent: content_block_delta\ndata: {}\n\nevent: content_block_stop\ndata: {}\n\n",
                json!({"type":"content_block_start","index":index,"content_block":{"type":"text","text":""}}),
                json!({"type":"content_block_delta","index":index,"delta":{"type":"text_delta","text":text}}),
                json!({"type":"content_block_stop","index":index}),
            ),
            Dialect::OpenAi => format!(
                "data: {}\n\n",
                json!({"id":"moochy","object":"chat.completion.chunk","created":0,"model":"","choices":[{"index":0,"delta":{"content":text},"finish_reason":null}]})
            ),
        })
    }

    pub fn is_stream(&self) -> bool {
        self.stream
    }

    /// A tool block is held (or still open): releasing needs a covering checkpoint.
    pub fn holds_tools(&self) -> bool {
        self.hold.is_some() || self.out.iter().any(|o| matches!(o, Out::Tool { .. })) || !self.stream
    }

    /// Next releasable output. A tool block needs a verified checkpoint with seq ≥ its chunk;
    /// at the end (`finale`) unverified blocks are replaced.
    pub fn pop(&mut self, verified: Option<u32>, finale: bool) -> Option<Bytes> {
        let ready = match self.out.front()? {
            Out::Bytes(_) => true,
            Out::Tool { seq, .. } => finale || verified.is_some_and(|v| v >= *seq),
        };
        if !ready {
            return None;
        }
        match self.out.pop_front()? {
            Out::Bytes(b) => Some(b),
            Out::Tool { seq, bytes, index, block } => {
                let signed = verified.is_some_and(|v| v >= seq);
                Some(match (block, signed) {
                    (None, true) => bytes,
                    (Some(r), _) => self.replacement(index, &r),
                    (None, false) => self.replacement(index, "no verified donor signature covers it"),
                })
            }
        }
    }

    /// End of the response: flush the stream tail, or check a non-streamed body's tool calls.
    /// `verified_all` = a verified checkpoint covers the last chunk.
    pub fn finish(&mut self, verified_all: bool) -> Result<(), &'static str> {
        if self.stream {
            if self.hold.is_some() {
                // A tool block that never ended (truncated stream): never forward it.
                let index = self.hold.as_ref().map_or(0, |h| h.first_index);
                self.hold = None;
                self.buf.clear();
                let seq = self.last_seq;
                self.out.push_back(Out::Tool { seq, bytes: Bytes::new(), index, block: Some("incomplete tool call".into()) });
            } else {
                let end = self.base.saturating_add(self.buf.len() as u64);
                self.emit_until(end);
            }
            return Ok(());
        }
        let body = self.buf.split().freeze();
        let calls = response_tool_calls(self.dialect.worker(), &body).map_err(|_| "malformed provider response")?;
        if calls.is_empty() {
            self.out.push_back(Out::Bytes(body));
            return Ok(());
        }
        let blocked: Vec<Option<String>> = calls
            .iter()
            .map(|(n, i)| self.verdict(n, i).or_else(|| (!verified_all).then(|| "no verified donor signature covers it".into())))
            .collect();
        if blocked.iter().all(Option::is_none) {
            self.out.push_back(Out::Bytes(body));
            return Ok(());
        }
        let rewritten = rewrite_body(self.dialect, &body, &blocked).ok_or("malformed provider response")?;
        self.out.push_back(Out::Bytes(rewritten));
        Ok(())
    }
}

/// Replace blocked tool calls of a non-streamed body with a visible `[moochy]` text.
fn rewrite_body(d: Dialect, body: &[u8], blocked: &[Option<String>]) -> Option<Bytes> {
    let mut v = crate::json::parse(body).ok()?;
    let note = |r: &str| format!("[moochy] a tool call from a donor's model was withheld: {r}");
    let mut i = 0usize;
    match d {
        Dialect::Anthropic => {
            let content = v.get_mut("content")?.as_array_mut()?;
            for b in content.iter_mut() {
                if b.get("type").and_then(Value::as_str) == Some("tool_use") {
                    if let Some(Some(r)) = blocked.get(i) {
                        *b = json!({"type":"text","text":note(r)});
                    }
                    i = i.saturating_add(1);
                }
            }
        }
        Dialect::OpenAi => {
            let msg = v.get_mut("choices")?.get_mut(0)?.get_mut("message")?.as_object_mut()?;
            let mut notes = Vec::new();
            if let Some(Value::Array(calls)) = msg.get_mut("tool_calls") {
                calls.retain(|_| {
                    let keep = blocked.get(i).is_none_or(Option::is_none);
                    if let Some(Some(r)) = blocked.get(i) {
                        notes.push(note(r));
                    }
                    i = i.saturating_add(1);
                    keep
                });
            }
            let prev = msg.get("content").and_then(Value::as_str).unwrap_or("").to_owned();
            msg.insert("content".into(), json!(format!("{prev}{}", notes.join("\n"))));
        }
    }
    Some(Bytes::from(v.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &[u8] = br#"{"model":"m","max_tokens":10,"stream":true,"messages":[],"tools":[{"name":"get_weather","input_schema":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}}]}"#;

    fn sse(name: &str, data: &str) -> String {
        format!("event: {name}\ndata: {data}\n\n")
    }

    fn stream(tool: &str, input: &str) -> Vec<String> {
        vec![
            sse("message_start", r#"{"type":"message_start","message":{"id":"m1","type":"message","role":"assistant","model":"x","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}}"#),
            sse("content_block_start", r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#),
            sse("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}"#),
            sse("content_block_stop", r#"{"type":"content_block_stop","index":0}"#),
            sse("content_block_start", &format!(r#"{{"type":"content_block_start","index":1,"content_block":{{"type":"tool_use","id":"t1","name":"{tool}","input":{{}}}}}}"#)),
            sse("content_block_delta", &format!(r#"{{"type":"content_block_delta","index":1,"delta":{{"type":"input_json_delta","partial_json":{}}}}}"#, serde_json::to_string(input).unwrap())),
            sse("content_block_stop", r#"{"type":"content_block_stop","index":1}"#),
            sse("message_delta", r#"{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":5}}"#),
            sse("message_stop", r#"{"type":"message_stop"}"#),
        ]
    }

    fn run(tool: &str, input: &str, verified: Option<u32>) -> String {
        let mut g = Gate::new(Dialect::Anthropic, true, REQ);
        let mut out = Vec::new();
        for (i, c) in stream(tool, input).iter().enumerate() {
            g.push(u32::try_from(i).unwrap(), c.as_bytes()).unwrap();
            while let Some(b) = g.pop(None, false) {
                out.extend_from_slice(&b);
            }
        }
        g.finish(true).unwrap();
        while let Some(b) = g.pop(verified, true) {
            out.extend_from_slice(&b);
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn text_streams_immediately_tool_waits_for_checkpoint() {
        let mut g = Gate::new(Dialect::Anthropic, true, REQ);
        let ev = stream("get_weather", r#"{"city":"Paris"}"#);
        g.push(0, ev[0].as_bytes()).unwrap();
        assert_eq!(g.pop(None, false).unwrap(), ev[0].as_bytes(), "text forwarded at once");
        for (i, c) in ev.iter().enumerate().skip(1).take(6) {
            g.push(u32::try_from(i).unwrap(), c.as_bytes()).unwrap();
        }
        let mut pre = Vec::new();
        while let Some(b) = g.pop(None, false) {
            pre.extend_from_slice(&b);
        }
        assert_eq!(pre, ev[1..4].concat().into_bytes(), "tool block held");
        assert_eq!(g.pop(Some(6), false).unwrap(), ev[4..7].concat().into_bytes(), "released byte-identical once signed");
    }

    #[test]
    fn verdicts() {
        let all = stream("get_weather", r#"{"city":"Paris"}"#).concat();
        assert_eq!(run("get_weather", r#"{"city":"Paris"}"#, Some(8)), all);
        let unsigned = run("get_weather", r#"{"city":"Paris"}"#, None);
        assert!(unsigned.contains("[moochy]") && !unsigned.contains(r#""type":"tool_use""#));
        for (t, i) in [("delete_repo", r#"{"repo":"x"}"#), ("get_weather", r#"{"town":5}"#)] {
            let o = run(t, i, Some(8));
            assert!(o.contains("[moochy]") && !o.contains(r#""type":"tool_use""#), "{o}");
            assert!(o.ends_with(&stream(t, i)[7..].concat()), "rest of the stream intact");
        }
    }

    #[test]
    fn invalid_event_fails_closed() {
        let mut g = Gate::new(Dialect::Anthropic, true, REQ);
        assert!(g.push(0, b"event: content_block_delta\ndata: {\"a\":1,\"a\":2}\n\n").is_err());
    }

    #[test]
    fn non_stream_rewrite() {
        let body = br#"{"id":"m","type":"message","role":"assistant","model":"x","content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"t","name":"rm","input":{}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#;
        let mut g = Gate::new(Dialect::Anthropic, false, REQ);
        g.push(0, body).unwrap();
        g.finish(true).unwrap();
        let o = String::from_utf8(g.pop(Some(0), true).unwrap().to_vec()).unwrap();
        assert!(o.contains("[moochy]") && !o.contains("tool_use\",\"id"));
    }
}
