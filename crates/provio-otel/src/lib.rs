//! provio-otel — OpenTelemetry GenAI semantic-convention emitter (spec §13).
//!
//! Emits the `invoke_agent → chat → execute_tool` span tree with MCP
//! attributes; policy decisions attach as span events on the tool span.
//!
//! Wave 1 scope: a dependency-free span model + JSON-lines exporter with the
//! exact GenAI attribute vocabulary, so any OTLP collector mapping lands as
//! a thin adapter in wave 2. Convention version pinned: OTel semconv gen-ai
//! (experimental, 1.3x era) — the conventions are still evolving; the pin is
//! documented here so a convention bump is a deliberate act.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use provio_core::call::ToolCall;
use provio_core::error::Result;
use provio_core::verdict::Verdict;
use provio_core::Timestamp;

/// The pinned semantic-convention generation. Bump deliberately.
pub const SEMCONV_PIN: &str = "gen-ai-semconv/experimental-1.3x";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn id(hex_len: usize) -> String {
    // Unique-enough span/trace ids without a rand dependency.
    let raw = format!(
        "{:x}{}{:x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        Timestamp::now().epoch_ms()
    );
    let mut s = String::with_capacity(hex_len);
    while s.len() < hex_len {
        s.push_str(&raw);
    }
    s.truncate(hex_len);
    s
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SpanEvent {
    pub name: String,
    pub attributes: BTreeMap<String, String>,
    pub time: Timestamp,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Span {
    pub name: String,
    pub trace_id: String,
    pub span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub attributes: BTreeMap<String, String>,
    pub events: Vec<SpanEvent>,
    pub start: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<Timestamp>,
}

impl Span {
    fn new(name: &str, trace: &str, parent: Option<String>) -> Self {
        Span {
            name: name.to_string(),
            trace_id: trace.to_string(),
            span_id: id(16),
            parent_span_id: parent,
            attributes: BTreeMap::new(),
            events: Vec::new(),
            start: Timestamp::now(),
            end: None,
        }
    }

    pub fn attr(&mut self, key: &str, value: impl ToString) -> &mut Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    pub fn event(&mut self, name: &str, attrs: &[(&str, String)]) -> &mut Self {
        self.events.push(SpanEvent {
            name: name.to_string(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            time: Timestamp::now(),
        });
        self
    }

    pub fn finish(&mut self) {
        self.end = Some(Timestamp::now());
    }
}

/// Builds the GenAI span tree for one governed agent run.
pub struct GenAiTrace {
    pub trace_id: String,
    pub invoke_agent: Span,
}

impl GenAiTrace {
    /// Root span: `invoke_agent <agent>`.
    pub fn begin(agent: &str) -> Self {
        let trace_id = id(32);
        let mut root = Span::new(&format!("invoke_agent {agent}"), &trace_id, None);
        root.attr("gen_ai.operation.name", "invoke_agent")
            .attr("gen_ai.agent.name", agent)
            .attr("provio.semconv.pin", SEMCONV_PIN);
        GenAiTrace {
            trace_id,
            invoke_agent: root,
        }
    }

    /// Child span: `chat <model>`.
    pub fn chat(&self, model: &str) -> Span {
        let mut s = Span::new(
            &format!("chat {model}"),
            &self.trace_id,
            Some(self.invoke_agent.span_id.clone()),
        );
        s.attr("gen_ai.operation.name", "chat")
            .attr("gen_ai.request.model", model);
        s
    }

    /// Child span: `execute_tool <tool>` (+ MCP attributes when present).
    pub fn execute_tool(&self, call: &ToolCall) -> Span {
        let mut s = Span::new(
            &format!("execute_tool {}", call.tool),
            &self.trace_id,
            Some(self.invoke_agent.span_id.clone()),
        );
        s.attr("gen_ai.operation.name", "execute_tool")
            .attr("gen_ai.tool.name", &call.tool)
            .attr("gen_ai.tool.call.id", &call.call_id)
            .attr(
                "provio.intercept.mode",
                format!("{:?}", call.mode).to_lowercase(),
            );
        if let Some(server) = &call.server {
            s.attr("mcp.server.name", &server.name)
                .attr("mcp.transport", &server.transport);
        }
        s
    }

    /// Policy decisions attach as events on the tool span (spec §13).
    pub fn record_decision(&self, tool_span: &mut Span, verdict: &Verdict) {
        let kind = match verdict {
            Verdict::Allow { .. } => "allow",
            Verdict::Deny { .. } => "deny",
            Verdict::Ask { .. } => "ask",
            Verdict::Redact { .. } => "redact",
        };
        tool_span.event(
            "provio.policy.decision",
            &[
                ("provio.verdict", kind.to_string()),
                (
                    "provio.rule_id",
                    verdict.rule_id().unwrap_or("default").to_string(),
                ),
            ],
        );
    }
}

/// JSON-lines span exporter (one span per line, OTLP-mappable).
/// The production OTLP exporter (gRPC/HTTP) is a wave-2 adapter over this
/// same span model — nothing here changes when it lands.
pub struct JsonLinesExporter<W: Write> {
    out: W,
}

impl<W: Write> JsonLinesExporter<W> {
    pub fn new(out: W) -> Self {
        JsonLinesExporter { out }
    }

    pub fn export(&mut self, span: &Span) -> Result<()> {
        let line = serde_json::to_string(span)?;
        self.out.write_all(line.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.out.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provio_core::call::{CallerIdentity, InterceptMode, ServerIdentity};

    fn call() -> ToolCall {
        ToolCall {
            call_id: "c1".into(),
            session_id: "s1".into(),
            caller: CallerIdentity {
                agent: "claude-code".into(),
                agent_version: None,
                user: None,
                non_human_id: None,
            },
            mode: InterceptMode::Mcp,
            tool: "fs.read".into(),
            args: serde_json::json!({"path": "x"}),
            server: Some(ServerIdentity {
                name: "filesystem".into(),
                transport: "stdio".into(),
                version: None,
            }),
            trust: None,
            captured_at: Timestamp::now(),
        }
    }

    #[test]
    fn builds_genai_span_tree_with_decision_event() {
        let trace = GenAiTrace::begin("claude-code");
        assert_eq!(
            trace.invoke_agent.attributes["gen_ai.operation.name"],
            "invoke_agent"
        );
        assert_eq!(
            trace.invoke_agent.attributes["gen_ai.agent.name"],
            "claude-code"
        );
        assert_eq!(
            trace.invoke_agent.attributes["provio.semconv.pin"],
            SEMCONV_PIN
        );

        let chat = trace.chat("claude-sonnet");
        assert_eq!(
            chat.parent_span_id.as_deref(),
            Some(trace.invoke_agent.span_id.as_str())
        );
        assert_eq!(chat.trace_id, trace.trace_id);
        assert_eq!(chat.attributes["gen_ai.operation.name"], "chat");
        assert_eq!(chat.attributes["gen_ai.request.model"], "claude-sonnet");

        let mut tool = trace.execute_tool(&call());
        assert_eq!(
            tool.parent_span_id.as_deref(),
            Some(trace.invoke_agent.span_id.as_str())
        );
        assert_eq!(tool.trace_id, trace.trace_id);
        assert_eq!(tool.attributes["gen_ai.operation.name"], "execute_tool");
        assert_eq!(tool.attributes["gen_ai.tool.name"], "fs.read");
        assert_eq!(tool.attributes["gen_ai.tool.call.id"], "c1");
        assert_eq!(tool.attributes["provio.intercept.mode"], "mcp");
        assert_eq!(tool.attributes["mcp.server.name"], "filesystem");
        assert_eq!(tool.attributes["mcp.transport"], "stdio");
        trace.record_decision(
            &mut tool,
            &Verdict::Deny {
                rule_id: "never-read-secrets".into(),
                reason: "x".into(),
                location: None,
            },
        );
        assert_eq!(tool.events[0].name, "provio.policy.decision");
        assert_eq!(tool.events[0].attributes["provio.verdict"], "deny");
        assert_eq!(
            tool.events[0].attributes["provio.rule_id"],
            "never-read-secrets"
        );
    }

    #[test]
    fn decision_event_defaults_rule_id_when_verdict_has_none() {
        let trace = GenAiTrace::begin("agent");
        let mut tool = trace.execute_tool(&call());

        trace.record_decision(&mut tool, &Verdict::Allow { rule_id: None });

        assert_eq!(tool.events[0].attributes["provio.verdict"], "allow");
        assert_eq!(tool.events[0].attributes["provio.rule_id"], "default");
    }

    #[test]
    fn exporter_writes_one_json_line_per_span() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut exp = JsonLinesExporter::new(&mut buf);
            let trace = GenAiTrace::begin("agent");
            let mut tool = trace.execute_tool(&call());
            tool.finish();
            exp.export(&tool).unwrap();
            exp.export(&trace.invoke_agent).unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text.lines().count(), 2);
        let parsed: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["name"], "execute_tool fs.read");
    }
}
