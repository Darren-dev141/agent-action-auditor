#!/usr/bin/env node
'use strict';

const { McpServer, fromJsonSchema } = require('@modelcontextprotocol/server');
const { serveStdio, StdioServerTransport } = require('@modelcontextprotocol/server/stdio');
const AAA = require('./rules.js');
const BL = require('./baseline.js');
const REPLAY = require('./replay.js');
const SESSION = require('./hooks/session.js');

const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_RPC_BYTES = 2 * 1024 * 1024;
const MAX_REPLAY_TRACES = 100;
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

const objectSchema = properties => fromJsonSchema({
  type: 'object',
  additionalProperties: false,
  required: Object.entries(properties).filter(([, v]) => !v.optional).map(([k]) => k),
  properties: Object.fromEntries(Object.entries(properties).map(([k, v]) => [k, v.schema]))
});
const anyTrace = { oneOf: [{ type: 'string' }, { type: 'object' }, { type: 'array' }] };
const baselineSchema = {
  type: 'object', additionalProperties: false, required: ['version', 'entries'],
  properties: {
    version: { const: 1 },
    entries: { type: 'array', maxItems: 10000, items: { type: 'object' } }
  }
};

function byteLength(value) { return Buffer.byteLength(JSON.stringify(value), 'utf8'); }
function requireBounded(value) {
  if (byteLength(value) > MAX_INPUT_BYTES) throw new Error('input exceeds 1 MiB');
}
function validateBaseline(baseline) {
  if (baseline == null) return BL.empty();
  if (!baseline || baseline.version !== 1 || !Array.isArray(baseline.entries) || baseline.entries.some(e =>
    !e || typeof e.fingerprint !== 'string' || !/^R[1-8]:[a-f0-9]{8}$/.test(e.fingerprint)))
    throw new Error('invalid baseline');
  return baseline;
}
function rawTrace(trace) { return typeof trace === 'string' ? trace : JSON.stringify(trace); }
function safeResult(value) { return JSON.parse(AAA.redactSecrets(JSON.stringify(value))); }
function toolResult(value, isError = false) {
  const safe = safeResult(value);
  return { content: [{ type: 'text', text: JSON.stringify(safe, null, 2) }], structuredContent: safe, ...(isError ? { isError: true } : {}) };
}
function reportFor(trace, baseline) {
  const findings = BL.apply_baseline(AAA.run_rules(AAA.parse_trace(rawTrace(trace))), validateBaseline(baseline));
  const report = AAA.render_report(findings);
  return {
    headline: report.headline,
    counts: report.counts,
    stats: findings.stats,
    findings: [...findings],
    suppressed: [...(findings.suppressed || [])]
  };
}
function normalizeCall(value, index) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('call must be an object');
  if (value.function && typeof value.function === 'object')
    return SESSION.toCall({ tool_name: value.function.name, tool_input: value.function.arguments || {} }, index);
  return SESSION.toCall({
    tool_name: value.tool_name || value.name || value.tool,
    tool_input: value.tool_input !== undefined ? value.tool_input : (value.args !== undefined ? value.args : value.arguments)
  }, index);
}

function createServer() {
  const server = new McpServer({ name: 'agent-action-auditor', version: '0.1.0' }, { capabilities: { tools: {} } });

  server.registerTool('audit-a-trace', {
    title: 'Audit an agent trace',
    description: 'Audit an OpenAI, Claude Code JSONL, or Anthropic messages trace with deterministic behavior rules. No network or file access.',
    inputSchema: objectSchema({
      trace: { schema: anyTrace },
      baseline: { optional: true, schema: baselineSchema }
    }),
    annotations: READ_ONLY
  }, async input => {
    try { requireBounded(input); return toolResult(reportFor(input.trace, input.baseline)); }
    catch (e) { return toolResult({ error: e instanceof AAA.ParseError ? `invalid trace: ${e.message}` : e.message }, true); }
  });

  server.registerTool('check-a-call', {
    title: 'Check a pending tool call',
    description: 'Check one pending tool call for secret-bearing arguments and uncorroborated irreversible behavior. Prior calls are context only; nothing executes.',
    inputSchema: objectSchema({
      call: { schema: { type: 'object' } },
      prior_calls: { optional: true, schema: { type: 'array', maxItems: 2000, items: { type: 'object' } } }
    }),
    annotations: READ_ONLY
  }, async input => {
    try {
      requireBounded(input);
      const prior = (input.prior_calls || []).map((c, i) => normalizeCall(c, i));
      const call = normalizeCall(input.call, prior.length);
      const findings = [];
      const hits = AAA.secretsIn(call.rawArgs);
      if (hits.length) findings.push({ rule: 'R4', severity: 'HIGH', title: `secret-format string in arguments: ${hits.join(', ')}` });
      if (AAA.isIrreversible(call) && !AAA.corroborated(call, prior.concat(call)))
        findings.push({ rule: 'R1', severity: 'HIGH', title: `irreversible ${call.name} with no prior read of its target` });
      return toolResult({ decision: findings.length ? 'warn' : 'allow', would_block_in_block_mode: findings.length > 0, findings });
    } catch (e) { return toolResult({ error: e.message }, true); }
  });

  server.registerTool('replay', {
    title: 'Replay archived traces',
    description: 'Replay up to 100 supplied traces through the current deterministic engine. Returns per-trace reports, aggregate counts, and a two-run determinism check. Does not read paths or load code.',
    inputSchema: objectSchema({
      traces: { schema: { type: 'array', minItems: 1, maxItems: MAX_REPLAY_TRACES, items: {
        type: 'object', additionalProperties: false, required: ['trace'],
        properties: { label: { type: 'string', maxLength: 200 }, model: { type: 'string', maxLength: 200 }, trace: anyTrace }
      } } },
      baseline: { optional: true, schema: baselineSchema }
    }),
    annotations: READ_ONLY
  }, async input => {
    try {
      requireBounded(input);
      const baseline = validateBaseline(input.baseline);
      const traces = input.traces.map((t, i) => ({ label: t.label || `trace-${i + 1}`, model: t.model, raw: rawTrace(t.trace) }));
      const rows = [];
      const counts = {};
      for (const t of traces) {
        const r = REPLAY.auditWith(AAA, t.raw, baseline);
        if (r.error) { rows.push({ label: t.label, model: t.model, error: r.error }); continue; }
        for (const f of r.findings) counts[f.rule] = (counts[f.rule] || 0) + 1;
        rows.push({ label: t.label, model: t.model, report: {
          headline: AAA.render_report(r.findings).headline,
          findings: [...r.findings], suppressed: [...(r.findings.suppressed || [])]
        } });
      }
      const first = REPLAY.snapshot(AAA, traces), second = REPLAY.snapshot(AAA, traces);
      return toolResult({ traces: rows, active_findings_by_rule: counts, deterministic: first === second });
    } catch (e) { return toolResult({ error: e.message }, true); }
  });

  return server;
}

if (require.main === module) {
  const transport = new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: MAX_RPC_BYTES });
  serveStdio(() => createServer(), { transport, onerror: () => {} });
}
module.exports = { createServer, reportFor, normalizeCall, safeResult, MAX_INPUT_BYTES, MAX_RPC_BYTES, MAX_REPLAY_TRACES };
