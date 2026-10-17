#!/usr/bin/env node
// Fixture validator for Agent Action Auditor. Independent of the engine:
// it checks that fixtures are well-formed and that their hand-written
// expectations are complete. It does NOT run any rule.
// Usage: node tests/validate-fixtures.js [fixtures/*.json]   (exit 0 = all valid)
//
// SECRET_PATTERNS must mirror SPEC-v1.md §13 D3 exactly.
'use strict';
const fs = require('fs');
const path = require('path');
// Rule ids only — expectations below stay hand-written, so the oracle stays independent.
const { RULE_IDS: RULES } = require('../rules.js');

const SECRET_PATTERNS = {
  'ghp_':     /^ghp_[A-Za-z0-9]{36}$/,
  'AKIA':     /^AKIA[0-9A-Z]{16}$/,
  'sk_live_': /^sk_live_[A-Za-z0-9]{24,}$/,
  'sk-':      /^sk-(proj-)?[A-Za-z0-9_-]{20,}$/,   // engine adds a left boundary; PREFIX_SCAN's word boundary already excludes 'ask-'
  'xox':      /^xox[abpr]-[A-Za-z0-9-]{10,}$/,
};
const PREFIX_SCAN = /\b(ghp_|AKIA|sk_live_|sk-|xox[abpr]-)[A-Za-z0-9_-]*/g;
const SEVERITIES = ['HIGH', 'MEDIUM', 'LOW'];
const ROLES = ['system', 'user', 'assistant', 'tool'];

function expectedVerdict(findings) {
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const med = findings.filter(f => f.severity === 'MEDIUM').length;
  if (findings.length === 0) return 'CLEAN — no findings';
  if (high > 0) return 'DO NOT DEPLOY';
  if (med >= 3) return 'REVIEW BEFORE DEPLOY';
  return `PASS — ${findings.length} note${findings.length === 1 ? '' : 's'}`;
}

function validate(file) {
  const errs = [];
  let d;
  try { d = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return [`invalid JSON: ${e.message}`]; }
  if (!Array.isArray(d.messages)) return ['missing messages[]'];

  const calls = new Map();   // id -> {answered}
  d.messages.forEach((m, i) => {
    if (!ROLES.includes(m.role)) errs.push(`msg[${i}] non-OpenAI role "${m.role}"`);
    if (m.role === 'assistant' && m.tool_calls) {
      for (const tc of m.tool_calls) {
        if (!tc.id) errs.push(`msg[${i}] tool_call without id`);
        if (tc.type !== 'function' || !tc.function || !tc.function.name)
          errs.push(`msg[${i}] tool_call ${tc.id} malformed`);
        try { JSON.parse(tc.function.arguments); }
        catch { errs.push(`msg[${i}] tool_call ${tc.id} arguments not JSON`); }
        if (calls.has(tc.id)) errs.push(`duplicate call id ${tc.id}`);
        calls.set(tc.id, { answered: false });
      }
    }
    if (m.role === 'tool') {
      if (!m.tool_call_id) errs.push(`msg[${i}] tool result without tool_call_id`);
      else if (!calls.has(m.tool_call_id)) errs.push(`msg[${i}] tool result for unknown call ${m.tool_call_id}`);
      else if (calls.get(m.tool_call_id).answered) errs.push(`msg[${i}] call ${m.tool_call_id} answered twice`);
      else calls.get(m.tool_call_id).answered = true;
    }
  });
  for (const [id, c] of calls) if (!c.answered) errs.push(`call ${id} has no tool result`);

  // Secret lint: any secret-prefixed token must be a FULL valid match.
  const blob = JSON.stringify(d.messages);
  for (const m of blob.matchAll(PREFIX_SCAN)) {
    const tok = m[0];
    const key = tok.startsWith('xox') ? 'xox' : m[1];
    if (!SECRET_PATTERNS[key].test(tok))
      errs.push(`near-miss secret "${tok.slice(0, 8)}…" (len ${tok.length}) fails ${SECRET_PATTERNS[key]}`);
  }

  const e = d.expected;
  if (!e) { errs.push('missing expected{} block'); return errs; }
  if (!Array.isArray(e.findings)) errs.push('expected.findings must be an array');
  if (!Array.isArray(e.absent)) errs.push('expected.absent must be an array');
  if (errs.length && !Array.isArray(e.findings)) return errs;
  for (const f of e.findings) {
    if (!RULES.includes(f.rule)) errs.push(`finding has unknown rule ${f.rule}`);
    if (!SEVERITIES.includes(f.severity)) errs.push(`finding ${f.rule} bad severity ${f.severity}`);
    // Message-level rules (R7/R8) carry call_id: null — there is no call to point at.
    if (f.call_id != null && !calls.has(f.call_id)) errs.push(`finding ${f.rule} points at unknown call ${f.call_id}`);
  }
  const fired = new Set(e.findings.map(f => f.rule));
  for (const r of e.absent) {
    if (!RULES.includes(r)) errs.push(`absent has unknown rule ${r}`);
    if (fired.has(r)) errs.push(`rule ${r} is both expected and absent`);
  }
  for (const r of RULES)
    if (!fired.has(r) && !e.absent.includes(r)) errs.push(`rule ${r} not declared (must be in findings or absent)`);
  const want = expectedVerdict(e.findings);
  if (e.verdict !== want) errs.push(`verdict "${e.verdict}" inconsistent with findings (thresholds give "${want}")`);
  if (!e.stats || e.stats.tool_calls !== calls.size)
    errs.push(`stats.tool_calls must equal ${calls.size}`);
  return errs;
}

const files = process.argv.slice(2).length
  ? process.argv.slice(2)
  : fs.readdirSync(path.join(__dirname, '..', 'fixtures'))
      .filter(f => f.endsWith('.json'))
      .map(f => path.join(__dirname, '..', 'fixtures', f));
let bad = 0;
for (const f of files) {
  const errs = validate(f);
  console.log(`${errs.length ? 'FAIL' : 'ok  '} ${path.basename(f)}`);
  for (const x of errs) console.log(`       - ${x}`);
  if (errs.length) bad++;
}
console.log(`\n${files.length - bad}/${files.length} fixtures valid`);
process.exit(bad ? 1 : 0);
