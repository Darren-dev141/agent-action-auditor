#!/usr/bin/env node
// Agent Action Auditor — V2-5 regression replay (v2-spec §V2-5, SPEC D17).
// Usage:
//   node replay.js <trace.json|archive.ndjson|dir> [--baseline <file>]           per-trace headlines
//   node replay.js <input> --compare <other-rules.js>                            rule-version diff
//   node replay.js <input> --models <old-model-id> <new-model-id>                model-upgrade diff
//   node replay.js <input> --determinism                                         kill check: 2 runs bit-identical
// Archive line format: a bare trace, or {"model": "...", "timestamp": "...", "trace": <trace>}.
// Exit: 0 ok · 1 nondeterminism / diff found with --fail-on-diff · 2 usage/IO error
'use strict';
const fs = require('fs');
const path = require('path');
const BL = require('./baseline.js');

function readTraces(input) {
  const out = []; // { label, raw, model, timestamp }
  const add = (label, src) => {
    let obj; try { obj = JSON.parse(src); } catch { out.push({ label, raw: src }); return; }
    if (obj && typeof obj === 'object' && !Array.isArray(obj) && 'trace' in obj)
      out.push({ label, raw: typeof obj.trace === 'string' ? obj.trace : JSON.stringify(obj.trace), model: obj.model, timestamp: obj.timestamp });
    else out.push({ label, raw: src });
  };
  const readOne = p => {
    const src = fs.readFileSync(p, 'utf8').trim();
    if (!src) return;
    if (p.endsWith('.ndjson')) src.split(/\r?\n/).forEach((ln, i) => { if (ln.trim()) add(`${path.basename(p)}#${i + 1}`, ln.trim()); });
    else add(path.basename(p), src);
  };
  const walk = d => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(nd)?jsonl?$/.test(e.name)) readOne(p);
    }
  };
  fs.statSync(input).isDirectory() ? walk(input) : readOne(input);
  return out;
}

// audit one trace with a given engine; returns {findings, error}
function auditWith(engine, raw, baseline) {
  try { return { findings: BL.apply_baseline(engine.run_rules(engine.parse_trace(raw)), baseline || BL.empty()) }; }
  catch (e) { return { error: e.message }; }
}

// stable serialisation of a run, used for the determinism kill check
const snapshot = (engine, traces) => JSON.stringify(traces.map(t => {
  const r = auditWith(engine, t.raw);
  return r.error ? { e: r.error } : r.findings.map(f => [f.rule, f.severity, f.fingerprint, f.call_id || null]);
}));

// diff two engines over the same traces: which traces gain/lose findings, and why
function diffEngines(a, b, traces) {
  return traces.map(t => {
    const ra = auditWith(a, t.raw), rb = auditWith(b, t.raw);
    if (ra.error || rb.error) return { label: t.label, error: ra.error || rb.error };
    const fa = new Map(ra.findings.map(f => [f.fingerprint, f])), fb = new Map(rb.findings.map(f => [f.fingerprint, f]));
    const gained = rb.findings.filter(f => !fa.has(f.fingerprint) || fa.get(f.fingerprint).severity !== f.severity);
    const lost = ra.findings.filter(f => !fb.has(f.fingerprint));
    return { label: t.label, gained, lost };
  });
}

// model-upgrade mode: count violations by rule+severity per model id, diff old→new
function diffModels(engine, traces, oldId, newId) {
  const tally = id => {
    const c = {}; let n = 0;
    for (const t of traces.filter(t => t.model === id)) {
      n++;
      const r = auditWith(engine, t.raw);
      if (r.findings) for (const f of r.findings) { const k = `${f.rule} ${f.severity}`; c[k] = (c[k] || 0) + 1; }
    }
    return { n, c };
  };
  const o = tally(oldId), nw = tally(newId);
  const keys = [...new Set([...Object.keys(o.c), ...Object.keys(nw.c)])].sort();
  return { old: { id: oldId, traces: o.n }, new: { id: newId, traces: nw.n },
    rows: keys.map(k => ({ key: k, old: o.c[k] || 0, new: nw.c[k] || 0, delta: (nw.c[k] || 0) - (o.c[k] || 0) })) };
}

module.exports = { readTraces, auditWith, snapshot, diffEngines, diffModels };

if (require.main === module) {
  const argv = process.argv.slice(2);
  const die = msg => { console.error(`ERROR: ${msg}`); process.exit(2); };
  const valued = ['--baseline', '--compare'];
  const opt = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const mi = argv.indexOf('--models');
  const positional = argv.filter((a, i) => !a.startsWith('--') && !valued.includes(argv[i - 1]) && !(mi >= 0 && (i === mi + 1 || i === mi + 2)));
  const input = positional[0];
  if (!input) die('usage: node replay.js <trace.json|archive.ndjson|dir> [--baseline f] [--compare rules.js] [--models old new] [--determinism] [--fail-on-diff]');
  let traces; try { traces = readTraces(input); } catch (e) { die(e.message); }
  if (!traces.length) die('no traces found');
  const AAA = require('./rules.js');

  if (argv.includes('--determinism')) {
    const s1 = snapshot(AAA, traces), s2 = snapshot(AAA, traces);
    console.log(s1 === s2 ? `DETERMINISTIC: ${traces.length} trace(s), 2 runs bit-identical` : 'NONDETERMINISTIC: runs differ — fix the engine before shipping replay');
    process.exit(s1 === s2 ? 0 : 1);
  }

  if (opt('--compare')) {
    let other; try { other = require(path.resolve(opt('--compare'))); } catch (e) { die(`could not load rules ${opt('--compare')}: ${e.message}`); }
    const d = diffEngines(AAA, other, traces);
    let changed = 0;
    for (const r of d) {
      if (r.error) { console.log(`[ERROR] ${r.label}: ${r.error}`); continue; }
      if (!r.gained.length && !r.lost.length) continue;
      changed++;
      console.log(`--- ${r.label}`);
      for (const f of r.gained) console.log(AAA.redactSecrets(`  + [${f.severity}] ${f.rule} ${f.evidence} — ${f.title}`));
      for (const f of r.lost) console.log(AAA.redactSecrets(`  - [${f.severity}] ${f.rule} ${f.evidence} — ${f.title}`));
    }
    console.log(`\n${changed} of ${traces.length} trace(s) changed between ${AAA.RULES_VERSION || 'current'} and ${other.RULES_VERSION || opt('--compare')}.`);
    process.exit(changed && argv.includes('--fail-on-diff') ? 1 : 0);
  }

  if (mi >= 0) {
    const [oldId, newId] = [argv[mi + 1], argv[mi + 2]];
    if (!oldId || !newId) die('--models needs <old-model-id> <new-model-id>');
    const d = diffModels(AAA, traces, oldId, newId);
    console.log(`${d.old.id} (${d.old.traces} traces) → ${d.new.id} (${d.new.traces} traces)`);
    for (const r of d.rows) console.log(`  ${r.key.padEnd(12)} ${String(r.old).padStart(4)} → ${String(r.new).padStart(4)}  (${r.delta > 0 ? '+' : ''}${r.delta})`);
    if (!d.rows.length) console.log('  no findings under either model');
    process.exit(0);
  }

  const baseline = opt('--baseline') ? JSON.parse(fs.readFileSync(opt('--baseline'), 'utf8')) : BL.empty();
  let total = 0;
  for (const t of traces) {
    const r = auditWith(AAA, t.raw, baseline);
    if (r.error) { console.error(`[ERROR] ${t.label}: ${r.error}`); continue; }
    const sup = (r.findings.suppressed || []).length;
    total += r.findings.length;
    console.log(AAA.redactSecrets(`--- ${t.label}${t.model ? ` [${t.model}]` : ''} : ${AAA.render_report(r.findings).headline}${sup ? ` (${sup} suppressed)` : ''}`));
  }
  console.log(`\nReplayed ${traces.length} trace(s), ${total} active finding(s) total.`);
}
