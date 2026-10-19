#!/usr/bin/env node
// Agent Action Auditor — fuzz harness for the untrusted-input surfaces.
//
// Targets the parsers/validators that consume agent-action logs nobody vetted:
//   pipeline  AAA.parse_trace -> AAA.run_rules -> AAA.render_report   (rules.js)
//   claude    AAA.fromClaudeMessages -> AAA.parse_trace (object path)  (rules.js)
//   baseline  BL.apply_baseline / BL.diff_baselines / BL.accept        (baseline.js)
//   mcp-call  MCP.normalizeCall                                        (mcp-server.js)
//   replay    REPLAY.readTraces (temp file) -> AAA.parse_trace         (replay.js)
//
// Contract under test: malformed input is rejected in a controlled way
// (ParseError from the trace pipeline; a plain Error from the validators).
// Anything else — TypeError, ReferenceError, RangeError, a hang — is a crash.
// First repro per unique crash signature lands in fuzz/crashes/.
//
// Deterministic: same --seed => same mutations => same result. Node built-ins
// only; no new dependencies. Usage:
//   node fuzz/fuzz.js [--iterations N] [--seed N] [--max-ms N] [--quiet]
//   npm run fuzz            (defaults: 4000 iterations, 60s budget)
// Exit 0 = no crashes. Exit 1 = crashes found (repros in fuzz/crashes/).
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const AAA = require(path.join(ROOT, 'rules.js'));
const BL = require(path.join(ROOT, 'baseline.js'));
const REPLAY = require(path.join(ROOT, 'replay.js'));
const MCP = require(path.join(ROOT, 'mcp-server.js'));

// ---------- args ----------
const argv = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = argv.indexOf(name);
  const v = i >= 0 ? Number(argv[i + 1]) : NaN;
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : dflt;
};
const ITERATIONS = opt('--iterations', 4000);
const SEED = opt('--seed', 20261018);
const MAX_MS = opt('--max-ms', 60000);
const QUIET = argv.includes('--quiet');
const MAX_INPUT = 1024 * 1024; // mirror the MCP server's MAX_INPUT_BYTES cap
const MAX_SAVED_CRASHES = 25;

// ---------- deterministic PRNG (mulberry32) ----------
let state = SEED >>> 0;
const rand = () => {
  state = (state + 0x6D2B79F5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const ri = n => Math.floor(rand() * n); // 0..n-1
const pick = arr => arr[ri(arr.length)];

// ---------- corpus ----------
const corpusDir = path.join(__dirname, 'corpus');
const seeds = fs.readdirSync(corpusDir).sort()
  .map(f => ({ name: f, text: fs.readFileSync(path.join(corpusDir, f), 'utf8') }));
if (!seeds.length) { console.error('fuzz: empty corpus'); process.exit(2); }

// Sample findings/baseline for the baseline target, from the violation seed.
const violationText = seeds.find(s => s.name.includes('violation')).text;
const sampleFindings = AAA.run_rules(AAA.parse_trace(violationText));
const sampleBaseline = JSON.parse(seeds.find(s => s.name === 'baseline.json').text);
const sampleFinding = { fingerprint: 'R1:fuzz0000', rule: 'R1' };

// ---------- mutators ----------
const TOKENS = ['{', '}', '[', ']', '"', ':', ',', 'null', 'true', 'false', '0', '-1', '1e999',
  '"messages"', '"role"', '"assistant"', '"tool_calls"', '"function"', '"arguments"',
  '"content"', '"tool_use"', '"tool_result"', '"__proto__"', '"constructor"',
  ' ', '\n', '\t', '', 'é', '\u0001', '"\\ud800"'];
const CHARS = '{}[]",:0123456789.eE+-truefalsn \n\t';

function mutateText(text) {
  let t = text;
  const ops = 1 + ri(3);
  for (let k = 0; k < ops; k++) {
    const op = ri(7);
    if (!t.length) { t = pick(TOKENS); continue; }
    const pos = ri(t.length + 1);
    if (op === 0) { // replace a char
      const i = ri(t.length);
      t = t.slice(0, i) + CHARS[ri(CHARS.length)] + t.slice(i + 1);
    } else if (op === 1) { // insert a token
      t = t.slice(0, pos) + pick(TOKENS) + t.slice(pos);
    } else if (op === 2) { // delete a slice
      const len = 1 + ri(Math.min(64, t.length));
      t = t.slice(0, pos) + t.slice(pos + len);
    } else if (op === 3) { // duplicate a slice
      const len = 1 + ri(Math.min(128, t.length));
      const slice = t.slice(pos, pos + len);
      t = t.slice(0, pos) + slice + t.slice(pos);
    } else if (op === 4) { // truncate
      t = t.slice(0, ri(t.length + 1));
    } else if (op === 5) { // swap two slices
      const a = ri(t.length), b = ri(t.length), len = 1 + ri(16);
      const sa = t.slice(a, a + len), sb = t.slice(b, b + len);
      t = t.slice(0, Math.min(a, b)) + (a < b ? sb : sa) + t.slice(Math.min(a, b) + len, Math.max(a, b)) + (a < b ? sa : sb) + t.slice(Math.max(a, b) + len);
    } else { // repeat whole input (bounded by MAX_INPUT below)
      t = t + t;
    }
    if (t.length > MAX_INPUT) t = t.slice(0, MAX_INPUT);
  }
  return t;
}

const WEIRD = [null, true, false, 0, -1, 1, 1e308, '', 'x', 'assistant', 'tool', 'role',
  'a'.repeat(5000), [], {}, [null], { role: 'assistant' }, { messages: [] },
  { type: 'tool_use', id: 'x', name: 'Read', input: {} }, ['nested', ['deep', ['deeper']]]];

function collectSlots(v, slots, depth) {
  if (depth > 8 || !v || typeof v !== 'object') return;
  for (const key of Object.keys(v)) {
    slots.push([v, key]);
    collectSlots(v[key], slots, depth + 1);
  }
}

// Structural mutation of a parsed JSON value. Inserted values are deep clones:
// sharing one WEIRD object across slots would let a later op point it at
// itself, manufacturing a cycle — a value JSON text can never encode.
const weird = () => JSON.parse(JSON.stringify(pick(WEIRD)));
function mutateValue(value) {
  let v;
  try { v = JSON.parse(JSON.stringify(value)); } catch { return value; }
  const ops = 1 + ri(3);
  for (let k = 0; k < ops; k++) {
    const slots = [];
    collectSlots(v, slots, 0);
    const op = ri(5);
    if (op === 0 || !slots.length) { // replace the whole value
      v = weird();
    } else if (op === 1) { // replace one node
      const [parent, key] = pick(slots);
      parent[key] = weird();
    } else if (op === 2) { // delete one node
      const [parent, key] = pick(slots);
      if (Array.isArray(parent)) parent.splice(Number(key), 1); else delete parent[key];
    } else if (op === 3) { // duplicate one array (deep clone, never a cycle)
      const arrays = slots.filter(([, key]) => true).map(([p, key2]) => [p, key2]).filter(([p, key2]) => Array.isArray(p[key2]));
      if (arrays.length) { const [p, key2] = pick(arrays); p[key2] = p[key2].concat(JSON.parse(JSON.stringify(p[key2]))); }
    } else { // inject a prototype-flavoured key at the root — as an OWN property,
      // exactly as JSON.parse would create it. Mutations stay inside the JSON
      // value space: a plain assignment to __proto__ would instead rewire the
      // object's prototype, manufacturing values no log file can contain.
      if (v && typeof v === 'object' && !Array.isArray(v))
        Object.defineProperty(v, pick(['__proto__', 'constructor', 'prototype']),
          { value: weird(), enumerable: true, writable: true, configurable: true });
      else v = { wrapped: v };
    }
  }
  return v;
}

// ---------- error classification ----------
// pipeline/claude/replay: ParseError is the controlled rejection; anything else crashes.
// baseline/mcp-call: these validators throw plain Errors by design; a TypeError /
// ReferenceError / RangeError means the code tripped over the input instead.
const PROGRAMMER_ERRORS = new Set(['TypeError', 'ReferenceError', 'RangeError']);
function classify(err, controlled) {
  if (!err) return 'ok';
  if (controlled === 'parse') return err instanceof AAA.ParseError ? 'rejected' : 'crash';
  return PROGRAMMER_ERRORS.has(err.name) ? 'crash' : 'rejected';
}

// ---------- targets ----------
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaa-fuzz-'));
const tmpFile = ext => path.join(tmpDir, `input${ext}`);

const targets = {
  pipeline(input) { // raw text, or a pre-parsed value (parse_trace tolerates both)
    const calls = AAA.parse_trace(input);
    const findings = AAA.run_rules(calls);
    AAA.render_report(findings);
    AAA.verdict(findings, calls);
  },
  claude(value) {
    const msgs = Array.isArray(value) ? value : (value && value.messages);
    if (!Array.isArray(msgs)) return; // outside fromClaudeMessages' contract; skip
    const trace = AAA.fromClaudeMessages(msgs);
    const calls = AAA.parse_trace(trace);
    AAA.run_rules(calls);
  },
  baseline(value) {
    BL.apply_baseline(sampleFindings, value);
    BL.diff_baselines(value, sampleBaseline);
    BL.diff_baselines(sampleBaseline, value);
    BL.accept(value, sampleFinding, 'fuzz iteration');
  },
  'mcp-call'(value) {
    MCP.normalizeCall(value, 0);
  },
  replay(text) {
    const ext = pick(['.json', '.jsonl', '.ndjson']);
    const file = tmpFile(ext);
    fs.writeFileSync(file, text);
    const traces = REPLAY.readTraces(file);
    for (const t of traces.slice(0, 50)) {
      const calls = AAA.parse_trace(t.raw);
      AAA.run_rules(calls);
    }
  },
};
const TARGET_NAMES = Object.keys(targets);
const WEIGHTS = [0.45, 0.15, 0.15, 0.10, 0.15]; // pipeline, claude, baseline, mcp-call, replay
function pickTarget() {
  const r = rand();
  let acc = 0;
  for (let i = 0; i < TARGET_NAMES.length; i++) { acc += WEIGHTS[i]; if (r < acc) return TARGET_NAMES[i]; }
  return TARGET_NAMES[0];
}

// ---------- crash bookkeeping ----------
const crashesDir = path.join(__dirname, 'crashes');
const crashSigs = new Map();
let savedCrashes = 0;
function recordCrash(target, err, reproText) {
  const sig = `${target}|${err.name}|${String(err.message || '').split('\n')[0].slice(0, 120)}`;
  const entry = crashSigs.get(sig) || { count: 0, file: null };
  entry.count++;
  if (!entry.file && savedCrashes < MAX_SAVED_CRASHES) {
    fs.mkdirSync(crashesDir, { recursive: true });
    const file = path.join(crashesDir, `crash-${crashSigs.size + 1}.txt`);
    const stack = String(err.stack || err).split('\n').slice(0, 4).join('\n');
    fs.writeFileSync(file, `${stack}\n--- input ---\n${reproText}`);
    entry.file = path.relative(ROOT, file);
    savedCrashes++;
  }
  crashSigs.set(sig, entry);
}

// ---------- run ----------
const stats = {};
for (const name of TARGET_NAMES) stats[name] = { ok: 0, rejected: 0, crash: 0 };
const started = Date.now();
let ran = 0;
let skipped = 0;

for (let i = 0; i < ITERATIONS; i++) {
  if ((i & 63) === 0 && Date.now() - started > MAX_MS) break;
  const target = pickTarget();
  const seed = pick(seeds);
  // Mutation and repro serialization are harness work: if they throw (e.g. a
  // cyclic value the mutator built), the iteration is skipped — never counted
  // as a target crash.
  let input, reproText;
  try {
    if (target === 'replay' || (target === 'pipeline' && rand() < 0.5)) {
      input = mutateText(seed.text);
      reproText = input;
    } else {
      let parsed;
      try { parsed = JSON.parse(seed.text); } catch { skipped++; continue; } // text-only seed; skip value targets
      input = mutateValue(parsed);
      try { reproText = JSON.stringify(input); } catch { reproText = '(unserializable mutated value)'; }
    }
  } catch { skipped++; continue; }
  try {
    targets[target](input);
    stats[target].ok++;
  } catch (err) {
    const kind = classify(err, target === 'baseline' || target === 'mcp-call' ? 'plain' : 'parse');
    if (kind === 'crash') {
      stats[target].crash++;
      recordCrash(target, err, reproText ?? '');
    } else {
      stats[target].rejected++;
    }
  }
  ran++;
}

try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* temp dir cleanup is best-effort */ }

// ---------- report ----------
const totals = { ok: 0, rejected: 0, crash: 0 };
for (const name of TARGET_NAMES) for (const k of Object.keys(totals)) totals[k] += stats[name][k];
const elapsed = Date.now() - started;

console.log(`fuzz: seed=${SEED} iterations=${ran} elapsed=${elapsed}ms`);
for (const name of TARGET_NAMES) {
  const s = stats[name];
  console.log(`  ${name.padEnd(9)} ok=${s.ok} rejected=${s.rejected} crash=${s.crash}`);
}
console.log(`fuzz: total inputs=${ran} skipped=${skipped} ok=${totals.ok} rejected=${totals.rejected} crashes=${totals.crash} unique-crash-signatures=${crashSigs.size}`);
for (const [sig, entry] of crashSigs) {
  console.log(`  CRASH x${entry.count} ${sig}${entry.file ? ` repro=${entry.file}` : ''}`);
}
if (!QUIET || totals.crash) console.log(totals.crash ? 'fuzz: FAIL — crashes found' : 'fuzz: PASS — no crashes');
process.exit(totals.crash ? 1 : 0);
