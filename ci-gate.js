#!/usr/bin/env node
'use strict';
// CI adapter only. All finding logic remains in the shared engine.
const fs = require('node:fs');
const path = require('node:path');
const AAA = require('./rules.js');
const BL = require('./baseline.js');
const escapeData = s => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escapeProperty = s => escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
const levels = { HIGH: 3, MEDIUM: 2, LOW: 1 };
// Deliberately restricted YAML: flat severity/baseline and inline or block rules list.
// Reject unsupported syntax rather than silently misconfigure an enforcement gate.
function readConfig(file) {
  const config = { severity: 'HIGH', rules: null, baseline: null };
  if (!file) return config;
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  const seen = new Set();
  let inRules = false;
  const scalar = value => {
    const s = value.trim();
    if (/^"[^"\\]*"$/.test(s) || /^'[^']*'$/.test(s)) return s.slice(1, -1);
    if (!s || /[{}\[\]&*!|>#]/.test(s)) throw new Error('unsupported .auditor.yml scalar');
    return s;
  };
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const item = line.match(/^\s+-\s+(\S+)\s*$/);
    if (item && inRules) { config.rules.push(scalar(item[1])); continue; }
    const pair = line.match(/^(severity|rules|baseline):\s*(.*?)\s*$/);
    if (!pair || seen.has(pair[1])) throw new Error('unknown, duplicated, or unsupported .auditor.yml setting');
    const [, key, value] = pair;
    seen.add(key); inRules = key === 'rules';
    if (key === 'rules') {
      if (!value) config.rules = [];
      else {
        if (!/^\[.*\]$/.test(value)) throw new Error('rules must be an inline or block list');
        config.rules = value.slice(1, -1).trim() ? value.slice(1, -1).split(',').map(scalar) : [];
      }
    } else config[key] = scalar(value);
  }
  if (!levels[config.severity]) throw new Error('severity must be HIGH, MEDIUM, or LOW');
  if (config.rules && config.rules.some(r => !AAA.RULE_IDS.includes(r)))
    throw new Error(`rules must contain only ${AAA.RULE_IDS[0]} through ${AAA.RULE_IDS[AAA.RULE_IDS.length - 1]}`);
  return config;
}
function processFile(filePath, config, baseline) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const events = AAA.parse_trace(raw);
  const all = AAA.run_rules(events);
  const selected = all.filter(f => !config.rules || config.rules.includes(f.rule));
  selected.stats = all.stats;
  const findings = BL.apply_baseline(selected, baseline);
  const report = AAA.render_report(findings);
  console.log(`${filePath}: ${report.headline}`);
  for (const line of report.lines) console.log(line);
  for (const f of findings) {
    const line = f.call_id ? raw.split('\n').findIndex(l => l.includes(JSON.stringify(f.call_id))) + 1 : 1;
    const kind = f.severity === 'HIGH' ? 'error' : 'warning';
    console.log(`::${kind} file=${escapeProperty(filePath.replace(/\\\\/g, '/'))},line=${Math.max(1, line)},title=${escapeProperty(f.rule)}::${escapeData(f.title)}`);
  }
  return findings.some(f => levels[f.severity] >= levels[config.severity]) ? 10 : 0;
}
function run(argv) {
  const i = argv.indexOf('--trace');
  if (i < 0 || !argv[i + 1]) throw new Error('usage: node ci-gate.js --trace <trace.json|trace_dir> [--config .auditor.yml]');
  const c = argv.indexOf('--config');
  if (c >= 0 && !argv[c + 1]) throw new Error('--config requires a path');
  const configFile = c >= 0 ? argv[c + 1] : (fs.existsSync('.auditor.yml') ? '.auditor.yml' : null);
  const config = readConfig(configFile);
  let baseline = BL.empty();
  if (config.baseline) {
    const baselineFile = path.resolve(path.dirname(configFile), config.baseline);
    baseline = JSON.parse(fs.readFileSync(baselineFile, 'utf8'));
    if (baseline.version !== 1 || !Array.isArray(baseline.entries) || baseline.entries.some(e =>
      !e || typeof e.rule !== 'string' || !AAA.RULE_IDS.includes(e.rule) || typeof e.fingerprint !== 'string' ||
      !new RegExp('^' + e.rule + ':[a-f0-9]{8}$').test(e.fingerprint) || typeof e.reason !== 'string' || !e.reason.trim()))
      throw new Error('invalid baseline: version 1 and fingerprint/rule/non-empty reason entries required');
  }
  const tracePath = argv[i + 1];
  const stat = fs.statSync(tracePath);
  if (stat.isDirectory()) {
    const jsonFiles = fs.readdirSync(tracePath)
      .filter(f => f.endsWith('.json'))
      .map(f => path.join(tracePath, f))
      .sort();
    if (jsonFiles.length === 0) throw new Error('no .json files found in trace directory');
    let maxExit = 0;
    for (const f of jsonFiles) { const code = processFile(f, config, baseline); if (code > maxExit) maxExit = code; }
    return maxExit;
  }
  return processFile(tracePath, config, baseline);
}
if (require.main === module) {
  try { process.exitCode = run(process.argv.slice(2)); }
  catch (e) { console.error(`::error::${escapeData(e.message)}`); process.exitCode = 2; }
}
module.exports = { run };
