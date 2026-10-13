#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const SKIP_DIRS = new Set(['.git', 'node_modules', 'real-traces']);
const SKIP_FILES = new Set(['package-lock.json']);
const FORBIDDEN = new Set(['.agents', '.claude', 'checkpoints', 'skills-lock.json']);
const TEXT_EXT = new Set(['', '.js', '.json', '.jsonl', '.md', '.html', '.css', '.svg', '.yml', '.yaml', '.txt']);
const checks = [
  ['credential-shaped value', /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|sk_live_[A-Za-z0-9]{24,}|(?:^|[^A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]+PRIVATE KEY-----/g],
  ['personal or machine-specific path', /C:[/\\]Users[/\\][^/\\\s"']+|\/home\/[^/\s"']+/gi],
  ['internal collaboration reference', new RegExp('\\b(?:aj' + 'big|agent-' + 'board|p' + 'mid)\\b', 'gi')],
  ['private file URL', new RegExp("https?://(?:mu" + "se\\.ai/files|[^\\s\"']*tail" + "net[^\\s\"']*)", 'gi')]
];

const findings = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    const rel = path.relative(ROOT, full).replace(/\\/g, '/');
    if (FORBIDDEN.has(entry.name)) findings.push(`${rel}: forbidden internal artifact`);
    const st = fs.lstatSync(full);
    if (st.isSymbolicLink()) { findings.push(`${rel}: symlink not allowed in release tree`); continue; }
    if (entry.isDirectory()) { walk(full); continue; }
    if (SKIP_FILES.has(entry.name) || !TEXT_EXT.has(path.extname(entry.name).toLowerCase())) continue;
    const text = fs.readFileSync(full, 'utf8');
    for (const [label, re] of checks) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        const line = text.slice(0, m.index).split(/\r?\n/).length;
        findings.push(`${rel}:${line}: ${label}`);
        if (m[0].length === 0) re.lastIndex++;
      }
    }
  }
}
walk(ROOT);

const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
if (!pkg.private && pkg.license === 'UNLICENSED') findings.push('package.json: public package cannot be UNLICENSED');
if (process.env.AAA_PUBLIC_RELEASE === '1') {
  if (pkg.private) findings.push('package.json: public release must set private=false');
  if (!fs.existsSync(path.join(ROOT, 'LICENSE'))) findings.push('LICENSE: required for public release');
  if (!fs.existsSync(path.join(ROOT, 'server.json'))) findings.push('server.json: required before MCP Registry publication');
}

if (findings.length) {
  console.error(`SECURITY SCAN FAILED (${findings.length})`);
  for (const f of findings) console.error(`- ${f}`);
  process.exit(1);
}
console.log('SECURITY SCAN CLEAN');
