#!/usr/bin/env node
'use strict';
// One verdict per trace in examples/. Parsing and rules stay in audit.js.
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const dir = path.join(root, 'examples');
let names;
try {
  names = fs.readdirSync(dir).filter(name => name.endsWith('.json')).sort();
} catch (e) {
  console.error(`ERROR: could not read examples/: ${e.message}`);
  process.exit(2);
}
if (names.length === 0) {
  console.error('ERROR: no traces in examples/');
  process.exit(2);
}

let bad = false;
for (const name of names) {
  const result = spawnSync(process.execPath, [path.join(root, 'audit.js'), path.join(dir, name)], {
    cwd: root,
    encoding: 'utf8',
  });
  const status = result.status == null ? 2 : result.status;
  const lines = (result.stdout || '').split(/\r?\n/).filter(line => line.length > 0);
  console.log(`examples/${name}\texit ${status}\t${lines[0] || '(no output)'}`);
  for (const line of lines.slice(1)) console.log(`\t${line}`);
  if (result.stderr && result.stderr.trim()) {
    console.error(result.stderr.trim());
    bad = true;
  }
  if (status === 2) bad = true;
}
process.exit(bad ? 2 : 0);
