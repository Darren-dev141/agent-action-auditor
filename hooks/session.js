// @ts-check
// V2-1 hook support: Claude Code payload → engine call shape, plus bounded,
// private per-session memory so live R1 can see earlier reads.
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const AAA = require('../rules.js');

const NAME_MAP = AAA.TOOL_NAME_MAP;
const MAX_SESSION_BYTES = 1024 * 1024;
const MAX_SESSION_ENTRIES = 2000;

/**
 * @param {any} payload Claude Code hook payload ({tool_name, tool_input} or {tool, args} shapes)
 * @param {number} index position in the session's call sequence
 * @returns {any} engine Call shape (see rules.js)
 */
function toCall(payload, index) {
  const raw = payload.tool_name || (payload.tool && payload.tool.name) || '';
  const name = AAA.mapName(raw);
  let args = payload.tool_input || payload.args || {};
  if (typeof args === 'string') { try { args = JSON.parse(args); } catch { args = { value: args }; } }
  args = AAA.mapArgs(args);
  const rawArgs = JSON.stringify(args);
  return { id: `live_${index}`, index, tool: name, name, args, rawArgs, output: null, result: null };
}

const redact = AAA.redactSecrets;
const dir = () => process.env.AAA_SESSION_DIR || path.join(os.tmpdir(), 'aaa-sessions');
const sessionKey = id => crypto.createHash('sha256').update(String(id)).digest('hex');
const fileFor = id => path.join(dir(), sessionKey(id) + '.jsonl');

function secureDir() {
  const d = dir();
  fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(d);
  if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('unsafe session directory');
  try { fs.chmodSync(d, 0o700); } catch { /* Windows ACLs are outside Node mode bits. */ }
}

function safeExistingFile(file) {
  const before = fs.lstatSync(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > MAX_SESSION_BYTES)
    throw new Error('unsafe session file');
  const fd = fs.openSync(file, fs.constants.O_RDWR | fs.constants.O_APPEND);
  const after = fs.fstatSync(fd);
  if (!after.isFile() || after.nlink !== 1 || (before.ino && after.ino && before.ino !== after.ino)) {
    fs.closeSync(fd);
    throw new Error('session file changed during open');
  }
  return fd;
}

function openForAppend(file) {
  secureDir();
  try { return fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600); }
  catch (e) { if (e.code !== 'EEXIST') throw e; return safeExistingFile(file); }
}

/**
 * @param {string} id session_id (hashed before use as a filename, D23)
 * @returns {any[]} prior calls for the session, oldest first
 */
function load(id) {
  if (!id) return [];
  try {
    secureDir();
    const file = fileFor(id);
    if (!fs.existsSync(file)) return [];
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1 || st.size > MAX_SESSION_BYTES) return [];
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    if (lines.length > MAX_SESSION_ENTRIES) return [];
    return lines.map((ln, i) => {
      const r = JSON.parse(ln);
      const args = AAA.mapArgs(r.args);
      return { id: `live_${i}`, index: i, tool: r.name, name: r.name, args, rawArgs: JSON.stringify(args), output: null, result: null };
    });
  } catch { return []; }
}

/**
 * @param {string} id session_id
 * @param {any} call engine Call shape; args are redacted before write
 */
function append(id, call) {
  if (!id) return;
  const args = JSON.parse(redact(JSON.stringify(call.args)));
  const line = JSON.stringify({ name: call.name, args }) + '\n';
  const file = fileFor(id);
  const fd = openForAppend(file);
  try {
    const st = fs.fstatSync(fd);
    if (st.size + Buffer.byteLength(line) > MAX_SESSION_BYTES) throw new Error('session memory limit reached');
    fs.writeSync(fd, line, null, 'utf8');
    try { fs.fchmodSync(fd, 0o600); } catch { /* Windows ACLs are outside Node mode bits. */ }
  } finally { fs.closeSync(fd); }
}

module.exports = { toCall, load, append, redact, fileFor, sessionKey, NAME_MAP, MAX_SESSION_BYTES, MAX_SESSION_ENTRIES };
