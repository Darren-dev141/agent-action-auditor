'use strict';

const MAX_STDIN_BYTES = 1024 * 1024;

function readStdin(callback) {
  const chunks = [];
  let bytes = 0;
  let settled = false;
  const finish = (error, text = '') => {
    if (settled) return;
    settled = true;
    callback(error, text);
  };
  process.stdin.on('data', chunk => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buf.length;
    if (bytes > MAX_STDIN_BYTES) {
      process.stdin.pause();
      finish(new Error('hook input exceeds 1 MiB'));
      return;
    }
    chunks.push(buf);
  });
  process.stdin.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
  process.stdin.on('error', () => finish(new Error('could not read hook input')));
}

module.exports = { readStdin, MAX_STDIN_BYTES };
