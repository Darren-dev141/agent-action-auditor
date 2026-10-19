// @ts-check
/* Agent Action Auditor — V2-3 baselines & suppression (SPEC §13 D15). Classic script, no import/export.
   Browser: window.AAA_BASELINE.  Node: require('./baseline.js').
   Baseline file (.auditor-baseline.json, versioned in git):
     { "version": 1, "entries": [ { "fingerprint", "rule", "reason", "added" } ] }
   Suppressed findings are collapsed in the report, never silently dropped. */
(function (root) {
  'use strict';

  /**
   * @typedef {Object} BaselineEntry
   * @property {string} fingerprint
   * @property {string} rule
   * @property {string} reason
   * @property {string} [added]
   */
  /**
   * @typedef {Object} Baseline
   * @property {number} version
   * @property {BaselineEntry[]} entries
   */
  /**
   * A findings array carrying the baseline outcome (the D15 seam shape).
   * @typedef {Array<any> & { suppressed?: any[], stats?: any }} FindingsWithBaseline
   */

  const empty = () => ({ version: 1, entries: [] });
  // A baseline arrives from disk / an MCP client: entries may be missing or not
  // an array at all. Anything that is not an array of entries is no entries.
  const entriesOf = b => (b && Array.isArray(b.entries)) ? b.entries : [];
  const clone = b => ({ version: (b && b.version) || 1, entries: entriesOf(b).map(e => Object.assign({}, e)) });

  // apply_baseline(findings, baseline) -> active[]  with .suppressed[] and .stats carried over
  /**
   * @param {FindingsWithBaseline} findings
   * @param {Baseline} baseline
   * @returns {FindingsWithBaseline}
   */
  function apply_baseline(findings, baseline) {
    const known = new Set(entriesOf(baseline).map(e => e && e.fingerprint));
    const active = /** @type {FindingsWithBaseline} */ (findings.filter(f => !known.has(f.fingerprint)));
    active.suppressed = findings.filter(f => known.has(f.fingerprint));
    active.stats = findings.stats;
    return active;
  }

  // accept(baseline, finding, reason) -> new baseline. A reason is mandatory: an unexplained
  // suppression is how a real violation gets waved through forever.
  /**
   * @param {Baseline} baseline
   * @param {{ fingerprint: string, rule: string }} finding
   * @param {string} reason
   * @returns {Baseline}
   */
  function accept(baseline, finding, reason) {
    if (typeof reason !== 'string' || !reason.trim()) throw new Error('accept: a non-empty reason is required');
    if (!finding || !finding.fingerprint) throw new Error('accept: finding has no fingerprint');
    const next = clone(baseline || empty());
    if (!next.entries.some(e => e.fingerprint === finding.fingerprint))
      next.entries.push({ fingerprint: finding.fingerprint, rule: finding.rule, reason: reason.trim(), added: new Date().toISOString() });
    return next;
  }

  // diff_baselines(a, b) -> {added, removed}  (what b has that a lacks, and vice versa)
  /**
   * @param {Baseline} a
   * @param {Baseline} b
   * @returns {{ added: BaselineEntry[], removed: BaselineEntry[] }}
   */
  function diff_baselines(a, b) {
    const fa = new Set(entriesOf(a).map(e => e && e.fingerprint));
    const fb = new Set(entriesOf(b).map(e => e && e.fingerprint));
    return {
      added: entriesOf(b).filter(e => !fa.has(e && e.fingerprint)),
      removed: entriesOf(a).filter(e => !fb.has(e && e.fingerprint)),
    };
  }

  const api = { apply_baseline, accept, diff_baselines, empty };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else /** @type {any} */ (root).AAA_BASELINE = api;
})(typeof window !== 'undefined' ? window : this);
