/* Agent Action Auditor — V2-3 baselines & suppression (SPEC §13 D15). Classic script, no import/export.
   Browser: window.AAA_BASELINE.  Node: require('./baseline.js').
   Baseline file (.auditor-baseline.json, versioned in git):
     { "version": 1, "entries": [ { "fingerprint", "rule", "reason", "added" } ] }
   Suppressed findings are collapsed in the report, never silently dropped. */
(function (root) {
  'use strict';

  const empty = () => ({ version: 1, entries: [] });
  const clone = b => ({ version: (b && b.version) || 1, entries: ((b && b.entries) || []).map(e => Object.assign({}, e)) });

  // apply_baseline(findings, baseline) -> active[]  with .suppressed[] and .stats carried over
  function apply_baseline(findings, baseline) {
    const known = new Set(((baseline && baseline.entries) || []).map(e => e.fingerprint));
    const active = findings.filter(f => !known.has(f.fingerprint));
    active.suppressed = findings.filter(f => known.has(f.fingerprint));
    active.stats = findings.stats;
    return active;
  }

  // accept(baseline, finding, reason) -> new baseline. A reason is mandatory: an unexplained
  // suppression is how a real violation gets waved through forever.
  function accept(baseline, finding, reason) {
    if (typeof reason !== 'string' || !reason.trim()) throw new Error('accept: a non-empty reason is required');
    if (!finding || !finding.fingerprint) throw new Error('accept: finding has no fingerprint');
    const next = clone(baseline || empty());
    if (!next.entries.some(e => e.fingerprint === finding.fingerprint))
      next.entries.push({ fingerprint: finding.fingerprint, rule: finding.rule, reason: reason.trim(), added: new Date().toISOString() });
    return next;
  }

  // diff_baselines(a, b) -> {added, removed}  (what b has that a lacks, and vice versa)
  function diff_baselines(a, b) {
    const fa = new Set(((a && a.entries) || []).map(e => e.fingerprint));
    const fb = new Set(((b && b.entries) || []).map(e => e.fingerprint));
    return {
      added: ((b && b.entries) || []).filter(e => !fa.has(e.fingerprint)),
      removed: ((a && a.entries) || []).filter(e => !fb.has(e.fingerprint)),
    };
  }

  const api = { apply_baseline, accept, diff_baselines, empty };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.AAA_BASELINE = api;
})(typeof window !== 'undefined' ? window : this);
