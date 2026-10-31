// Run: npm run selftest   (MongoDB ki zarurat nahi)
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { parseLine } = require('./services/parsers');
const { analyze } = require('./services/analysis');

const DATA = path.join(__dirname, '..', '..', 'test-data');
function run(file, type, ctx) {
  const lines = fs.readFileSync(path.join(DATA, file), 'utf8').split('\n').filter((l) => l.trim());
  const events = [], gaps = [];
  lines.forEach((l, i) => {
    const r = parseLine(type, l, ctx);
    if (r.event) events.push({ ...r.event, lineNumber: i + 1 }); else gaps.push({ line: l, reason: r.error });
  });
  events.sort((a, b) => a.normalizedTimestamp - b.normalizedTimestamp);
  return { total: lines.length, events, gaps, coverage: +(events.length / lines.length * 100).toFixed(2) };
}
const base = { logYear: 2026, sourceUtcOffsetMinutes: 0, clockSkewSeconds: 0 };

// Scenario 1
const s1 = run('scenario-1/auth.log', 'auth', base);
console.log('S1 coverage', s1.coverage + '%', 'gaps', s1.gaps.length);
assert.strictEqual(s1.gaps.length, 2);
const f1 = analyze(s1.events);
assert(f1.some((f) => f.type === 'ssh_bruteforce_then_success' && f.sourceIp === '203.0.113.45'));
const idxFail = s1.events.findIndex((e) => e.eventType === 'failed_login');
const idxOk = s1.events.findIndex((e) => e.eventType === 'successful_login' && e.sourceIp === '203.0.113.45');
assert(idxFail < idxOk, 'failed attempts must precede success');

// Scenario 2
const s2 = run('scenario-2/access.log', 'web', base);
console.log('S2 coverage', s2.coverage + '%', 'gaps', s2.gaps.length);
assert.strictEqual(s2.gaps.length, 1);
assert.strictEqual(s2.events.filter((e) => e.eventType === 'sql_injection_attempt').length, 4);
assert.strictEqual(s2.events.filter((e) => e.eventType === 'path_scan').length, 6);
assert.strictEqual(s2.events.filter((e) => e.eventType === 'http_request').length, 5);

// Scenario 3: raw order wrong, corrected order right
const a = (skew) => run('scenario-3/auth_serverA.log', 'auth', { ...base, clockSkewSeconds: skew }).events;
const b = run('scenario-3/access_serverB.log', 'web', base).events;
const order = (arr) => arr.sort((x, y) => x.normalizedTimestamp - y.normalizedTimestamp).map((e) => e.sourceType).join(',');
const before = order([...a(0), ...b]);
const after = order([...a(120), ...b]);
console.log('S3 before correction:', before, '\nS3 after  correction:', after);
assert.notStrictEqual(before, after);
assert.strictEqual(after, 'web,auth,web,auth,web');

// Timezone offset (+05:30) check
const r = parseLine('auth', 'Oct 20 15:30:00 h sshd[1]: Failed password for x from 1.2.3.4 port 22 ssh2', { ...base, sourceUtcOffsetMinutes: 330 });
assert.strictEqual(r.event.normalizedTimestamp.toISOString(), '2026-10-20T10:00:00.000Z');
console.log('ALL SELF TESTS PASSED');
