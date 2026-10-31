const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function buildReport({ incident, evidence, events, gaps, findings, truncated }) {
  const rows = events.map((e) => `<tr><td>${esc(new Date(e.normalizedTimestamp).toISOString())}</td><td>${esc(e.originalTimestamp)}</td>
    <td>${esc(e.sourceType)}</td><td>${esc(e.eventType)}</td><td>${esc(e.sourceIp)}</td><td>${esc(e.username)}</td><td>${esc(e.details)}</td></tr>`).join('');
  const evRows = evidence.map((v) => `<tr><td>${esc(v.originalFileName)}</td><td>${esc(v.sourceType)}</td>
    <td class="mono">${esc(v.sha256)}</td><td>${esc(v.size)}</td><td>${esc(v.verification?.status)}</td>
    <td>${esc(v.clockSkewSeconds)}s / UTC${v.sourceUtcOffsetMinutes >= 0 ? '+' : ''}${esc(v.sourceUtcOffsetMinutes)}m</td>
    <td>${esc(v.processing?.coveragePercent ?? '-')}% (${esc(v.processing?.parsedLines ?? '-')}/${esc(v.processing?.totalLines ?? '-')})</td></tr>`).join('');
  const fRows = findings.length
    ? findings.map((f) => `<tr><td class="sev-${esc(f.severity)}">${esc(f.severity)}</td><td>${esc(f.title)}</td><td>${esc(f.detail)}</td></tr>`).join('')
    : '<tr><td colspan="3">No rule-based findings.</td></tr>';
  const gRows = gaps.length
    ? gaps.map((g) => `<tr><td>${esc(g.lineNumber)}</td><td>${esc(g.reason)}</td><td class="mono">${esc(g.rawLine)}</td></tr>`).join('')
    : '<tr><td colspan="3">No parsing gaps.</td></tr>';
  return `<!doctype html><html><head><meta charset="utf-8"><title>Incident Report - ${esc(incident.title)}</title>
<style>body{font-family:Arial,sans-serif;margin:32px;color:#111}h1{margin-bottom:0}table{border-collapse:collapse;width:100%;margin:8px 0 24px;font-size:12px}
th,td{border:1px solid #bbb;padding:5px 7px;text-align:left;vertical-align:top}th{background:#eee}.mono{font-family:monospace;word-break:break-all}
.sev-high{color:#b00020;font-weight:bold}.sev-medium{color:#b26a00;font-weight:bold}.note{font-size:12px;color:#555}@media print{button{display:none}}</style></head><body>
<button onclick="window.print()">Print / Save as PDF</button>
<h1>Incident Report: ${esc(incident.title)}</h1>
<p class="note">Status: ${esc(incident.status)} | Generated (UTC): ${new Date().toISOString()}<br>${esc(incident.description)}</p>
<h2>1. Evidence &amp; integrity (hashes re-verified at report time)</h2>
<table><tr><th>File</th><th>Type</th><th>SHA-256</th><th>Bytes</th><th>Verification</th><th>Skew / Offset</th><th>Parsing coverage</th></tr>${evRows}</table>
<p class="note">A matching hash shows the stored file is unchanged since collection; it does not by itself prove the file was authentic when collected.</p>
<h2>2. Rule-based findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr>${fRows}</table>
<h2>3. Unified timeline (UTC)${truncated ? ' - first 2000 events shown' : ''}</h2>
<table><tr><th>UTC time</th><th>Original</th><th>Source</th><th>Event</th><th>IP</th><th>User</th><th>Details</th></tr>${rows}</table>
<h2>4. Parsing gaps</h2><table><tr><th>Line</th><th>Reason</th><th>Raw line</th></tr>${gRows}</table>
</body></html>`;
}
module.exports = { buildReport };
