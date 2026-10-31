// Simple, explainable detection rules over normalized events (time-sorted)
function analyze(events) {
  const findings = [];
  const failsByIp = {};
  for (const e of events) {
    if (e.eventType === 'failed_login' && e.sourceIp) (failsByIp[e.sourceIp] ||= []).push(e);
  }
  for (const [ip, fails] of Object.entries(failsByIp)) {
    if (fails.length < 5) continue;
    const first = fails[0];
    const success = events.find((e) => e.eventType === 'successful_login' && e.sourceIp === ip &&
      new Date(e.normalizedTimestamp) >= new Date(first.normalizedTimestamp));
    findings.push({
      severity: success ? 'high' : 'medium',
      type: success ? 'ssh_bruteforce_then_success' : 'ssh_bruteforce',
      sourceIp: ip,
      title: success ? `SSH brute force followed by successful login from ${ip}` : `Repeated SSH failures from ${ip}`,
      detail: `${fails.length} failed logins starting ${new Date(first.normalizedTimestamp).toISOString()}` +
        (success ? `; successful login as "${success.username}" at ${new Date(success.normalizedTimestamp).toISOString()}` : ''),
    });
  }
  const sqliByIp = {}, scanByIp = {};
  for (const e of events) {
    if (!e.sourceIp) continue;
    if (e.eventType === 'sql_injection_attempt') sqliByIp[e.sourceIp] = (sqliByIp[e.sourceIp] || 0) + 1;
    if (e.eventType === 'path_scan') scanByIp[e.sourceIp] = (scanByIp[e.sourceIp] || 0) + 1;
  }
  for (const [ip, n] of Object.entries(sqliByIp))
    findings.push({ severity: 'high', type: 'sqli', sourceIp: ip, title: `SQL-injection-like requests from ${ip}`, detail: `${n} suspicious request(s)` });
  for (const [ip, n] of Object.entries(scanByIp))
    if (n >= 3) findings.push({ severity: 'medium', type: 'path_scan', sourceIp: ip, title: `Path scanning from ${ip}`, detail: `${n} requests to sensitive/admin paths` });
  return findings;
}
module.exports = { analyze };
