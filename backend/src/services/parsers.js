// Pure functions - DB ke bina test ho sakte hain (node src/selftest.js)
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

const AUTH_RE = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[\d+\])?:\s+(.*)$/;
const WEB_RE = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/;
const WEB_TS_RE = /^(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/;

const SQLI_RE = /(union(\s|\+|%20)+select|select.+from|or\s+1=1|'\s*or\s*'|--\s|--$|sleep\(|benchmark\(|information_schema|xp_cmdshell|%27)/i;
const SCAN_RE = /(\/\.env|\/\.git|\/wp-login|\/wp-admin|\/phpmyadmin|\/admin|\/config\.php|\/etc\/passwd|\.\.\/|\.\.%2f)/i;

function validDate(ms, y, mo, d) {
  const dt = new Date(ms);
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo && dt.getUTCDate() === d;
}

function classifyAuth(msg) {
  let m;
  if ((m = msg.match(/^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/)))
    return { eventType: 'failed_login', username: m[2], sourceIp: m[3], details: `Failed ${m[1]} login for ${m[2]} from ${m[3]}` };
  if ((m = msg.match(/^Accepted (\S+) for (\S+) from (\S+) port (\d+)/)))
    return { eventType: 'successful_login', username: m[2], sourceIp: m[3], details: `Accepted ${m[1]} login for ${m[2]} from ${m[3]}` };
  if ((m = msg.match(/^Invalid user (\S+) from (\S+)/)))
    return { eventType: 'invalid_user', username: m[1], sourceIp: m[2], details: `Invalid user ${m[1]} from ${m[2]}` };
  const ip = (msg.match(/(\d{1,3}(?:\.\d{1,3}){3})/) || [])[1];
  return { eventType: 'other', sourceIp: ip, details: msg.slice(0, 200) };
}

function parseAuthLine(line, ctx) {
  const m = line.match(AUTH_RE);
  if (!m) return { error: 'Line does not match syslog (auth.log) format' };
  const [, mon, day, hh, mm, ss, host, proc, msg] = m;
  if (!(mon in MONTHS)) return { error: `Unknown month "${mon}"` };
  const y = ctx.logYear, mo = MONTHS[mon], d = Number(day);
  if (Number(hh) > 23 || Number(mm) > 59 || Number(ss) > 59) return { error: 'Invalid time value' };
  const localMs = Date.UTC(y, mo, d, Number(hh), Number(mm), Number(ss));
  if (!validDate(localMs, y, mo, d)) return { error: 'Invalid calendar date' };
  const utcMs = localMs - ctx.sourceUtcOffsetMinutes * 60000 - ctx.clockSkewSeconds * 1000;
  const c = classifyAuth(msg);
  return {
    event: {
      originalTimestamp: `${mon} ${day} ${hh}:${mm}:${ss}`,
      normalizedTimestamp: new Date(utcMs),
      sourceType: 'auth',
      ...c,
      details: `[${host} ${proc}] ${c.details}`,
    },
  };
}

function parseWebLine(line, ctx) {
  const m = line.match(WEB_RE);
  if (!m) return { error: 'Line does not match Nginx/Apache combined log format' };
  const [, ip, user, ts, method, rawPath, status, , , agent] = m;
  const t = ts.match(WEB_TS_RE);
  if (!t) return { error: `Bad timestamp "${ts}"` };
  const [, dd, mon, yyyy, hh, mi, ss, sign, oh, om] = t;
  if (!(mon in MONTHS)) return { error: `Unknown month "${mon}"` };
  const y = Number(yyyy), mo = MONTHS[mon], d = Number(dd);
  const localMs = Date.UTC(y, mo, d, Number(hh), Number(mi), Number(ss));
  if (!validDate(localMs, y, mo, d)) return { error: 'Invalid calendar date' };
  const offMin = (sign === '-' ? -1 : 1) * (Number(oh) * 60 + Number(om));
  const utcMs = localMs - offMin * 60000 - ctx.clockSkewSeconds * 1000; // web log ka apna offset use hota hai
  let decoded = rawPath;
  try { decoded = decodeURIComponent(rawPath); } catch (_) { /* malformed encoding */ }
  let eventType = 'http_request';
  if (SQLI_RE.test(rawPath) || SQLI_RE.test(decoded)) eventType = 'sql_injection_attempt';
  else if (SCAN_RE.test(decoded)) eventType = 'path_scan';
  return {
    event: {
      originalTimestamp: ts,
      normalizedTimestamp: new Date(utcMs),
      sourceType: 'web',
      sourceIp: ip,
      username: user === '-' ? undefined : user,
      eventType,
      method,
      path: rawPath.slice(0, 500),
      statusCode: Number(status),
      details: `${method} ${decoded.slice(0, 200)} -> ${status}${agent ? ' | ' + agent.slice(0, 60) : ''}`,
    },
  };
}

function parseLine(sourceType, line, ctx) {
  return sourceType === 'auth' ? parseAuthLine(line, ctx) : parseWebLine(line, ctx);
}

module.exports = { parseLine, parseAuthLine, parseWebLine };
