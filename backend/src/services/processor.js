const fs = require('fs');
const readline = require('readline');
const { Event, ParsingGap } = require('../models');
const { parseLine } = require('./parsers');

async function processEvidence(evidence) {
  // Re-process safe: sirf derived records hatate hain, original file kabhi touch nahi hoti
  await Event.deleteMany({ evidenceId: evidence._id });
  await ParsingGap.deleteMany({ evidenceId: evidence._id });

  const ctx = {
    logYear: evidence.logYear || new Date().getUTCFullYear(),
    sourceUtcOffsetMinutes: evidence.sourceUtcOffsetMinutes || 0,
    clockSkewSeconds: evidence.clockSkewSeconds || 0,
  };
  const rl = readline.createInterface({ input: fs.createReadStream(evidence.storagePath), crlfDelay: Infinity });

  let lineNumber = 0, total = 0, parsed = 0;
  let events = [], gaps = [];
  const base = { incidentId: evidence.incidentId, evidenceId: evidence._id };
  const flush = async () => {
    if (events.length) await Event.insertMany(events);
    if (gaps.length) await ParsingGap.insertMany(gaps);
    events = []; gaps = [];
  };

  for await (const raw of rl) {
    lineNumber++;
    const line = raw.replace(/\r$/, '');
    if (!line.trim()) continue; // blank lines count nahi hoti
    total++;
    let res;
    try { res = parseLine(evidence.sourceType, line, ctx); }
    catch (err) { res = { error: 'Parser exception: ' + err.message }; }
    if (res.event) { parsed++; events.push({ ...base, lineNumber, rawLine: line, ...res.event }); }
    else gaps.push({ ...base, lineNumber, rawLine: line.slice(0, 1000), reason: res.error });
    if (events.length + gaps.length >= 1000) await flush();
  }
  await flush();

  evidence.processing = {
    status: 'done', totalLines: total, parsedLines: parsed, gapCount: total - parsed,
    coveragePercent: total ? Math.round((parsed / total) * 10000) / 100 : 0,
    processedAt: new Date(),
  };
  await evidence.save();
  return evidence.processing;
}

module.exports = { processEvidence };
