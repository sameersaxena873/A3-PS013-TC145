const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const mongoose = require('mongoose');
const { Incident, Evidence, Event, ParsingGap } = require('./models');
const { sha256File } = require('./services/hashService');
const { processEvidence } = require('./services/processor');
const { analyze } = require('./services/analysis');
const { buildReport } = require('./services/reportService');

const router = express.Router();
const STORE = path.join(__dirname, '..', 'evidence-store');
fs.mkdirSync(STORE, { recursive: true });

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const validId = (id) => mongoose.Types.ObjectId.isValid(id);
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

// ---------- upload config: size limit + extension allow-list; files kabhi execute nahi hoti ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = path.join(STORE, req.params.id);
      fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/[^\w.\-]/g, '_')}`),
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = ['.log', '.txt', ''].includes(path.extname(file.originalname).toLowerCase());
    cb(ok ? null : new Error('Only .log / .txt files are allowed'), ok);
  },
});

// ---------- Incidents ----------
router.post('/incidents', wrap(async (req, res) => {
  if (!req.body.title) return bad(res, 'title is required');
  res.status(201).json(await Incident.create({ title: req.body.title, description: req.body.description }));
}));
router.get('/incidents', wrap(async (req, res) => res.json(await Incident.find().sort({ createdAt: -1 }))));
router.get('/incidents/:id', wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  const inc = await Incident.findById(req.params.id);
  inc ? res.json(inc) : bad(res, 'not found', 404);
}));

// ---------- Evidence ----------
router.post('/incidents/:id/evidence', upload.single('file'), wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  if (!req.file) return bad(res, 'file is required (field name: file)');
  const incident = await Incident.findById(req.params.id);
  if (!incident) { fs.unlinkSync(req.file.path); return bad(res, 'incident not found', 404); }

  const name = req.file.originalname.toLowerCase();
  const sourceType = ['auth', 'web'].includes(req.body.sourceType)
    ? req.body.sourceType : (name.includes('auth') || name.includes('secure') ? 'auth' : 'web');
  const sha256 = await sha256File(req.file.path);
  fs.chmodSync(req.file.path, 0o444); // read-only: original overwrite na ho

  const evidence = await Evidence.create({
    incidentId: incident._id,
    originalFileName: req.file.originalname,
    storagePath: req.file.path,
    sha256, size: req.file.size, sourceType,
    sourceUtcOffsetMinutes: Number(req.body.sourceUtcOffsetMinutes) || 0,
    clockSkewSeconds: Number(req.body.clockSkewSeconds) || 0,
    logYear: Number(req.body.logYear) || new Date().getUTCFullYear(),
  });
  res.status(201).json(evidence);
}));

router.get('/incidents/:id/evidence', wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  res.json(await Evidence.find({ incidentId: req.params.id }).sort({ collectedAt: 1 }));
}));

router.post('/evidence/:id/process', wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  const ev = await Evidence.findById(req.params.id);
  if (!ev) return bad(res, 'not found', 404);
  // optional: process se pehle skew/offset update kar sakte ho
  for (const k of ['clockSkewSeconds', 'sourceUtcOffsetMinutes', 'logYear'])
    if (req.body && req.body[k] !== undefined && req.body[k] !== '') ev[k] = Number(req.body[k]);
  res.json(await processEvidence(ev));
}));

async function verify(ev) {
  const current = await sha256File(ev.storagePath).catch(() => null);
  ev.verification = { status: current === ev.sha256 ? 'verified' : 'failed', lastVerifiedAt: new Date(), currentSha256: current };
  await ev.save();
  return ev.verification;
}
router.post('/evidence/:id/verify', wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  const ev = await Evidence.findById(req.params.id);
  if (!ev) return bad(res, 'not found', 404);
  const v = await verify(ev);
  res.json({ status: v.status, lastVerifiedAt: v.lastVerifiedAt, currentSha256: v.currentSha256, originalSha256: ev.sha256 });
}));

// ---------- Timeline / gaps / analysis ----------
router.get('/incidents/:id/timeline', wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  const { q, ip, username, start, end, eventType, evidenceId } = req.query;
  const page = Math.max(1, Number(req.query.page) || 1);
  const limit = Math.min(500, Number(req.query.limit) || 100);
  const f = { incidentId: req.params.id };
  if (ip) f.sourceIp = ip;
  if (username) f.username = username;
  if (eventType) f.eventType = eventType;
  if (evidenceId && validId(evidenceId)) f.evidenceId = evidenceId;
  if (start || end) {
    f.normalizedTimestamp = {};
    if (start) f.normalizedTimestamp.$gte = new Date(start);
    if (end) f.normalizedTimestamp.$lte = new Date(end);
  }
  if (q) f.$or = [{ rawLine: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } }];
  const [items, total] = await Promise.all([
    Event.find(f).sort({ normalizedTimestamp: 1, lineNumber: 1 }).skip((page - 1) * limit).limit(limit),
    Event.countDocuments(f),
  ]);
  res.json({ total, page, limit, items });
}));

router.get('/incidents/:id/gaps', wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  res.json(await ParsingGap.find({ incidentId: req.params.id }).sort({ evidenceId: 1, lineNumber: 1 }).limit(1000));
}));

router.get('/incidents/:id/analysis', wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  const events = await Event.find({ incidentId: req.params.id }).sort({ normalizedTimestamp: 1 }).lean();
  res.json(analyze(events));
}));

// ---------- Report (HTML; browser se Print -> Save as PDF) ----------
router.get('/incidents/:id/report', wrap(async (req, res) => {
  if (!validId(req.params.id)) return bad(res, 'invalid id');
  const incident = await Incident.findById(req.params.id);
  if (!incident) return bad(res, 'not found', 404);
  const evidence = await Evidence.find({ incidentId: incident._id });
  for (const ev of evidence) await verify(ev); // export se pehle hash dobara verify
  const events = await Event.find({ incidentId: incident._id }).sort({ normalizedTimestamp: 1 }).limit(2001).lean();
  const gaps = await ParsingGap.find({ incidentId: incident._id }).limit(500).lean();
  const all = await Event.find({ incidentId: incident._id }).sort({ normalizedTimestamp: 1 }).lean();
  const html = buildReport({
    incident, evidence, gaps, findings: analyze(all),
    events: events.slice(0, 2000), truncated: events.length > 2000,
  });
  res.type('html').send(html);
}));

module.exports = router;
