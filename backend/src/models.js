const mongoose = require('mongoose');
const { Schema } = mongoose;

const Incident = mongoose.model('Incident', new Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String, default: '' },
  status: { type: String, enum: ['open', 'investigating', 'closed'], default: 'open' },
  createdBy: { type: String, default: 'analyst' },
}, { timestamps: true }));

const Evidence = mongoose.model('Evidence', new Schema({
  incidentId: { type: Schema.Types.ObjectId, ref: 'Incident', required: true, index: true },
  originalFileName: String,
  storagePath: String,
  sha256: String,
  size: Number,
  sourceType: { type: String, enum: ['auth', 'web'], required: true },
  collectedAt: { type: Date, default: Date.now },
  sourceUtcOffsetMinutes: { type: Number, default: 0 }, // local time = UTC + offset
  clockSkewSeconds: { type: Number, default: 0 },       // + means source clock is AHEAD
  logYear: { type: Number },                            // syslog has no year
  verification: {
    status: { type: String, enum: ['not_checked', 'verified', 'failed'], default: 'not_checked' },
    lastVerifiedAt: Date,
    currentSha256: String,
  },
  processing: {
    status: { type: String, enum: ['pending', 'done'], default: 'pending' },
    totalLines: Number,
    parsedLines: Number,
    gapCount: Number,
    coveragePercent: Number,
    processedAt: Date,
  },
}));

const Event = mongoose.model('Event', new Schema({
  incidentId: { type: Schema.Types.ObjectId, index: true },
  evidenceId: { type: Schema.Types.ObjectId, index: true },
  lineNumber: Number,
  originalTimestamp: String,
  normalizedTimestamp: { type: Date, index: true },
  sourceType: String,
  sourceIp: { type: String, index: true },
  username: String,
  eventType: { type: String, index: true },
  method: String,
  path: String,
  statusCode: Number,
  details: String,
  rawLine: String,
}));

const ParsingGap = mongoose.model('ParsingGap', new Schema({
  incidentId: { type: Schema.Types.ObjectId, index: true },
  evidenceId: { type: Schema.Types.ObjectId, index: true },
  lineNumber: Number,
  rawLine: String,
  reason: String,
}));

module.exports = { Incident, Evidence, Event, ParsingGap };
