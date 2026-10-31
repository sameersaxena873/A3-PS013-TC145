// Production me VITE_API_URL=https://your-backend.onrender.com/api set karo
const BASE = import.meta.env.VITE_API_URL || '/api';

async function req(path, opts = {}) {
  const res = await fetch(BASE + path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
const json = (method, body) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });

export const api = {
  listIncidents: () => req('/incidents'),
  createIncident: (b) => req('/incidents', json('POST', b)),
  listEvidence: (id) => req(`/incidents/${id}/evidence`),
  upload: (id, formData) => req(`/incidents/${id}/evidence`, { method: 'POST', body: formData }),
  process: (evId, b) => req(`/evidence/${evId}/process`, json('POST', b)),
  verify: (evId) => req(`/evidence/${evId}/verify`, json('POST')),
  timeline: (id, params) => req(`/incidents/${id}/timeline?` + new URLSearchParams(params)),
  gaps: (id) => req(`/incidents/${id}/gaps`),
  analysis: (id) => req(`/incidents/${id}/analysis`),
  reportUrl: (id) => `${BASE}/incidents/${id}/report`,
};
