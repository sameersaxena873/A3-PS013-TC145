import React, { useEffect, useState, useCallback } from 'react';
import { api } from './api.js';

const EVENT_TYPES = ['', 'failed_login', 'successful_login', 'invalid_user', 'sql_injection_attempt', 'path_scan', 'http_request', 'other'];

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [current, setCurrent] = useState(null);
  const [tab, setTab] = useState('evidence');
  const [error, setError] = useState('');
  const [newTitle, setNewTitle] = useState('');

  const loadIncidents = useCallback(async () => {
    try { setIncidents(await api.listIncidents()); } catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { loadIncidents(); }, [loadIncidents]);

  async function create(e) {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      const inc = await api.createIncident({ title: newTitle });
      setNewTitle(''); await loadIncidents(); setCurrent(inc); setError('');
    } catch (err) { setError(err.message); }
  }

  return (
    <div className="layout">
      <aside className="side">
        <h1>NovaNexus · PS-013</h1>
        <form onSubmit={create} className="row" style={{ marginBottom: 12 }}>
          <input style={{ flex: 1 }} placeholder="New incident title" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} />
          <button>Add</button>
        </form>
        {incidents.map((i) => (
          <div key={i._id} className={'inc ' + (current?._id === i._id ? 'active' : '')} onClick={() => { setCurrent(i); setTab('evidence'); }}>
            <div>{i.title}</div>
            <small style={{ color: '#9fb0c8' }}>{new Date(i.createdAt).toLocaleString()}</small>
          </div>
        ))}
        {!incidents.length && <small>Pehle ek incident banao.</small>}
      </aside>

      <main className="main">
        {error && <div className="err">{error} <button className="ghost" onClick={() => setError('')}>x</button></div>}
        {!current ? <p>Left side se incident select karo ya naya banao.</p> : (
          <>
            <h1>{current.title}</h1>
            <div className="tabs">
              {['evidence', 'timeline', 'findings', 'gaps'].map((t) => (
                <button key={t} className={tab === t ? 'on' : ''} onClick={() => setTab(t)}>{t}</button>
              ))}
              <button className="ghost" onClick={() => window.open(api.reportUrl(current._id), '_blank')}>Export report</button>
            </div>
            {tab === 'evidence' && <Evidence incident={current} onError={setError} />}
            {tab === 'timeline' && <Timeline incident={current} onError={setError} />}
            {tab === 'findings' && <Findings incident={current} onError={setError} />}
            {tab === 'gaps' && <Gaps incident={current} onError={setError} />}
          </>
        )}
      </main>
    </div>
  );
}

function Evidence({ incident, onError }) {
  const [list, setList] = useState([]);
  const [busy, setBusy] = useState('');
  const [form, setForm] = useState({ sourceType: 'auth', sourceUtcOffsetMinutes: 0, clockSkewSeconds: 0, logYear: new Date().getFullYear() });
  const [file, setFile] = useState(null);

  const load = useCallback(async () => {
    try { setList(await api.listEvidence(incident._id)); } catch (e) { onError(e.message); }
  }, [incident._id, onError]);
  useEffect(() => { load(); }, [load]);

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  async function upload(e) {
    e.preventDefault();
    if (!file) return onError('Pehle file choose karo');
    const fd = new FormData();
    Object.entries(form).forEach(([k, v]) => fd.append(k, v));
    fd.append('file', file);
    setBusy('upload');
    try { await api.upload(incident._id, fd); setFile(null); e.target.reset(); await load(); onError(''); }
    catch (err) { onError(err.message); }
    setBusy('');
  }
  async function act(kind, ev) {
    setBusy(kind + ev._id);
    try { await (kind === 'process' ? api.process(ev._id) : api.verify(ev._id)); await load(); onError(''); }
    catch (err) { onError(err.message); }
    setBusy('');
  }

  return (
    <>
      <form className="card" onSubmit={upload}>
        <h2 style={{ marginTop: 0 }}>Upload log file</h2>
        <div className="row">
          <label>File (.log / .txt)<input type="file" accept=".log,.txt" onChange={(e) => setFile(e.target.files[0])} /></label>
          <label>Source type
            <select value={form.sourceType} onChange={set('sourceType')}>
              <option value="auth">Linux auth.log</option><option value="web">Nginx/Apache access log</option>
            </select></label>
          <label>UTC offset (minutes)<input type="number" style={{ width: 110 }} value={form.sourceUtcOffsetMinutes} onChange={set('sourceUtcOffsetMinutes')} /></label>
          <label>Clock skew (sec, + = ahead)<input type="number" style={{ width: 130 }} value={form.clockSkewSeconds} onChange={set('clockSkewSeconds')} /></label>
          <label>Log year<input type="number" style={{ width: 90 }} value={form.logYear} onChange={set('logYear')} /></label>
          <button disabled={busy === 'upload'}>Upload + hash</button>
        </div>
        <small style={{ color: '#9fb0c8' }}>Web logs me timezone line ke andar hota hai; UTC offset sirf auth.log (syslog) ke liye lagta hai.</small>
      </form>

      <div className="card" style={{ overflowX: 'auto' }}>
        <table>
          <thead><tr><th>File</th><th>Type</th><th>SHA-256</th><th>Integrity</th><th>Parsing</th><th>Actions</th></tr></thead>
          <tbody>
            {list.map((ev) => (
              <tr key={ev._id}>
                <td>{ev.originalFileName}<br /><small>{ev.size} bytes · skew {ev.clockSkewSeconds}s · offset {ev.sourceUtcOffsetMinutes}m</small></td>
                <td><span className="badge">{ev.sourceType}</span></td>
                <td className="mono">{ev.sha256}</td>
                <td className={ev.verification?.status}>{ev.verification?.status}</td>
                <td>{ev.processing?.status === 'done'
                  ? <>{ev.processing.coveragePercent}% <small>({ev.processing.parsedLines}/{ev.processing.totalLines}, gaps {ev.processing.gapCount})</small></>
                  : 'not processed'}</td>
                <td className="row">
                  <button disabled={!!busy} onClick={() => act('process', ev)}>Process</button>
                  <button className="ghost" disabled={!!busy} onClick={() => act('verify', ev)}>Verify hash</button>
                </td>
              </tr>
            ))}
            {!list.length && <tr><td colSpan="6">Abhi koi evidence nahi.</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Timeline({ incident, onError }) {
  const [filters, setFilters] = useState({ q: '', ip: '', username: '', eventType: '', start: '', end: '' });
  const [data, setData] = useState({ items: [], total: 0 });
  const [page, setPage] = useState(1);

  const load = useCallback(async (p = 1) => {
    const params = { page: p, limit: 100 };
    Object.entries(filters).forEach(([k, v]) => {
      if (!v) return;
      params[k] = k === 'start' || k === 'end' ? new Date(v).toISOString() : v;
    });
    try { setData(await api.timeline(incident._id, params)); setPage(p); onError(''); } catch (e) { onError(e.message); }
  }, [filters, incident._id, onError]);
  useEffect(() => { load(1); /* eslint-disable-next-line */ }, [incident._id]);

  const set = (k) => (e) => setFilters({ ...filters, [k]: e.target.value });
  return (
    <>
      <div className="card">
        <div className="row">
          <label>Keyword<input value={filters.q} onChange={set('q')} /></label>
          <label>IP<input value={filters.ip} onChange={set('ip')} /></label>
          <label>Username<input value={filters.username} onChange={set('username')} /></label>
          <label>Event type<select value={filters.eventType} onChange={set('eventType')}>{EVENT_TYPES.map((t) => <option key={t} value={t}>{t || 'all'}</option>)}</select></label>
          <label>Start (local)<input type="datetime-local" value={filters.start} onChange={set('start')} /></label>
          <label>End (local)<input type="datetime-local" value={filters.end} onChange={set('end')} /></label>
          <button onClick={() => load(1)}>Apply</button>
          <button className="ghost" onClick={() => { setFilters({ q: '', ip: '', username: '', eventType: '', start: '', end: '' }); setTimeout(() => load(1), 0); }}>Reset</button>
        </div>
      </div>
      <div className="card" style={{ overflowX: 'auto' }}>
        <div className="stats" style={{ marginBottom: 8 }}><div className="stat"><b>{data.total}</b>matching events</div></div>
        <table>
          <thead><tr><th>UTC time</th><th>Original</th><th>Source</th><th>Event</th><th>IP</th><th>User</th><th>Details</th></tr></thead>
          <tbody>
            {data.items.map((e) => (
              <tr key={e._id}>
                <td className="mono">{new Date(e.normalizedTimestamp).toISOString()}</td>
                <td className="mono">{e.originalTimestamp}</td>
                <td><span className="badge">{e.sourceType}</span></td>
                <td className={e.eventType === 'failed_login' || e.eventType === 'sql_injection_attempt' ? 'high' : e.eventType === 'path_scan' ? 'medium' : ''}>{e.eventType}</td>
                <td>{e.sourceIp}</td><td>{e.username}</td><td>{e.details}</td>
              </tr>
            ))}
            {!data.items.length && <tr><td colSpan="7">Koi event nahi. Evidence tab me file ko Process karo.</td></tr>}
          </tbody>
        </table>
        <div className="row" style={{ marginTop: 8 }}>
          <button className="ghost" disabled={page <= 1} onClick={() => load(page - 1)}>Prev</button>
          <span>Page {page}</span>
          <button className="ghost" disabled={page * 100 >= data.total} onClick={() => load(page + 1)}>Next</button>
        </div>
      </div>
    </>
  );
}

function Findings({ incident, onError }) {
  const [items, setItems] = useState([]);
  useEffect(() => { api.analysis(incident._id).then(setItems).catch((e) => onError(e.message)); }, [incident._id, onError]);
  return (
    <div className="card">
      <table>
        <thead><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead>
        <tbody>
          {items.map((f, i) => <tr key={i}><td className={f.severity}>{f.severity}</td><td>{f.title}</td><td>{f.detail}</td></tr>)}
          {!items.length && <tr><td colSpan="3">Koi finding nahi (ya evidence process nahi hui).</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function Gaps({ incident, onError }) {
  const [items, setItems] = useState([]);
  useEffect(() => { api.gaps(incident._id).then(setItems).catch((e) => onError(e.message)); }, [incident._id, onError]);
  return (
    <div className="card" style={{ overflowX: 'auto' }}>
      <table>
        <thead><tr><th>Line</th><th>Reason</th><th>Raw line</th></tr></thead>
        <tbody>
          {items.map((g) => <tr key={g._id}><td>{g.lineNumber}</td><td>{g.reason}</td><td className="mono">{g.rawLine}</td></tr>)}
          {!items.length && <tr><td colSpan="3">Koi parsing gap nahi.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
