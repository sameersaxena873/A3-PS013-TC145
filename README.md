# NovaNexus · PS-013 — Incident Timeline & Evidence Collection for Small Teams

Pipeline: **Collect → Hash (SHA-256) → Parse → Normalize (UTC + clock skew) → Timeline → Report**
Stack: React (Vite) · Node/Express · MongoDB Atlas (Mongoose) · Multer · Node `crypto`.
Parsers: Linux `auth.log` (SSH) aur Nginx/Apache combined access log (pure JavaScript, regex based).

## Folder structure
```
NovaNexus-PS013/
├── backend/   (src/server.js, routes.js, models.js, config/db.js, services/*)
├── frontend/  (Vite + React dashboard)
├── test-data/ (scenario-1, scenario-2, scenario-3 + generate_testdata.py)
└── README.md
```

## Step 1 — Backend setup
1. Apne purane `backend` folder ki jagah is zip ka `backend` use karo (ya files overwrite karo). Terminal me:
   ```powershell
   cd backend
   npm install
   ```
2. `backend/.env` file banao (`.env.example` copy karke):
   ```
   PORT=5000
   MONGO_URI=mongodb+srv://<USER>:<PASSWORD>@<CLUSTER>.mongodb.net/incident_forensics?retryWrites=true&w=majority
   ```
   - Password ke **aas-paas `<` `>` mat rakho** (screenshot me `<Sameer1234>` tha, wo galat hai; sirf `Sameer1234`).
   - Hostname Atlas ke "Connect → Drivers" se **mongodb+srv://...** wali string copy karo (screenshot me `ac-...-shard-00-00` wali non-SRV string thi, wo bhi chalegi par SRV simple hai).
   - Database name (`/incident_forensics`) host ke baad zaroor likho.
3. Atlas me **Network Access → Add IP Address → Allow access from anywhere (0.0.0.0/0)** (demo ke liye).
4. Parser test (DB ki zarurat nahi): `npm run selftest` → `ALL SELF TESTS PASSED` aana chahiye.
5. Server start: `npm run dev` → `MongoDB connected` aur `API running on http://localhost:5000`.

## Step 2 — Frontend setup
```powershell
cd frontend
npm install
npm run dev
```
Browser me http://localhost:5173 kholo (API proxy `/api → localhost:5000` already set hai).

## Step 3 — Demo / testing flow (3 mandatory scenarios)
Har scenario ke liye: naya incident banao → Evidence tab me file upload karo → **Process** → **Verify hash**.

| Scenario | Files | Upload settings | Kya verify karna hai |
|---|---|---|---|
| 1 SSH brute force | `scenario-1/auth.log` | type = auth, skew 0, year 2026 | Timeline me 8 failed → fir success; Findings me "SSH brute force followed by successful login"; Gaps tab me 2 lines |
| 2 Web attack | `scenario-2/access.log` | type = web | Event type filter `sql_injection_attempt` (4) aur `path_scan` (6); 1 gap |
| 3 Clock skew | `scenario-3/auth_serverA.log` (type auth, **skew = 120**) + `scenario-3/access_serverB.log` (type web, skew 0) | Dono ek hi incident me | Timeline order: web, auth, web, auth, web. Skew 0 se process karke compare karo (order galat dikhega) |

Hash tamper test: `backend/evidence-store/<incidentId>/` me file ka content badal do → **Verify hash** → `failed` dikhna chahiye.

Report: **Export report** button → naye tab me HTML report (hashes report ke time dobara verify hote hain) → Print → Save as PDF.

### Metrics table (khud run karke bharo — bina run kiye numbers mat likho)
| Scenario | Total lines | Parsed | Coverage % | Gaps | Hash verify |
|---|---|---|---|---|---|
| 1 SSH brute force | 13 | 11 | 84.62 | 2 | pass |
| 2 Web attack | 16 | 15 | 93.75 | 1 | pass |
| 3 Clock skew | 5 | 5 | 100 | 0 | pass |

Reports: `docs/report-scenario1-ssh-bruteforce.pdf`, `docs/report-scenario2-web-attack.pdf`, `docs/report-scenario3-clock-skew.pdf`

## API summary
`POST/GET /api/incidents` · `POST/GET /api/incidents/:id/evidence` · `POST /api/evidence/:id/process` ·
`POST /api/evidence/:id/verify` · `GET /api/incidents/:id/timeline?q=&ip=&username=&eventType=&start=&end=&page=` ·
`GET /api/incidents/:id/gaps` · `GET /api/incidents/:id/analysis` · `GET /api/incidents/:id/report`

## Design notes (viva ke liye)
- Original file kabhi modify nahi hoti: `evidence-store/` me read-only (0444) save; MongoDB me sirf metadata + hash + derived events.
- Re-process karne par sirf derived `Event`/`ParsingGap` records badalte hain, original file nahi.
- syslog me year/timezone nahi hota → upload ke time `logYear` aur `UTC offset` explicitly configure hota hai.
- Clock skew: `normalized = local − utcOffset − skew` (skew + = source clock aage hai).
- Parse na hone wali lines silently drop nahi hoti; `ParsingGap` me line number + reason ke saath store hoti hain.
- Hash match integrity ka check hai, authenticity ka proof nahi.
- Limits: 25 MB upload, sirf `.log/.txt`, file kabhi execute nahi hoti. Auth/JWT aur immutable storage future work hain.

## GitHub push
```powershell
cd NovaNexus-PS013
git init
git add .
git commit -m "PS-013 MERN incident timeline prototype"
git branch -M main
git remote add origin https://github.com/<username>/<team-repo>.git
git push -u origin main
```
`.gitignore` me `.env` already hai — **MongoDB password kabhi push mat karna.**

## Deploy (optional, live demo link ke liye)
- Backend: Render → New Web Service → root `backend`, build `npm install`, start `npm start`, env vars `MONGO_URI`, `PORT`. (Free plan me disk ephemeral hota hai: uploaded files restart par ja sakti hain — demo ke liye theek.)
- Frontend: Vercel → root `frontend`, env `VITE_API_URL=https://<render-url>/api`.
- Live demo na ho paye to README me demo video link + screenshots daalo.

## Submission checklist
- [ ] Team-named GitHub repo (code + README + PDF)
- [ ] Demo video YouTube pe upload, link README me
- [ ] Live demo link (ya final files repo me)
- [ ] Metrics table run karke bhari hui
# AIORI-3 Hackathon Project

## Team NovaNexus (A3-PS013-TC145)

**Problem Statement 013:** Incident Timeline and Evidence Collection for Small Teams

**Team Members:** Sameer Saxena, Palak Saxena

**Mentor:** Anas Khan

### Team Introduction Video
https://youtu.be/ppCxTrD-hkw

### Presentation
[PS013_NovaNexus_Final.pdf](PS013_NovaNexus_Final.pdf)
## 🌐 Live Demo
- Frontend: https://a3-ps-013-tc-145.vercel.app
- Backend API: https://novanexus-backend.onrender.com

> Note: Free hosting hai, pehli load me ~50 sec lag sakte hain.