# Sentinel

**AI-powered SOC dashboard that detects threats in server logs and predicts what the attacker does next.**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-sentinel--anomaly.vercel.app-00d4ff?style=flat-square)](https://sentinel-anomaly.vercel.app)
[![Backend](https://img.shields.io/badge/Backend-Render-46e3b7?style=flat-square)](https://log-anomaly-detector.onrender.com/health)
[![Claude](https://img.shields.io/badge/Powered%20by-Claude%20Opus%204.6-cc785c?style=flat-square)](https://anthropic.com)

---

<!-- Replace this line with your demo GIF once recorded -->
> **Demo:** Drop in a log file at [sentinel-anomaly.vercel.app](https://sentinel-anomaly.vercel.app). Try the "Load Sample Attack Chain" button to see a full intrusion sequence analyzed end to end.

---

## What it does

Sentinel reads raw server and auth logs the way a senior SOC analyst would: tracing the attack timeline, connecting events across the log, and mapping findings to the MITRE ATT&CK framework. It doesn't grep for keywords.

Drop in a log file and it returns:

- Every detected anomaly with severity, MITRE ATT&CK tactic, affected user, source IP, time window, and the exact evidence lines from your logs
- An overall risk score from 0-100
- A "What Happens Next" prediction: the attacker's 3 most likely next moves based on kill chain progression, each with a likelihood score, specific indicators to watch for, and an immediately actionable countermeasure

Everything runs in a single Claude Opus 4.6 call with structured JSON output. Analysis and prediction come back together, no second round trip.

## Demo

Drop in the included `sample-logs/attack-chain.log` and it catches the full intrusion sequence:

```
brute force SSH (8 failed attempts, 3 usernames)
  -> credential hit on sysadmin
  -> sudo to root
  -> wget payload from 185.220.101.45 into /tmp
  -> chmod +x + execute
  -> SSH lateral movement to 192.168.1.55 and .60
  -> cat /etc/shadow | base64 > /tmp/out.b64
  -> curl POST to C2 server
  -> cron persistence in /etc/crontab
  -> rm -f /var/log/auth.log  (log tampering)
```

Then drop in `sample-logs/normal-activity.log` and it comes back clean.

## Features

- Drag and drop `.log` / `.txt` files or paste logs directly
- Multi-file support: analyze files individually or combine them into one analysis
- MITRE ATT&CK tactic mapping on every finding
- Expandable threat cards with raw evidence lines
- "What Happens Next" panel: 3 predicted next attacker moves with likelihood bars, watch indicators, and countermeasures
- Export full report as PDF or JSON
- Dark SOC-style dashboard UI

## How it works

```
User drops log file
       |
FastAPI backend receives log_text
       |
Claude Opus 4.6 (extended thinking, 5k token budget)
  - Reads full log timeline in context
  - Identifies anomalies, maps to MITRE ATT&CK
  - Predicts next 3 attacker moves via kill chain progression
  - Returns structured JSON enforced by output schema
       |
Frontend renders risk gauge, anomaly cards, prediction panel
```

The Claude call uses `output_config` with a strict JSON schema so the response is always structured. No parsing heuristics, no prompt-engineered delimiters.

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React + TypeScript + Vite |
| Backend | Python + FastAPI |
| AI | Claude Opus 4.6 (Anthropic API) |
| PDF export | jsPDF |
| Hosting | Vercel (frontend) + Render (backend) |

## Running locally

You need Python 3.10+, Node 18+, and an [Anthropic API key](https://console.anthropic.com).

**Backend**
```bash
cd backend
pip install -r requirements.txt
echo "ANTHROPIC_API_KEY=your_key_here" > .env
uvicorn main:app --reload
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Detection coverage

| Category | Examples |
|---|---|
| Credential attacks | Brute force, credential stuffing, password spray |
| Privilege escalation | sudo/su abuse, wheel group changes |
| Lateral movement | SSH pivoting, unusual internal connections |
| Persistence | Cron in /tmp, SSH key injection, service installs |
| Exfiltration | /etc/shadow reads, base64 encoding, suspicious outbound POST |
| C2 indicators | Periodic beaconing, unusual destination ports |
| Defense evasion | Log deletion, auth.log tampering |
| Anomalous access | Off-hours logins, impossible travel (same user, multiple IPs) |
| Execution | wget/curl to temp dirs, chmod+x on downloaded files |

## Project structure

```
sentinel/
├── backend/
│   ├── main.py        # FastAPI app, CORS, /analyze endpoint
│   ├── analyzer.py    # Claude API call, combined schema, structured output
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.tsx    # Full dashboard, drag-drop, export, prediction panel
│       ├── App.css    # Dark SOC theme
│       └── types.ts   # TypeScript types
└── sample-logs/
    ├── attack-chain.log    # Full intrusion scenario
    └── normal-activity.log # Clean baseline
```
