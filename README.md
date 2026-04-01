# Sentinel — AI-Powered Log Anomaly Detector

A SOC-style security dashboard that analyzes raw server logs for threats using Claude Opus 4.6. Detects attack patterns, maps them to MITRE ATT&CK tactics, and generates professional PDF reports.

## Demo

Load the sample attack chain to see a full kill chain detected:
**Brute Force → Privilege Escalation → Payload Download → Lateral Movement → Exfiltration → Persistence → Log Tampering**

## Features

- **AI-powered detection** — Claude Opus 4.6 with adaptive thinking reasons through log timelines, not just keyword matching
- **MITRE ATT&CK mapping** — every finding tagged with the relevant tactic
- **Risk scoring** — 0–100 overall risk gauge per analysis
- **Multi-file analysis** — drag and drop multiple log files, analyze individually or all together
- **PDF & JSON export** — download professional SOC reports
- **Dark SOC dashboard** — severity-tiered threat cards with expandable evidence

## Tech Stack

| Layer | Tech |
|---|---|
| Frontend | React + TypeScript + Vite |
| Backend | Python + FastAPI |
| AI | Claude Opus 4.6 (Anthropic API) |
| PDF Export | jsPDF |

## Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+
- An [Anthropic API key](https://console.anthropic.com)

### Backend

```bash
cd backend
cp .env.example .env
# Add your API key to .env
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`

## What It Detects

- Brute force / credential stuffing
- Privilege escalation (sudo, su, wheel)
- Lateral movement (SSH pivoting)
- Persistence (cron jobs, SSH key injection)
- Data exfiltration (shadow file reads, base64 encoding, outbound POST)
- C2 beacon indicators
- Defense evasion (log deletion, tampering)
- Off-hours activity and impossible logins

## Project Structure

```
log-anomaly-detector/
├── backend/
│   ├── main.py          # FastAPI app
│   ├── analyzer.py      # Claude API integration + structured output
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.tsx      # SOC dashboard UI
│       └── types.ts
└── sample-logs/
    ├── attack-chain.log    # Full intrusion scenario
    └── normal-activity.log # Clean baseline
```
