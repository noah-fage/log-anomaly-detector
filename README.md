# Sentinel - Log Anomaly Detector

A cybersecurity dashboard that takes raw server and auth logs and uses Claude Opus 4.6 to find threats. It doesn't just grep for keywords - it reads the log timeline like an analyst would, connects the dots between events, and tells you what actually happened and why it's suspicious.

Built this because most "security projects" on GitHub are either toy examples or just wrappers around existing tools. I wanted something that demonstrates real threat hunting logic.

## What it looks like in action

Drop in the sample attack chain log and you'll see it catch a full intrusion sequence from start to finish:

brute force SSH login attempts → credential hit on a low-priv user → sudo to root → wget payload from a sketchy IP → lateral movement to internal hosts → /etc/shadow dump → base64 encode + curl exfil → hidden cron job for persistence → auth.log deleted to cover tracks

Each finding comes with the MITRE ATT&CK tactic it maps to, the specific log lines used as evidence, and an explanation of why the behavior is suspicious in context. Then drop in the normal activity log and it comes back clean. That contrast is the whole point.

## Features

- Paste logs or drag and drop `.log` / `.txt` files directly onto the dashboard
- Upload multiple files at once and analyze them individually or all together as one combined analysis
- Every detected threat is tagged with a MITRE ATT&CK tactic (Credential Access, Lateral Movement, Exfiltration, etc.)
- Risk score from 0 to 100 so you can see overall severity at a glance
- Expandable threat cards with the exact evidence lines pulled from your logs
- Export the full report as a PDF or JSON

## Tech stack

- React + TypeScript + Vite on the frontend
- Python + FastAPI on the backend
- Claude Opus 4.6 via the Anthropic API for the actual analysis
- Adaptive thinking enabled so Claude reasons through the log timeline before responding, not just pattern matching
- jsPDF for the report export

## Running it locally

You'll need Python 3.10+, Node.js 18+, and an Anthropic API key from [console.anthropic.com](https://console.anthropic.com).

**Backend:**
```bash
cd backend
cp .env.example .env
# paste your Anthropic API key into .env
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173`.

## What it can detect

- Brute force and credential stuffing attacks
- Privilege escalation via sudo, su, or wheel group changes
- Lateral movement through SSH pivoting between internal hosts
- Persistence mechanisms like cron jobs in temp directories or SSH key injection
- Data exfiltration (shadow file reads, base64 encoding, suspicious outbound POST requests)
- Command and control beacon patterns
- Defense evasion like log file deletion or tampering
- Off-hours logins and impossible travel (same user, multiple source IPs at once)
- Suspicious command execution like downloading and chmod-ing files from unknown IPs

## Project structure

```
log-anomaly-detector/
├── backend/
│   ├── main.py          # FastAPI app and routing
│   ├── analyzer.py      # Claude API call + JSON schema enforcement
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.tsx      # Dashboard UI
│       └── types.ts     # TypeScript types
└── sample-logs/
    ├── attack-chain.log    # Full intrusion scenario to test with
    └── normal-activity.log # Clean baseline logs
```
