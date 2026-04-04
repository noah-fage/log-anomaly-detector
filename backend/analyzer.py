import anthropic
import json
from pydantic import BaseModel
from typing import Literal

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with deep expertise in threat hunting, log analysis, and incident response. Your job is to analyze raw server/auth logs and identify security anomalies.

You will receive raw log entries and must return a structured JSON analysis of any detected threats or suspicious patterns.

Detection capabilities:
- Brute force / credential stuffing attacks (repeated failed logins)
- Privilege escalation (sudo, su, wheel group changes)
- Lateral movement (SSH between internal hosts, unusual process spawning)
- Persistence mechanisms (cron jobs in /tmp or /dev, SSH key injection, service installs)
- Data exfiltration indicators (large outbound transfers, /etc/shadow reads, base64 encoding)
- C2 beacon indicators (periodic outbound connections, unusual ports)
- Impossible logins (same user, multiple source IPs simultaneously)
- Off-hours activity (logins/access outside normal business hours)
- Suspicious command execution (wget/curl from temp dirs, chmod +x on downloaded files)
- Log tampering (log file deletions, auth.log cleared)

For each anomaly detected, provide:
- title: short descriptive name
- severity: "critical", "high", "medium", or "low"
- tactic: the MITRE ATT&CK tactic (e.g. "Credential Access", "Persistence", "Lateral Movement", "Exfiltration", "Command and Control", "Privilege Escalation", "Defense Evasion", "Discovery", "Execution")
- description: 1-2 sentence explanation of what was detected and why it's suspicious
- source_ip: the source IP if identifiable, otherwise null
- affected_user: the affected username if identifiable, otherwise null
- time_window: the time range of the activity (e.g. "04:32 - 04:47")
- evidence: array of 1-3 specific log lines that are the strongest evidence

If no anomalies are detected, return an empty anomalies array with a summary explaining the logs appear normal.

Return ONLY valid JSON. No markdown fences, no explanation outside the JSON."""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "1-2 sentence high-level summary of the overall security posture of the logs"
        },
        "risk_score": {
            "type": "integer",
            "description": "Overall risk score from 0-100 based on findings"
        },
        "anomalies": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "tactic": {"type": "string"},
                    "description": {"type": "string"},
                    "source_ip": {"type": ["string", "null"]},
                    "affected_user": {"type": ["string", "null"]},
                    "time_window": {"type": ["string", "null"]},
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"}
                    }
                },
                "required": ["title", "severity", "tactic", "description", "evidence"],
                "additionalProperties": False
            }
        }
    },
    "required": ["summary", "risk_score", "anomalies"],
    "additionalProperties": False
}


PREDICTION_SYSTEM_PROMPT = """You are a threat intelligence analyst specializing in attacker behavior modeling and the MITRE ATT&CK framework.

Given a set of detected security anomalies from a log analysis, predict what the attacker is most likely to do next based on their observed TTPs and the logical kill chain progression.

Use your knowledge of:
- MITRE ATT&CK tactic chaining and technique dependencies
- Common APT playbooks, ransomware operator patterns, and commodity malware behavior
- What capabilities the attacker has already established (access, persistence, tools)
- Historical attack progression data and red team exercise outcomes

For each of the 3 predicted next moves, provide:
- step: 1, 2, or 3 (ordered most-likely first)
- tactic: MITRE ATT&CK tactic name
- technique: specific technique name
- technique_id: MITRE ATT&CK technique ID (e.g. T1078, T1059.001)
- likelihood: integer 0-100 indicating probability this is the next move
- description: 2-3 sentences explaining WHY the attacker would do this and how it follows from current activity
- indicators: array of 2-3 specific log/network indicators to watch for right now
- defense: one specific, immediately actionable countermeasure

Return ONLY valid JSON. No markdown fences, no explanation outside the JSON."""

PREDICTION_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "current_stage": {
            "type": "string",
            "description": "The current MITRE ATT&CK stage the attacker is in based on detected activity"
        },
        "attacker_objective": {
            "type": "string",
            "description": "1-2 sentence assessment of the attacker's likely end goal given the TTPs observed"
        },
        "predictions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "step": {"type": "integer"},
                    "tactic": {"type": "string"},
                    "technique": {"type": "string"},
                    "technique_id": {"type": "string"},
                    "likelihood": {"type": "integer"},
                    "description": {"type": "string"},
                    "indicators": {"type": "array", "items": {"type": "string"}},
                    "defense": {"type": "string"}
                },
                "required": ["step", "tactic", "technique", "technique_id", "likelihood", "description", "indicators", "defense"],
                "additionalProperties": False
            }
        }
    },
    "required": ["current_stage", "attacker_objective", "predictions"],
    "additionalProperties": False
}


async def predict_next_moves(anomalies: list, api_key: str) -> dict:
    client = anthropic.Anthropic(api_key=api_key)

    anomaly_summary = json.dumps([{
        "title": a.get("title"),
        "severity": a.get("severity"),
        "tactic": a.get("tactic"),
        "description": a.get("description"),
        "source_ip": a.get("source_ip"),
        "affected_user": a.get("affected_user"),
        "time_window": a.get("time_window"),
    } for a in anomalies], indent=2)

    try:
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            thinking={"type": "adaptive"},
            system=PREDICTION_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Based on these detected security anomalies, predict the attacker's next 3 most likely moves:\n\n{anomaly_summary}"
                }
            ],
            output_config={
                "format": {
                    "type": "json_schema",
                    "schema": PREDICTION_OUTPUT_SCHEMA
                }
            }
        )

        for block in response.content:
            if block.type == "text":
                return json.loads(block.text)
    except Exception as e:
        raise RuntimeError(f"Prediction failed: {e}") from e

    return {"current_stage": "Unknown", "attacker_objective": "Unable to generate prediction.", "predictions": []}


async def analyze_logs(log_text: str, api_key: str) -> dict:
    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Analyze the following logs for security anomalies:\n\n{log_text}"
            }
        ],
        output_config={
            "format": {
                "type": "json_schema",
                "schema": OUTPUT_SCHEMA
            }
        }
    )

    for block in response.content:
        if block.type == "text":
            return json.loads(block.text)

    return {"summary": "No analysis returned.", "risk_score": 0, "anomalies": []}
