import anthropic
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

    import json
    for block in response.content:
        if block.type == "text":
            return json.loads(block.text)

    return {"summary": "No analysis returned.", "risk_score": 0, "anomalies": []}
