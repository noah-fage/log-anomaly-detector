import anthropic
import json

ANALYSIS_SYSTEM_PROMPT = """You are a senior SOC analyst. Analyze raw server/auth logs and identify security anomalies.

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

Return ONLY valid JSON. No markdown fences, no explanation outside the JSON."""

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "1-2 sentence high-level summary of the overall security posture"
        },
        "risk_score": {
            "type": "integer",
            "description": "Overall risk score from 0-100"
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
                    "evidence": {"type": "array", "items": {"type": "string"}}
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

Given detected security anomalies, predict what the attacker is most likely to do next based on kill chain progression.

For each of the 3 predicted next moves provide:
- step: 1, 2, or 3
- tactic: MITRE ATT&CK tactic name
- technique: specific technique name
- technique_id: MITRE ATT&CK technique ID (e.g. T1078)
- likelihood: integer 0-100
- description: 2-3 sentences explaining why this follows from current activity
- indicators: array of 2-3 specific log/network indicators to watch for
- defense: one specific, immediately actionable countermeasure

Return ONLY valid JSON. No markdown fences, no explanation outside the JSON."""

PREDICTION_SCHEMA = {
    "type": "object",
    "properties": {
        "current_stage": {"type": "string"},
        "attacker_objective": {"type": "string"},
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


async def analyze_logs(log_text: str, api_key: str) -> dict:
    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=3000,
        system=ANALYSIS_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Analyze these logs for security anomalies:\n\n{log_text}"}],
        output_config={"format": {"type": "json_schema", "schema": ANALYSIS_SCHEMA}}
    )

    for block in response.content:
        if block.type == "text":
            return json.loads(block.text)

    return {"summary": "No analysis returned.", "risk_score": 0, "anomalies": []}


async def predict_next_moves(anomalies: list, api_key: str) -> dict:
    client = anthropic.Anthropic(api_key=api_key)

    anomaly_summary = json.dumps([{
        "title": a.get("title"),
        "severity": a.get("severity"),
        "tactic": a.get("tactic"),
        "description": a.get("description"),
    } for a in anomalies], indent=2)

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            system=PREDICTION_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Based on these anomalies, predict the attacker's next 3 moves:\n\n{anomaly_summary}"}],
            output_config={"format": {"type": "json_schema", "schema": PREDICTION_SCHEMA}}
        )

        for block in response.content:
            if block.type == "text":
                return json.loads(block.text)
    except Exception as e:
        raise RuntimeError(f"Prediction failed: {e}") from e

    return {"current_stage": "Unknown", "attacker_objective": "Unable to generate prediction.", "predictions": []}
