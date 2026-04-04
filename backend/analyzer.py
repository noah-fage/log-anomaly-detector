import anthropic
import json

SYSTEM_PROMPT = """You are a senior SOC analyst and threat intelligence expert. Given raw server/auth logs, you will:

1. Identify all security anomalies
2. Predict the attacker's next 3 most likely moves based on MITRE ATT&CK kill chain progression

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

For the prediction section, use your knowledge of:
- MITRE ATT&CK tactic chaining and technique dependencies
- Common APT playbooks, ransomware operators, and commodity malware behavior
- What access and capabilities the attacker has already established
- If no anomalies are found, return an empty predictions array and generic current_stage/attacker_objective values

Return ONLY valid JSON. No markdown fences, no explanation outside the JSON."""

COMBINED_SCHEMA = {
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
        },
        "prediction": {
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
    },
    "required": ["summary", "risk_score", "anomalies", "prediction"],
    "additionalProperties": False
}


async def analyze_logs(log_text: str, api_key: str) -> dict:
    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4000,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Analyze these logs for anomalies and predict the attacker's next 3 moves:\n\n{log_text}"
            }
        ],
        output_config={
            "format": {
                "type": "json_schema",
                "schema": COMBINED_SCHEMA
            }
        }
    )

    for block in response.content:
        if block.type == "text":
            return json.loads(block.text)

    return {
        "summary": "No analysis returned.",
        "risk_score": 0,
        "anomalies": [],
        "prediction": {"current_stage": "Unknown", "attacker_objective": "N/A", "predictions": []}
    }
