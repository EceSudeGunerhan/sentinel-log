CANONICAL_ENUMS = {
    "severity": ["info", "warn", "error", "critical"],
    "category": [
        "auth", "network", "http", "dns", "dhcp", "firewall",
        "ids", "proxy", "vpn", "mail", "system", "app", "db"
    ],
}

CANONICAL_KEYS = [
    "timestamp_iso", "source",
    "src_ip", "dst_ip", "protocol",
    "process", "severity", "category",
    "status_code", "message"
]

SYSTEM_PROMPT = """You are a strict JSON normalizer for log lines.

!! RULES (must obey) !!
- Output ONLY one JSON object. Nothing before, nothing after.
- Use double quotes for all keys and string values.
- No <think>, no explanations, no markdown, no code fences, no comments.
- Keys must be exactly: timestamp_iso, source, src_ip, dst_ip,
                         protocol, process, severity, category,
                         status_code, message.
- If a field is missing, set it to null.
- severity must be one of: info, warn, error, critical.
- category must be inferred ONLY from the raw log content, not from file path.
- message: short normalized description of the log.
"""

def build_user_prompt(raw: str, pre: dict) -> str:
    """
    Build the user prompt given raw log and regex-pre extracted fields.
    Category hint is NOT passed anymore, must be inferred from raw.
    """
    lines = []
    lines.append("RAW LOG LINE:")
    lines.append(raw.strip())
    lines.append("")
    lines.append("PRE-EXTRACTED FIELDS (may be null):")
    lines.append(str(pre))
    lines.append("")
    lines.append("Now output ONLY the JSON object with the fixed keys.")
    return "\n".join(lines)
