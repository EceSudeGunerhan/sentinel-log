# scripts/patterns.py

import re
from datetime import datetime, timezone
from dateutil import parser as dtparser

# Regex patterns
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_STATUS = re.compile(r"\b(?:status|code|status_code)\s*[:=]\s*(\d{3})\b", re.I)
RE_PROTO = re.compile(r"\b(TCP|UDP|ICMP|HTTP|HTTPS|SMTP|FTP)\b", re.I)
RE_PROCESS = re.compile(r"\bprocess(?:name)?[:=]\s*([A-Za-z0-9_\-\.]+)\b", re.I)

# IDS/IPS style "x.x.x.x:port -> y.y.y.y:port"
RE_IDS_FLOW = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+) -> (\d{1,3}(?:\.\d{1,3}){3}):(\d+)")

# Timestamp regexes
RE_TS_APACHE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+\-]\d{4})\]")
RE_TS_SYSLOG = re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
RE_TS_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)\b")

def parse_timestamp_iso(raw: str) -> str | None:
    """Parse various timestamp formats into ISO8601 UTC string."""
    for regex in (RE_TS_APACHE, RE_TS_ISO, RE_TS_SYSLOG):
        m = regex.search(raw)
        if m:
            try:
                dt = dtparser.parse(m.group(1))
                return dt.astimezone(timezone.utc).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
            except:
                continue
    try:
        dt = dtparser.parse(raw, fuzzy=True)
        return dt.astimezone(timezone.utc).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except:
        return None

def extract_ips(raw: str) -> tuple[str | None, str | None]:
    """Try IDS-style flow first, else fallback to first 2 IPv4s."""
    m = RE_IDS_FLOW.search(raw)
    if m:
        return m.group(1), m.group(3)
    ips = RE_IPV4.findall(raw)
    if len(ips) >= 2:
        return ips[0], ips[1]
    elif len(ips) == 1:
        return ips[0], None
    return None, None

def extract_status_code(raw: str) -> int | None:
    """Try generic status=XXX or standalone 3-digit codes (SMTP/HTTP)."""
    m = RE_STATUS.search(raw)
    if m:
        return int(m.group(1))
    m2 = re.search(r"\b(\d{3})\b", raw)
    if m2:
        code = int(m2.group(1))
        if 100 <= code <= 599:
            return code
    return None

def extract_process(raw: str) -> str | None:
    """Catch 'process=xyz', 'sshd[123]', 'MTA[pid]' etc."""
    m = RE_PROCESS.search(raw)
    if m:
        return m.group(1)
    m2 = re.search(r"([A-Za-z]+)\[\d+\]", raw)
    if m2:
        return m2.group(1)
    return None

def extract_basic_fields(raw: str) -> dict:
    ts = parse_timestamp_iso(raw)
    src_ip, dst_ip = extract_ips(raw)

    protocol = None
    m = RE_PROTO.search(raw)
    if m:
        protocol = m.group(1).upper()

    status_code = extract_status_code(raw)
    process = extract_process(raw)

    return {
        "timestamp_iso": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "process": process,
        "status_code": status_code,
    }
