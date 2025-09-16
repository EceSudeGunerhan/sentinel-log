# scripts/patterns.py
# Regex + rule-based parsing for generic log format
import re
import json
from datetime import timezone
from dateutil import parser as dtparser
from xml.etree import ElementTree as ET

# --------------------
# Regex definitions
# --------------------
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_IDS_FLOW = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*[-:>]+\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)")
RE_STATUS_NUM = re.compile(r"\b([1-5]\d{2})\b")
RE_PROTO = re.compile(r"\b(TCP|UDP|ICMP|HTTP|HTTPS|SMTP|ESMTP|DHCP|DNS|IKE|IKEV2|VPN)\b", re.I)
RE_PROCESS = re.compile(r"\bprocess(?:name)?[:=]\s*([A-Za-z0-9_\-\.\/]+)\b", re.I)
RE_KEYVAL = re.compile(r"([A-Za-z0-9_\-]+)=((?:\"[^\"]*\")|(?:'[^']*')|[^;|\s]+)")

# Timestamp candidates
RE_TS_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)\b")
RE_TS_APACHE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+\-]\d{4})\]")
RE_TS_DAYMON = re.compile(r"\b(\d{1,2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b")
RE_TS_SYSLOG = re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")

# Severity/categorical hints
SEVERITY_WORDS = re.compile(r"\b(INFO|WARN|WARNING|ERROR|CRIT|CRITICAL|DEBUG|NOTICE|LOW|MEDIUM|HIGH|ALERT|REJECTED|DENY|BLOCK)\b", re.I)
CATEGORY_WORDS = re.compile(r"\b(XSS|LDAP|RDP|BRUTE|PHISH|MALWARE|IDS|IPS|VPN|DHCP|DNS|HTTP|WEB|AUTH|MAIL)\b", re.I)

# --------------------
# Helpers
# --------------------
def _parse_iso_timestamp_from_text(raw: str):
    """Try several timestamp regexes then fallback to dateutil fuzzy parse."""
    for rx in (RE_TS_ISO, RE_TS_APACHE, RE_TS_DAYMON, RE_TS_SYSLOG):
        m = rx.search(raw)
        if m:
            try:
                dt = dtparser.parse(m.group(1))
                return dt.astimezone(timezone.utc).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
            except Exception:
                continue
    try:
        dt = dtparser.parse(raw, fuzzy=True)
        return dt.astimezone(timezone.utc).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None

def _try_json(raw: str):
    try:
        return json.loads(raw)
    except Exception:
        return None

def _try_xml(raw: str):
    try:
        root = ET.fromstring(raw.strip())
        out = {}
        for child in root:
            out[child.tag] = child.text
        return out
    except Exception:
        return None

def _extract_keyvals(raw: str):
    kv = {}
    for m in RE_KEYVAL.finditer(raw):
        k = m.group(1).strip()
        v = m.group(2).strip().strip('"\'')
        kv[k] = v
    return kv

# --------------------
# Main extraction
# --------------------
def extract_generic(raw: str, source_file: str) -> dict:
    """Extract generic fields from raw log + source file."""
    raw = raw.strip()
    result = {
        "timestamp_iso": None,
        "source": source_file,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "process": None,
        "severity": None,
        "category": None,
        "status_code": None,
        "message": None,
    }

    # 1) JSON logs
    j = _try_json(raw)
    if isinstance(j, dict):
        result["timestamp_iso"] = j.get("timestamp") or j.get("time") or _parse_iso_timestamp_from_text(raw)
        result["src_ip"] = j.get("src_ip") or j.get("remoteIp") or j.get("source_ip")
        result["dst_ip"] = j.get("dst_ip") or j.get("dest_ip") or j.get("serverIp")
        result["protocol"] = j.get("protocol")
        result["process"] = j.get("process") or j.get("resourceId")
        result["severity"] = j.get("severity") or j.get("alert_severity")
        result["category"] = j.get("category")
        sc = j.get("status") or j.get("status_code") or j.get("httpRequest", {}).get("status") if isinstance(j.get("httpRequest", None), dict) else None
        result["status_code"] = int(sc) if sc and str(sc).isdigit() else None
        result["message"] = j.get("message") or j.get("logdesc") or j.get("reason") or raw
        return _finalize(result)

    # 2) XML logs
    x = _try_xml(raw)
    if x:
        result["timestamp_iso"] = x.get("time") or _parse_iso_timestamp_from_text(raw)
        result["src_ip"] = x.get("srcAddr")
        result["dst_ip"] = x.get("destAddr")
        result["protocol"] = x.get("protocol")
        result["severity"] = x.get("sev")
        result["category"] = x.get("sigName")
        result["process"] = x.get("sensorId")
        result["status_code"] = int(x.get("sigId")) if x.get("sigId") and x.get("sigId").isdigit() else None
        result["message"] = x.get("sigName") or raw
        return _finalize(result)

    # 3) Key=Value logs
    kv = _extract_keyvals(raw)
    if kv:
        result["timestamp_iso"] = kv.get("timestamp") or kv.get("time") or kv.get("date") or _parse_iso_timestamp_from_text(raw)
        result["src_ip"] = kv.get("srcip") or kv.get("src_ip")
        result["dst_ip"] = kv.get("dstip") or kv.get("dst_ip") or kv.get("assigned_ip")
        result["protocol"] = kv.get("protocol") or kv.get("method")
        result["process"] = kv.get("devname") or kv.get("process")
        result["severity"] = kv.get("level") or kv.get("severity")
        result["category"] = kv.get("category") or kv.get("type") or kv.get("subtype")
        sc = kv.get("status") or kv.get("status_code")
        result["status_code"] = int(sc) if sc and sc.isdigit() else None
        result["message"] = kv.get("logdesc") or kv.get("reason") or kv.get("message") or raw
        return _finalize(result)

    # 4) Free-form logs (syslog, postfix, apache etc.)
    result["timestamp_iso"] = _parse_iso_timestamp_from_text(raw)

    # IPs
    m = RE_IDS_FLOW.search(raw)
    if m:
        result["src_ip"], result["dst_ip"] = m.group(1), m.group(3)
    else:
        ips = RE_IPV4.findall(raw)
        if len(ips) >= 2:
            result["src_ip"], result["dst_ip"] = ips[0], ips[1]
        elif len(ips) == 1:
            result["src_ip"] = ips[0]

    # Protocol
    m = RE_PROTO.search(raw)
    if m:
        result["protocol"] = m.group(1).upper()

    # Process
    m = RE_PROCESS.search(raw)
    if m:
        result["process"] = m.group(1)

    # Status code
    m = RE_STATUS_NUM.search(raw)
    if m:
        result["status_code"] = int(m.group(1))

    # Severity/Category
    m = SEVERITY_WORDS.search(raw)
    if m:
        result["severity"] = m.group(1).upper()
    m = CATEGORY_WORDS.search(raw)
    if m:
        result["category"] = m.group(1).upper()

    # Message fallback = simplified tail
    if "logdesc" in raw.lower():
        result["message"] = raw.split("logdesc", 1)[-1].strip().strip('"')
    elif "status" in raw.lower():
        result["message"] = raw.split("status", 1)[-1].strip()
    else:
        result["message"] = raw

    return _finalize(result)

# --------------------
# Final cleanup
# --------------------
def _finalize(d: dict) -> dict:
    if not d.get("timestamp_iso"):
        d["timestamp_iso"] = _parse_iso_timestamp_from_text(d.get("message", "") or "")
    if d.get("severity"):
        d["severity"] = str(d["severity"]).upper()
    if d.get("protocol"):
        d["protocol"] = str(d["protocol"]).upper()
    try:
        if d.get("status_code") is not None:
            d["status_code"] = int(d["status_code"])
    except Exception:
        d["status_code"] = None
    return d
