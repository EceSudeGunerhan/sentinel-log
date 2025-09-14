# -*- coding: utf-8 -*-
"""
Generate 30k intrusion-related logs from three formats into separate .log files.
- 10k Cisco IPS (SSE) key=value
- 10k Cisco SDEE (XML)
- 10k Google Cloud IDS (JSON)
"""

import os
import random
import json
from datetime import datetime, timedelta, timezone

random.seed(42)

# ----------------------------
# Yardımcılar
# ----------------------------
def rand_ip(private_bias=0.5):
    is_private = random.random() < private_bias
    if is_private:
        choice = random.choice(["10", "172", "192"])
        if choice == "10":
            return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        elif choice == "172":
            return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
        else:
            return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def iso_utc(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

def pick_protocol_and_port(category):
    mapping = {
        "BruteForce_RDP": ("TCP", 3389),
        "BruteForce_SSH": ("TCP", 22),
        "SQLi": ("TCP", random.choice([80, 443, 8080])),
        "XSS": ("TCP", random.choice([80, 443])),
        "DNS_Tunnel": ("UDP", 53),
        "SMB_Exploit": ("TCP", 445),
        "Port_Scan": (random.choice(["TCP", "UDP"]), random.choice([21,22,23,25,53,80,110,139,143,443,445,993,3306,3389])),
        "ICMP_Flood": ("ICMP", 0),
        "LDAP_Exploit": ("TCP", 389),
        "RCE_HTTP": ("TCP", random.choice([80, 443]))
    }
    return mapping[category]

SIGNATURES = {
    "BruteForce_RDP": {"id": "30501", "name": "RDP Brute Force Attempt"},
    "BruteForce_SSH": {"id": "30502", "name": "SSH Brute Force Attempt"},
    "SQLi": {"id": "40110", "name": "SQL Injection Attempt"},
    "XSS": {"id": "40120", "name": "Cross-Site Scripting Attempt"},
    "DNS_Tunnel": {"id": "50210", "name": "Suspicious DNS Tunneling"},
    "SMB_Exploit": {"id": "60310", "name": "SMB Lateral Movement/Exploit"},
    "Port_Scan": {"id": "10001", "name": "Port Scan Detected"},
    "ICMP_Flood": {"id": "20001", "name": "ICMP Flood/DoS"},
    "LDAP_Exploit": {"id": "70450", "name": "LDAP Anon Bind/RCE Attempt"},
    "RCE_HTTP": {"id": "80500", "name": "Remote Code Execution over HTTP"}
}

def choose_category_weighted():
    weights = {
        "Port_Scan": 0.18,
        "BruteForce_SSH": 0.16,
        "BruteForce_RDP": 0.12,
        "SQLi": 0.12,
        "XSS": 0.09,
        "DNS_Tunnel": 0.08,
        "SMB_Exploit": 0.08,
        "ICMP_Flood": 0.07,
        "LDAP_Exploit": 0.05,
        "RCE_HTTP": 0.05
    }
    cats, w = zip(*weights.items())
    return random.choices(cats, weights=w, k=1)[0]

def choose_severity():
    return random.choices(["low", "medium", "high"], weights=[0.45, 0.4, 0.15], k=1)[0]

def action_for_cisco_ips(sev):
    if sev == "high":
        return random.choice(["BLOCK", "RESET_CONNECTION", "DROP"])
    elif sev == "medium":
        return random.choice(["BLOCK", "ALERT"])
    else:
        return random.choice(["ALERT", "ALLOW"])

def action_for_sdee(sev):
    if sev == "high":
        return random.choice(["deny-connection", "deny-packet-inline", "reset-tcp-connection"])
    elif sev == "medium":
        return random.choice(["deny-packet-inline", "produce-alert"])
    else:
        return "produce-alert"

def direction_from_ips(src_private=True):
    return "ingress" if not src_private else random.choice(["ingress", "egress"])

def sample_timestamp(now_utc, days_back=30):
    delta = timedelta(seconds=random.randint(0, days_back * 24 * 3600))
    return now_utc - delta

# ----------------------------
# Format üreticiler
# ----------------------------
def gen_cisco_ips_sse_line(dt, src_ip, dst_ip, proto, dport, category, sev):
    sig = SIGNATURES[category]
    action = action_for_cisco_ips(sev)
    src_port = random.randint(1024, 65535) if proto in ("TCP", "UDP") else 0
    sensor_id = f"IPS-Sensor-{random.randint(1,4):02d}"
    bytes_in = random.randint(200, 50000)
    bytes_out = random.randint(100, 20000)

    return (
        f"timestamp={iso_utc(dt)} src_ip={src_ip} src_port={src_port} "
        f"dst_ip={dst_ip} dst_port={dport} protocol={proto} action={action} "
        f"signature_id={sig['id']} signature_name=\"{sig['name']}\" severity={sev} "
        f"category={category} bytes_in={bytes_in} bytes_out={bytes_out} sensor_id={sensor_id}"
    )

def gen_cisco_sdee_xml_line(dt, src_ip, dst_ip, proto, dport, category, sev):
    sig = SIGNATURES[category]
    action = action_for_sdee(sev)
    src_port = random.randint(1024, 65535) if proto in ("TCP", "UDP") else 0
    iface_in = f"GigabitEthernet0/{random.randint(0,2)}"
    iface_out = f"GigabitEthernet0/{random.randint(3,5)}"
    sensor_id = f"IPS-Sensor-{random.randint(1,4):02d}"
    event_id = random.randint(100000, 999999)

    return (
        f"<event><eventId>{event_id}</eventId><time>{iso_utc(dt)}</time>"
        f"<srcAddr>{src_ip}</srcAddr><srcPort>{src_port}</srcPort>"
        f"<destAddr>{dst_ip}</destAddr><destPort>{dport}</destPort>"
        f"<protocol>{proto}</protocol><sigId>{sig['id']}</sigId>"
        f"<sigName>{sig['name']}</sigName><sev>{sev}</sev><action>{action}</action>"
        f"<interfaceIn>{iface_in}</interfaceIn><interfaceOut>{iface_out}</interfaceOut>"
        f"<sensorId>{sensor_id}</sensorId></event>"
    )

def gen_gcp_ids_json_line(dt, src_ip, dst_ip, proto, dport, category, sev):
    sig = SIGNATURES[category]
    direction = direction_from_ips(src_ip.startswith(("10.", "172.", "192.168.")))
    payload = {
        "insertId": str(random.randint(10000000, 99999999)),
        "logName": f"projects/proj-{random.randint(100,999)}/logs/ids.googleapis.com%2Fthreat",
        "resource": {
            "type": "ids.googleapis.com/Threat",
            "labels": {
                "project_id": f"proj-{random.randint(100,999)}",
                "location": random.choice(["us-central1", "europe-west1", "asia-southeast1"]),
                "ids_endpoint_id": f"cloud-ids-{random.randint(1,3):02d}"
            }
        },
        "timestamp": iso_utc(dt),
        "severity": sev.upper(),
        "jsonPayload": {
            "alert_signature_id": sig["id"],
            "alert_signature": sig["name"],
            "alert_severity": sev,
            "category": category,
            "action": "alert",
            "src_ip": src_ip,
            "src_port": random.randint(1024, 65535) if proto in ("TCP", "UDP") else 0,
            "dest_ip": dst_ip,
            "dest_port": dport,
            "protocol": proto,
            "direction": direction
        }
    }
    return json.dumps(payload, separators=(",", ":"))

# ----------------------------
# Ana fonksiyon
# ----------------------------
def generate_and_write_logs():
    now = datetime.now(timezone.utc)
    count = 10000

    with open("cisco_ips.log", "w", encoding="utf-8") as f_ips, \
         open("cisco_sdee.log", "w", encoding="utf-8") as f_sdee, \
         open("gcp_ids.log", "w", encoding="utf-8") as f_gcp:

        for _ in range(count):
            cat = choose_category_weighted()
            proto, dport = pick_protocol_and_port(cat)
            dt = sample_timestamp(now)
            src = rand_ip(0.7)
            dst = rand_ip(0.2)
            sev = choose_severity()

            f_ips.write(gen_cisco_ips_sse_line(dt, src, dst, proto, dport, cat, sev) + "\n")

        for _ in range(count):
            cat = choose_category_weighted()
            proto, dport = pick_protocol_and_port(cat)
            dt = sample_timestamp(now)
            src = rand_ip(0.7)
            dst = rand_ip(0.2)
            sev = choose_severity()

            f_sdee.write(gen_cisco_sdee_xml_line(dt, src, dst, proto, dport, cat, sev) + "\n")

        for _ in range(count):
            cat = choose_category_weighted()
            proto, dport = pick_protocol_and_port(cat)
            dt = sample_timestamp(now)
            src = rand_ip(0.7)
            dst = rand_ip(0.2)
            sev = choose_severity()

            f_gcp.write(gen_gcp_ids_json_line(dt, src, dst, proto, dport, cat, sev) + "\n")

    print("✅ 10k kayıt her formata ayrı ayrı yazıldı.")

# ----------------------------
# Ana giriş noktası
# ----------------------------
if __name__ == "__main__":
    generate_and_write_logs()
