import os
import random
import ipaddress
from datetime import datetime, timedelta, timezone
import json

# ==============================
# CONFIG
# ==============================
random.seed(42)

TOTAL = 30000                     # total lines written to the single output file
SPLIT = (10000, 10000, 10000)     # Cisco, Fortinet, Azure counts (sum must equal TOTAL)
PCT_FAILED_CISCO = 0.20           # share of FAILED events inside Cisco portion
PCT_FAILED_AZURE = 0.15           # share of failure-like diagnostics inside Azure portion
MIN_SESSION_SEC = 60
MAX_SESSION_SEC = 8 * 3600
DAYS_SPAN = 30
OUT_FILE = "vpn_mixed_logs.log"   # single, mixed-format output

# ==============================
# VOCABS / POOLS
# ==============================
users = [
    "alice","bob","charlie","diana","eve","frank","grace","heidi","ivan","judy",
    "karen","leo","mallory","ned","olivia","peggy","quinn","rick","sybil","trent",
    "ursula","victor","wendy","xavier","yasmine","zach","ayse","mehmet","fatma","ahmet",
    "sinem","burak","elif","mert","selin","can","gizem","baran","berfin","enes"
]
hostnames = [
    "hq-vpn-gw-1","hq-vpn-gw-2","eu-vpn-gw-1","eu-vpn-gw-2",
    "apac-vpn-gw-1","us-vpn-gw-1","us-vpn-gw-2","latam-vpn-gw-1"
]
aws_regions = ["us-east-1","us-west-2","eu-west-1","eu-central-1","ap-southeast-1","ap-northeast-1","sa-east-1"]
session_types = ["IKEv2","TLS"]
vpn_profile = "CiscoSecureAccessVPN"
os_versions = [
    "Windows 11 23H2","Windows 10 22H2","Mac OS X 14.6.1","Mac OS X 13.6",
    "Ubuntu 22.04","Ubuntu 24.04","iOS 17.5","Android 14"
]
anyconnect_versions = ["5.1.2.42","5.0.05040","5.1.0.91","5.0.03120","4.10.06079"]
asa_syslog_ids = ["ASA-5-109201","ASA-4-113019","ASA-6-113039","ASA-3-113015"]
asa_severity_class_desc = [
    ("5","INFORMATION","AAA-INFO"),
    ("4","WARNING","AAA-WARN"),
    ("3","ERROR","AAA-ERROR"),
]
disconnect_reasons = ["User Requested","Idle Timeout","Network Error","Re-authentication","Admin Logout"]
failed_reasons_kinds = ["AUTHORIZATION-CHECK","CERT-AUTH-CHECK"]

# Azure categories/operations
azure_categories = ["TunnelDiagnosticLog","GatewayDiagnosticLog","IKEDiagnosticLog"]
azure_ops_connected = ["TunnelConnected","RouteAdded","GatewayPolicyApplied"]
azure_ops_disconnected = ["TunnelDisconnected"]
azure_ops_failed = ["IKEAuthFailed","IKENegotiationTimeout","TunnelFailure"]

# Fortinet device names
forti_devices = ["FGT-HQ","FGT-Branch1","FGT-Branch2","FGT-EU1","FGT-US1","FGT-APAC1"]

# ==============================
# HELPERS
# ==============================
def rand_public_ipv4():
    """Generate a plausible public IPv4 (exclude private/reserved/multicast)."""
    while True:
        a, b, c, d = [random.randint(1, 254) for _ in range(4)]
        ip_ = ipaddress.ip_address(f"{a}.{b}.{c}.{d}")
        if not (ip_.is_private or ip_.is_loopback or ip_.is_multicast or ip_.is_link_local or ip_.is_reserved):
            return str(ip_)

def rand_assigned_ip():
    """Generate a plausible RFC1918 assigned IP for VPN."""
    nets = [ipaddress.ip_network("10.10.0.0/16"), ipaddress.ip_network("192.168.10.0/24"), ipaddress.ip_network("172.16.0.0/16")]
    net = random.choice(nets)
    a = int(str(net.network_address).split(".")[0])
    b = int(str(net.network_address).split(".")[1])
    c = random.randint(0, 254)
    d = random.randint(1, 254)
    return f"{a}.{b}.{c}.{d}"

def within_last_days(days=30):
    """Pick a datetime within the last N days (UTC)."""
    now = datetime.now(timezone.utc)
    dt = now - timedelta(seconds=random.randint(0, days*24*3600))
    return dt

def ts_str_cisco(dt):
    """Cisco sample uses naive 'YYYY-MM-DD HH:MM:SS' (no timezone offset in value)."""
    return dt.astimezone(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")

def ts_iso_z(dt):
    """ISO8601 Zulu format."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def forti_date_time(dt):
    """Return strings date=YYYY-MM-DD and time=HH:MM:SS."""
    local = dt.astimezone(timezone.utc)
    return local.strftime("%Y-%m-%d"), local.strftime("%H:%M:%S")

def quoted(val):
    """Always double-quote a CSV value."""
    return f"\"{val}\""

def list_string(items):
    """Render list as CSV-like JSON array e.g. ["AUTHORIZATION-CHECK"]."""
    return "[" + ",".join(f"\"{x}\"" for x in items) + "]"

def make_origin_ids():
    return f"[{random.randint(100000000, 1999999999)}]"

def make_session_id():
    return str(random.randint(1000, 9999))

def pick_asa_triplet():
    return random.choice(asa_severity_class_desc)

# ==============================
# 1) CISCO GENERATION (CSV lines)
# ==============================
CISCO_HEADER = ",".join([
    "timestamp","hostname","aws region","event type","origin ids","origin type","user id",
    "organization id","retention days","storage location","msp organization id","session id",
    "session type","vpn profile","public ip","assigned ip","connected at","disconnection reason",
    "os version","anyconnect version","asa syslog id","device id","machine id","public ipv6",
    "assigned ipv6","security group tag","dap record name","dap connection type","failed reasons",
    "log message","asa syslog severity","asa syslog class","asa syslog description"
])

# constants matching Cisco sample
CISCO_ORIGIN_TYPE = "7"
CISCO_ORG_ID = "8236318"
CISCO_RETENTION = "365"
CISCO_STORAGE = "us"
CISCO_MSP_ORG = ""
CISCO_SGT = "10"

def cisco_row_connected(dt_conn, hostname, region, origin_ids, user, sess_id, sess_type,
                        pub_ip, assigned_ip, os_ver, ac_ver,
                        asa_id, device_id, machine_id,
                        failed_list, log_msg, asa_sev, asa_class, asa_desc):
    fields = [
        ts_str_cisco(dt_conn), hostname, region, "CONNECTED", origin_ids, CISCO_ORIGIN_TYPE, user,
        CISCO_ORG_ID, CISCO_RETENTION, CISCO_STORAGE, CISCO_MSP_ORG, sess_id,
        sess_type, vpn_profile, pub_ip, assigned_ip, "", "", os_ver, ac_ver,
        asa_id, device_id, machine_id, "n/a", "n/a", CISCO_SGT, "", "",
        list_string(failed_list), log_msg, asa_sev, asa_class, asa_desc
    ]
    return ",".join(quoted(x) for x in fields)

def cisco_row_disconnected(dt_disc, hostname, region, origin_ids, user, sess_id, sess_type,
                           pub_ip, assigned_ip, connected_at_iso, reason,
                           os_ver, ac_ver, asa_id, device_id, machine_id,
                           failed_list, log_msg, asa_sev, asa_class, asa_desc):
    fields = [
        ts_str_cisco(dt_disc), hostname, region, "DISCONNECTED", origin_ids, CISCO_ORIGIN_TYPE, user,
        CISCO_ORG_ID, CISCO_RETENTION, CISCO_STORAGE, CISCO_MSP_ORG, sess_id,
        sess_type, vpn_profile, pub_ip, assigned_ip, connected_at_iso, reason,
        os_ver, ac_ver, asa_id, device_id, machine_id, "n/a", "n/a",
        CISCO_SGT, "", "", list_string(failed_list), log_msg, asa_sev, asa_class, asa_desc
    ]
    return ",".join(quoted(x) for x in fields)

def cisco_row_failed(dt_fail, hostname, region, origin_ids, user, sess_id, sess_type,
                     pub_ip, assigned_ip, failed_list, os_ver, ac_ver,
                     asa_id, device_id, machine_id, log_msg, asa_sev, asa_class, asa_desc):
    fields = [
        ts_str_cisco(dt_fail), hostname, region, "FAILED", origin_ids, CISCO_ORIGIN_TYPE, user,
        CISCO_ORG_ID, CISCO_RETENTION, CISCO_STORAGE, CISCO_MSP_ORG, sess_id,
        sess_type, vpn_profile, pub_ip, assigned_ip, "", "",
        os_ver, ac_ver, asa_id, device_id, machine_id, "n/a", "n/a",
        CISCO_SGT, "", "", list_string(failed_list), log_msg, asa_sev, asa_class, asa_desc
    ]
    return ",".join(quoted(x) for x in fields)

def generate_cisco_rows(target_rows):
    rows = []
    failed_target = int(target_rows * PCT_FAILED_CISCO)
    success_rows = target_rows - failed_target
    session_pairs = success_rows // 2

    # Successful pairs
    for _ in range(session_pairs):
        dt_conn = within_last_days(DAYS_SPAN)
        duration = random.randint(MIN_SESSION_SEC, MAX_SESSION_SEC)
        dt_disc = dt_conn + timedelta(seconds=duration)
        now_utc = datetime.now(timezone.utc)
        if dt_disc > now_utc:
            dt_disc = now_utc

        user = random.choice(users)
        hostname = random.choice(hostnames)
        region = random.choice(aws_regions)
        origin_ids = make_origin_ids()
        sess_id = make_session_id()
        sess_type = random.choice(session_types)
        pub_ip = rand_public_ipv4()
        assigned_ip = rand_assigned_ip()
        os_ver = random.choice(os_versions)
        ac_ver = random.choice(anyconnect_versions)
        asa_id = random.choice(asa_syslog_ids)
        device_id = f"DEVICE-{random.choice(['M','W','L'])}-{random.randint(1000,9999)}"
        machine_id = ""
        failed_list = []
        reason = random.choice(disconnect_reasons)
        connected_at_iso = ts_iso_z(dt_conn)
        asa_sev1, asa_class1, asa_desc1 = pick_asa_triplet()
        asa_sev2, asa_class2, asa_desc2 = pick_asa_triplet()

        rows.append(cisco_row_connected(
            dt_conn, hostname, region, origin_ids, user, sess_id, sess_type,
            pub_ip, assigned_ip, os_ver, ac_ver, asa_id, device_id, machine_id,
            failed_list, "Session connected successfully", asa_sev1, asa_class1, asa_desc1
        ))
        rows.append(cisco_row_disconnected(
            dt_disc, hostname, region, origin_ids, user, sess_id, sess_type,
            pub_ip, assigned_ip, connected_at_iso, reason,
            os_ver, ac_ver, asa_id, device_id, machine_id, failed_list,
            "Session disconnected", asa_sev2, asa_class2, asa_desc2
        ))

    # Failed
    for _ in range(failed_target):
        dt_fail = within_last_days(DAYS_SPAN)
        user = random.choice(users)
        hostname = random.choice(hostnames)
        region = random.choice(aws_regions)
        origin_ids = make_origin_ids()
        sess_id = make_session_id()
        sess_type = random.choice(session_types)
        pub_ip = rand_public_ipv4()
        assigned_ip = rand_assigned_ip()
        os_ver = random.choice(os_versions)
        ac_ver = random.choice(anyconnect_versions)
        asa_id = random.choice(asa_syslog_ids)
        device_id = f"DEVICE-{random.choice(['M','W','L'])}-{random.randint(1000,9999)}"
        machine_id = ""
        failed_kind = random.choice(failed_reasons_kinds)
        failed_list = [failed_kind]
        asa_sev, asa_class, asa_desc = pick_asa_triplet()

        rows.append(cisco_row_failed(
            dt_fail, hostname, region, origin_ids, user, sess_id, sess_type,
            pub_ip, assigned_ip, failed_list, os_ver, ac_ver,
            asa_id, device_id, machine_id, "AAA Marking param1 server param2 as FAILED",
            asa_sev, asa_class, asa_desc
        ))

    random.shuffle(rows)
    return rows[:target_rows]

# ==============================
# 2) FORTINET GENERATION (key=value)
# ==============================
def forti_line(dt, devname, devid, msg, user, srcip, assigned_ip, subtype, extra=None):
    date_str, time_str = forti_date_time(dt)
    event_ns = int(dt.timestamp() * 1e9)
    fields = [
        f"date={date_str}",
        f"time={time_str}",
        f"devname=\"{devname}\"",
        f"devid=\"{devid}\"",
        f"eventtime={event_ns}",
        "tz=\"+0000\"",
        "logid=\"0101039424\"",
        "type=\"vpn\"",
        f"subtype=\"{subtype}\"",
        "level=\"notice\"",
        f"logdesc=\"{msg}\"",
        f"user=\"{user}\"",
        f"srcip={srcip}",
        f"assigned_ip={assigned_ip}"
    ]
    if extra:
        fields.extend(extra)
    return " ".join(fields)

def generate_fortinet_lines(target_rows):
    lines = []
    for _ in range(target_rows):
        mode = random.random()
        dt_conn = within_last_days(DAYS_SPAN)
        devname = random.choice(forti_devices)
        devid = f"FG{random.choice(['60F','100E','200F'])}{random.randint(100000,999999)}"
        user = random.choice(users)
        srcip = rand_public_ipv4()
        assigned_ip = rand_assigned_ip()
        subtype = random.choice(["ssl","ipsec"])

        if mode < 0.45:
            lines.append(forti_line(dt_conn, devname, devid, "SSL VPN tunnel established",
                                    user, srcip, assigned_ip, subtype, extra=[f"duration=0"]))
        elif mode < 0.85:
            dur = random.randint(MIN_SESSION_SEC, MAX_SESSION_SEC)
            reason = random.choice(["User logout","Idle timeout","Network error"])
            lines.append(forti_line(dt_conn, devname, devid, "SSL VPN tunnel disconnected",
                                    user, srcip, assigned_ip, subtype, extra=[f"duration={dur}", f"reason=\"{reason}\""]))
        else:
            choice = random.choice(["Re-authentication required","Connection timeout","IKE negotiation failed"])
            extras = []
            if "failed" in choice.lower():
                extras.append("severity=\"error\"")
            lines.append(forti_line(dt_conn, devname, devid, choice, user, srcip, assigned_ip, subtype, extra=extras))
    random.shuffle(lines)
    return lines[:target_rows]

# ==============================
# 3) AZURE GENERATION (JSONL)
# ==============================
def azure_obj(dt, category, operation, result, message, identity=None, assigned_ip=None, resource_suffix="vpngw1"):
    return {
        "time": dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resourceId": f"/SUBSCRIPTIONS/1111/RESOURCEGROUPS/rg-vpn/PROVIDERS/MICROSOFT.NETWORK/VIRTUALNETWORKGATEWAYS/{resource_suffix}",
        "category": category,
        "operationName": operation,
        "resultType": result,
        "durationMs": random.randint(40, 1800000),
        "message": message,
        **({"identity": identity} if identity else {}),
        **({"assignedIp": assigned_ip} if assigned_ip else {})
    }

def generate_azure_jsonl(target_rows):
    objs = []
    for _ in range(target_rows):
        dt = within_last_days(DAYS_SPAN)
        identity = random.choice(users)
        assigned_ip = rand_assigned_ip()
        r = random.random()
        if r < 0.35:
            objs.append(azure_obj(dt, "TunnelDiagnosticLog", random.choice(azure_ops_connected),
                                  "Success", f"IPsec tunnel established with peer {rand_public_ipv4()}",
                                  identity=identity, assigned_ip=assigned_ip))
        elif r < 0.60:
            reason = random.choice(["UserLogout","IdleTimeout","NetworkError"])
            objs.append(azure_obj(dt, "TunnelDiagnosticLog", "TunnelDisconnected",
                                  reason, f"Tunnel disconnected by {identity}",
                                  identity=identity, assigned_ip=assigned_ip))
        elif r < 0.85:
            op = random.choice(["RouteAdded","GatewayPolicyApplied"])
            objs.append(azure_obj(dt, "GatewayDiagnosticLog", op, "Success",
                                  f"{op} for {identity}"))
        else:
            op = random.choice(azure_ops_failed)
            result = random.choice(["Failure","Timeout","AuthFailed"])
            msg = random.choice([
                "IKE authentication failed (PSK mismatch)",
                "IKE negotiation timeout",
                "No proposal chosen",
                "Peer not responding"
            ])
            objs.append(azure_obj(dt, "IKEDiagnosticLog", op, result, msg, identity=identity))
    random.shuffle(objs)
    return objs[:target_rows]

# ==============================
# MAIN (single mixed file)
# ==============================
if __name__ == "__main__":
    cisco_rows = generate_cisco_rows(SPLIT[0])
    forti_lines = generate_fortinet_lines(SPLIT[1])
    azure_objs = generate_azure_jsonl(SPLIT[2])

    out_cisco = os.path.join(os.getcwd(), "vpn_cisco.log")
    with open(out_cisco, "w", encoding="utf-8", newline="") as f:
        f.write(CISCO_HEADER + "\n")
        for line in cisco_rows:
            f.write(line + "\n")

    out_forti = os.path.join(os.getcwd(), "vpn_fortinet.log")
    with open(out_forti, "w", encoding="utf-8") as f:
        for line in forti_lines:
            f.write(line + "\n")

    out_azure = os.path.join(os.getcwd(), "vpn_azure.log")
    with open(out_azure, "w", encoding="utf-8") as f:
        for obj in azure_objs:
            json.dump(obj, f, ensure_ascii=False)
            f.write("\n")

    print(f"✓ Cisco log written: {out_cisco}")
    print(f"✓ Fortinet log written: {out_forti}")
    print(f"✓ Azure log written: {out_azure}")
    print(f"   Cisco rows  : {len(cisco_rows)}")
    print(f"   Fortinet    : {len(forti_lines)}")
    print(f"   Azure       : {len(azure_objs)}")
