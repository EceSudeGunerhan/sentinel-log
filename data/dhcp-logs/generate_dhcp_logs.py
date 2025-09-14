import random
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

# ===============================
# CONFIG (editable)
# ===============================
TOTAL_RECORDS = 30000            # total across all formats
PER_FORMAT = TOTAL_RECORDS // 3  # 10k each
DAYS_BACK = 30                   # spread timestamps over last N days
SEED = 20250816                  # reproducibility

OUT_MIXED = "dhcp_mixed.log"

NETWORK = IPv4Network("192.168.1.0/24")
SERVER_IP = IPv4Address("192.168.1.1")

random.seed(SEED)

# ===============================
# HELPERS
# ===============================
def rand_mac() -> str:
    """Generate a locally-administered unicast MAC (upper-case, colon-separated)."""
    mac = [0x02, 0x00, 0x00,
           random.randint(0x00, 0x7F),
           random.randint(0x00, 0xFF),
           random.randint(0x00, 0xFF)]
    return ":".join(f"{b:02X}" for b in mac)

def rand_hostname() -> str:
    """Generate a simple hostname with domain."""
    prefix = random.choice(["PC", "LAP", "SRV", "NAS", "IOT"])
    num = random.randint(1, 999)
    domain = random.choice(["local", "lan", "contoso.local", "corp.local"])
    return f"{prefix}{num}.{domain}"

def sample_ips(net: IPv4Network, count=400):
    """Pick 'count' usable IPs, skipping network/broadcast/server."""
    pool = []
    for ip in net.hosts():
        if ip in (net.network_address, net.broadcast_address, SERVER_IP):
            continue
        pool.append(ip)
        if len(pool) >= count:
            break
    return pool

def rand_time_within(days_back: int) -> datetime:
    """Random timestamp within last 'days_back' days."""
    now = datetime.now()
    delta = timedelta(seconds=random.randint(0, days_back * 24 * 3600))
    return now - delta

def mmddyy(dt: datetime) -> str:
    return dt.strftime("%m/%d/%y")

def hhmmss(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S")

def txid() -> str:
    return f"0x{random.getrandbits(32):08x}"

# Windows DHCP Event IDs & descriptions (simplified)
WIN_EVENT = {
    "DISCOVER": 17,
    "OFFER": 16,
    "REQUEST": 10,     # often represented as Assign/Request
    "ACK": 13,
    "RENEW": 11,
    "NAK": 14,
    "DECLINE": 15,
    "RELEASE": 13,
    "INFORM": 18
}
DESC_MAP = {
    "DISCOVER": "DHCPDISCOVER",
    "OFFER": "DHCPOFFER",
    "REQUEST": "DHCPREQUEST",
    "ACK": "DHCPACK",
    "RENEW": "DHCPREQUEST",   # renew is request on wire
    "NAK": "DHCPNACK",
    "DECLINE": "DHCPDECLINE",
    "RELEASE": "DHCPRELEASE",
    "INFORM": "DHCPINFORM"
}

# ===============================
# WRITERS (single event → one output)
# ===============================
def windows_line(event: str, ts: datetime, ip: IPv4Address, host: str, mac: str) -> str:
    """Single-line Windows DHCP CSV-like entry."""
    eid = WIN_EVENT.get(event, 10)
    desc = DESC_MAP.get(event, event)
    # Fields: ID,Date,Time,Description,IP Address,Host Name,MAC Address,User,TransID,QResult,ProbationTime,CorrelationID,DHCID,VendorClass,UserClass,RelayAgentInfo,SubscriberID,ClientDuid,ClientId
    empties = "," * (18 - 6)  # we already populated 6 fields before these empties
    return f"{eid},{mmddyy(ts)},{hhmmss(ts)},{desc},{ip},{host},{mac}{empties}"

def syslog_line(event: str, ts: datetime, host_short: str, iface: str, ip: IPv4Address, mac: str) -> str:
    """Single-line syslog-like entry."""
    t = ts.strftime("%Y-%m-%d %H:%M:%S")
    if event == "DISCOVER":
        return f"{t} {host_short} {iface} DISCOVER DHCPDISCOVER from {mac} via {iface}"
    if event == "OFFER":
        return f"{t} {host_short} {iface} OFFER    DHCPOFFER on {ip} to {mac} via {iface}"
    if event == "REQUEST":
        return f"{t} {host_short} {iface} REQUEST  DHCPREQUEST for {ip} from {mac} via {iface}"
    if event == "ACK":
        return f"{t} {host_short} {iface} ACK      DHCPACK on {ip} to {mac} via {iface}"
    if event == "RENEW":
        return f"{t} {host_short} {iface} RENEW    DHCPREQUEST (renew) for {ip} from {mac} via {iface}"
    if event == "NAK":
        return f"{t} {host_short} {iface} NAK      DHCPNAK to {mac} via {iface}"
    if event == "DECLINE":
        return f"{t} {host_short} {iface} DECLINE  DHCPDECLINE from {mac} for {ip} via {iface}"
    if event == "RELEASE":
        return f"{t} {host_short} {iface} RELEASE  DHCPRELEASE of {ip} from {mac} via {iface}"
    return f"{t} {host_short} {iface} INFO     {event} for {ip} from {mac} via {iface}"

def analytical_block(event: str, ts: datetime, iface: str, server_ip: IPv4Address, ip: IPv4Address, host: str, mac: str) -> str:
    """Multi-line analytical/debug block."""
    lines = [
        f"TIME: {ts.strftime('%Y-%m-%d %H:%M:%S')}",
        f"INTERFACE: {iface}",
        f"CLIENT MAC: {mac}",
    ]
    if event == "DISCOVER":
        lines += [
            "DHCP Message Type: DHCPDISCOVER",
            "Requested IP: 0.0.0.0",
            f"Transaction ID: {txid()}",
            "Parameter List: 1,3,6,15,119",
        ]
    elif event == "OFFER":
        lines += [
            "DHCP Message Type: DHCPOFFER",
            f"Offered IP: {ip}",
            "Lease Time: 86400",
            "Subnet Mask: 255.255.255.0",
            f"Router: {server_ip}",
            f"DNS: {server_ip}",
        ]
    elif event == "REQUEST":
        lines += [
            "DHCP Message Type: DHCPREQUEST",
            f"Requested IP: {ip}",
            f"Server Identifier: {server_ip}",
            f"Hostname: {host}",
        ]
    elif event == "ACK":
        lines += [
            "DHCP Message Type: DHCPACK",
            f"Assigned IP: {ip}",
            f"Lease Start: {ts.strftime('%Y-%m-%d %H:%M:%S')}",
            "Lease Time: 86400",
            f"Options: Router={server_ip}; DNS={server_ip}; Domain=lan.local",
        ]
    elif event == "RENEW":
        lines += [
            "DHCP Message Type: DHCPREQUEST (RENEW)",
            f"Requested IP: {ip}",
            f"Server Identifier: {server_ip}",
        ]
    elif event == "NAK":
        lines += [
            "DHCP Message Type: DHCPNAK",
            "Reason: policy violation or address in use",
        ]
    elif event == "DECLINE":
        lines += [
            "DHCP Message Type: DHCPDECLINE",
            f"Declined IP: {ip}",
            "Reason: duplicate IP detected (gratuitous ARP)",
        ]
    elif event == "RELEASE":
        lines += [
            "DHCP Message Type: DHCPRELEASE",
            f"Released IP: {ip}",
            "Reason: client shutdown",
        ]
    return "\n".join(lines)

# ===============================
# EVENT SEQUENCES
# ===============================
def make_sequence(base_ts: datetime):
    """Return ordered (event, ts) for one lease with realistic branches."""
    seq = []
    d0 = base_ts
    seq.append(("DISCOVER", d0))
    seq.append(("OFFER", d0 + timedelta(milliseconds=random.randint(50, 300))))
    seq.append(("REQUEST", d0 + timedelta(milliseconds=random.randint(120, 500))))
    # NAK branch (5%)
    if random.random() < 0.05:
        seq.append(("NAK", d0 + timedelta(milliseconds=random.randint(140, 700))))
        retry = d0 + timedelta(seconds=random.randint(2, 4))
        seq += [
            ("DISCOVER", retry),
            ("OFFER",    retry + timedelta(milliseconds=random.randint(50, 300))),
            ("REQUEST",  retry + timedelta(milliseconds=random.randint(120, 500))),
            ("ACK",      retry + timedelta(milliseconds=random.randint(140, 700))),
        ]
    else:
        seq.append(("ACK", d0 + timedelta(milliseconds=random.randint(140, 700))))
    # DECLINE branch (15%)
    if random.random() < 0.15:
        seq.append(("DECLINE", d0 + timedelta(milliseconds=random.randint(800, 1600))))
        retry2 = d0 + timedelta(seconds=random.randint(3, 6))
        seq += [
            ("DISCOVER", retry2),
            ("OFFER",    retry2 + timedelta(milliseconds=random.randint(50, 300))),
            ("REQUEST",  retry2 + timedelta(milliseconds=random.randint(120, 500))),
            ("ACK",      retry2 + timedelta(milliseconds=random.randint(140, 700))),
        ]
    # RENEW (40%)
    if random.random() < 0.40:
        seq.append(("RENEW", d0 + timedelta(minutes=random.randint(10, 240))))
    # RELEASE (30%)
    if random.random() < 0.30:
        seq.append(("RELEASE", d0 + timedelta(minutes=random.randint(5, 360))))
    seq.sort(key=lambda x: x[1])
    return seq

# ===============================
# MAIN (ayrı ayrı kaydet)
# ===============================
def main():
    ip_pool = sample_ips(NETWORK, count=500)
    host_pool = [rand_hostname() for _ in range(800)]
    mac_pool = [rand_mac() for _ in range(800)]
    iface_choices = ["eth0", "wlan0", "wlan1", "enp0s3"]

    win_needed = PER_FORMAT
    sys_needed = PER_FORMAT
    dbg_needed = PER_FORMAT

    win_lines, sys_lines, dbg_blocks = [], [], []

    while (len(win_lines) < win_needed) or (len(sys_lines) < sys_needed) or (len(dbg_blocks) < dbg_needed):
        ip = random.choice(ip_pool)
        host = random.choice(host_pool)
        mac = random.choice(mac_pool)
        iface = random.choice(iface_choices)
        base = rand_time_within(DAYS_BACK)

        seq = make_sequence(base)

        for ev, ts in seq:
            if len(win_lines) < win_needed:
                win_lines.append(windows_line(ev, ts, ip, host, mac))
            if len(sys_lines) < sys_needed:
                sys_lines.append(syslog_line(ev, ts, host.split(".")[0], iface, ip, mac))
            if len(dbg_blocks) < dbg_needed:
                dbg_blocks.append(analytical_block(ev, ts, iface, SERVER_IP, ip, host, mac))

            if len(win_lines) >= win_needed and len(sys_lines) >= sys_needed and len(dbg_blocks) >= dbg_needed:
                break

    # dosyaları ayrı ayrı kaydet
    with open("windows_dhcp.log", "w", encoding="utf-8") as f:
        for ln in win_lines:
            f.write(ln + "\n")

    with open("syslog_dhcp.log", "w", encoding="utf-8") as f:
        for ln in sys_lines:
            f.write(ln + "\n")

    with open("analytical_dhcp.log", "w", encoding="utf-8") as f:
        for blk in dbg_blocks:
            f.write(blk + "\n\n")

    print("✅ Log dosyaları oluşturuldu:")
    print(f" - windows_dhcp.log     ({len(win_lines)} satır)")
    print(f" - syslog_dhcp.log      ({len(sys_lines)} satır)")
    print(f" - analytical_dhcp.log  ({len(dbg_blocks)} blok)")

if __name__ == "__main__":
    main()
