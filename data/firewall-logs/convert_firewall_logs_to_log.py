import random
from datetime import datetime, timedelta
import pytz

# --- 1) YARDIMCI ÜRETİCİLER -------------------------------------------------
def random_ip(public=False):
    if public:
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return random.choice([
            f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
            f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ])

def consistent_port(protocol):
    port_map = {
        "TCP": [80, 443, 22, 3389, 8080, 8443],
        "UDP": [53, 123, 161, 500, 4500, 1194, 3478],
        "ICMP": [0]
    }
    if protocol == "ICMP":
        return 0
    return random.choice(port_map.get(protocol, [random.randint(1024, 49151)]))

def validate_action_rule(action, protocol):
    if action == "DENY":
        return f"{protocol}-BLOCK-{random.randint(100, 999)}"
    return random.choice([
        f"{protocol}-ACCESS-{random.randint(100, 999)}",
        f"ALLOW-{random.randint(1000, 9999)}"
    ])

def random_timestamp(start, end):
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("start ve end timezone-aware olmalı")
    delta = end - start
    sec = random.randint(0, int(delta.total_seconds()))
    ms = random.randint(0, 999)
    return start + timedelta(seconds=sec, milliseconds=ms)

def random_user():
    return random.choice([
        f"DOMAIN\\user{random.randint(1, 100)}",
        f"admin{random.randint(1, 20)}",
        f"svc-{random.choice(['web', 'db', 'app'])}{random.randint(1, 15)}",
        f"guest{random.randint(1000, 9999)}"
    ])

def random_fqdn():
    domains = {
        "google.com": ["drive", "meet", "docs"],
        "microsoft.com": ["azure", "teams", "sharepoint"],
        "apple.com": ["icloud", "appstore"]
    }
    main = random.choice(list(domains.keys()))
    return f"{random.choice(domains[main])}.{main}" if random.random() > 0.5 else main

# --- 2) LOG OLUŞTURUCULAR ---------------------------------------------------
def generate_tmg_log(timestamp):
    protocol = random.choice(["TCP", "UDP", "ICMP"])
    action = random.choice(["ALLOW", "DENY"])
    src_port = "" if protocol == "ICMP" else f":{consistent_port(protocol)}"
    dst_port = "" if protocol == "ICMP" else f":{consistent_port(protocol)}"
    source_ip = random_ip(public=False)
    dest_ip = random_ip(public=(random.random() > 0.2))
    user = random_user()
    auth_method = "ANON" if "guest" in user else random.choice(["AUTH", "NTLM", "KERBEROS"])
    return (
        f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')}|TMG|"
        f"SRV-{random.choice(['WEB', 'DB', 'APP', 'DC'])}{random.randint(1, 20)}|"
        f"{protocol}|"
        f"{source_ip}{src_port}|"
        f"{dest_ip}{dst_port}|"
        f"{action}|"
        f"{validate_action_rule(action, protocol)}|"
        f"{random.randint(0, 10000)}|"
        f"{random.randint(0, 5000)}|"
        f"{user}|"
        f"{auth_method}|"
        f"{random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])}"
    )

def generate_cdfw_log(timestamp):
    protocol = random.choice(["TCP", "UDP", "ICMP"])
    action = random.choice(["ALLOW", "BLOCK"])
    direction = random.choice(["INBOUND", "OUTBOUND"])

    if direction == "INBOUND":
        src_ip = random_ip(public=True)
        dst_ip = random_ip(public=False)
    else:
        src_ip = random_ip(public=False)
        dst_ip = random_ip(public=True)

    dst_port = "" if protocol == "ICMP" else f":{consistent_port(protocol)}"
    server_origin = f"GW{random.randint(1,5)}-{direction}"
    fqdn_or_rule = random_fqdn()
    bytes_sent = random.randint(0, 10000)
    bytes_recv = random.randint(0, 5000)
    traffic_source = random_ip(public=True)
    country = random.choice(["US", "GB", "DE", "TR", "CN"])
    policy = f"{random.choice(['IT', 'SALES', 'HR'])}-{random.randint(100, 999)}"

    return (
        f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')}|CDFW|"
        f"{server_origin}|"
        f"{protocol}|"
        f"{src_ip}|"
        f"{dst_ip}{dst_port}|"
        f"{action}|"
        f"{fqdn_or_rule}|"
        f"{bytes_sent}|"
        f"{bytes_recv}|"
        f"{traffic_source}|"
        f"{country}|"
        f"{policy}"
    )

# --- 3) AYRI AYRI YAZIM -----------------------------------------------------
def generate_logs_separate(tmg_file="tmg_firewall.log", cdfw_file="cdfw_firewall.log", total_entries=30000):
    end_date = datetime.now(pytz.UTC)
    start_date = end_date - timedelta(days=30)
    half = total_entries // 2

    with open(tmg_file, "w", encoding="utf-8") as tmg_f, \
         open(cdfw_file, "w", encoding="utf-8") as cdfw_f:

        header = "# Timestamp|LogType|Server/Origin|Protocol|Source|Destination|Action|Rule/FQDN|BytesSent|BytesRecv|User/TrafficSource|Auth/Country|Policy\n"
        tmg_f.write(header)
        cdfw_f.write(header)

        for _ in range(half):
            ts = random_timestamp(start_date, end_date)
            tmg_f.write(generate_tmg_log(ts) + "\n")

        for _ in range(total_entries - half):
            ts = random_timestamp(start_date, end_date)
            cdfw_f.write(generate_cdfw_log(ts) + "\n")

    print(f"✓ {half} TMG → {tmg_file}")
    print(f"✓ {total_entries - half} CDFW → {cdfw_file}")

# --- 4) ÇALIŞTIR ------------------------------------------------------------
if __name__ == "__main__":
    # random.seed(42)  # istersen deterministik üretim için aktif et
    generate_logs_separate(
        tmg_file="tmg_firewall.log",
        cdfw_file="cdfw_firewall.log",
        total_entries=30000
    )
