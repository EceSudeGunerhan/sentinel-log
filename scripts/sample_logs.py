import pathlib, json, random
random.seed(42)  # deterministic sampling

BASE = pathlib.Path("data")
OUT_FILE = pathlib.Path("artifacts/sampled_logs.jsonl")

# windows_dhcp.log, analytical_dhcp.log, win_debug.log kaldırıldı
FILE_PATHS = [
    "dhcp-logs/syslog_dhcp.log",

    "dns-logs/bind_category.log",
    "dns-logs/bind_syslog.log",
    "dns-logs/umbrella_text.log",
    "dns-logs/win_analytic.log",

    "firewall-logs/cdfw_firewall.log",
    "firewall-logs/tmg_firewall.log",

    "ids-ips-logs/cisco_ips.log",
    "ids-ips-logs/cisco_sdee.log",
    "ids-ips-logs/gcp_ids.log",

    "mail-server-logs/mail_msf.log",
    "mail-server-logs/mail_mta.log",

    "proxy-logs/gcp_proxy.log",
    "proxy-logs/umbrella_proxy.log",

    "vpn-logs/vpn_azure.log",
    "vpn-logs/vpn_cisco.log",
    "vpn-logs/vpn_fortinet.log",

    "web-server-logs/web_server_logs_sample.log",
]

TOTAL_SAMPLES = 2000
PER_FILE_BASE = TOTAL_SAMPLES // len(FILE_PATHS)
PER_FILE_EXTRA = TOTAL_SAMPLES % len(FILE_PATHS)

def sample_file(path: pathlib.Path, n: int):
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if not lines:
        return []
    if len(lines) >= n:
        return random.sample(lines, n)
    # file shorter → take all, pad with duplicates
    picked = list(lines)
    picked += random.choices(lines, k=n - len(lines))
    return picked

def main():
    present = []
    for rel in FILE_PATHS:
        fpath = BASE / rel
        if fpath.exists():
            present.append(rel)
        else:
            print(f"Missing: {fpath}")

    if not present:
        print("No input files found under 'data/'.")
        return

    sampled = []
    for i, rel in enumerate(present):
        fpath = BASE / rel
        n = PER_FILE_BASE + (1 if i < PER_FILE_EXTRA else 0)
        lines = sample_file(fpath, n)
        for line in lines:
            sampled.append({"source_file": rel, "raw": line})

    random.shuffle(sampled)

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for rec in sampled:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Saved {len(sampled)} logs to {OUT_FILE}")

if __name__ == "__main__":
    main()
