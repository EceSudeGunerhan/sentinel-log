#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS multi-format synthetic generator (single merged file, no CSV, no labels)
Formats mixed:
  - BIND category style
  - Windows DNS Debug
  - Windows DNS Analytic (ETW-like)
  - Umbrella-like key=value
  - BIND syslog-like
"""

import argparse
import random
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
import os

SEED = 42
FORMATS = ["bind_category","win_debug","win_analytic","umbrella_text","bind_syslog"]
random.seed(SEED)

def rand_public_ipv4():
    while True:
        ip = IPv4Address(random.randint(int(IPv4Address("8.0.0.0")), int(IPv4Address("223.255.255.255"))))
        s = str(ip)
        if not (s.startswith("10.") or s.startswith("192.168.") or s.startswith("172.")):
            return s

def rand_domain():
    labels = ["www","api","mail","auth","cdn","assets","vpn","portal","secure","login","updates","status","repo"]
    tlds = ["com","net","org","io","dev","co","biz","info","xyz"]
    mid = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(5,10)))
    return f"{random.choice(labels)}.{mid}.{random.choice(tlds)}"

def rand_qtype(): return random.choice(["A","AAAA","MX","TXT","NS","SOA","SRV","CAA","PTR"])
def rand_rcode(): return random.choice(["NOERROR","NXDOMAIN","SERVFAIL","REFUSED","FORMERR"])
def iso_ts(dt):   return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
def bind_ts(dt):  return dt.strftime("%d-%b-%Y %H:%M:%S.") + f"{int(dt.microsecond/1000):03d}"
def syslog_ts(dt):return dt.strftime("%b %d %H:%M:%S")

def dns_wire_name(qname):
    parts = qname.rstrip(".").split(".")
    return "".join([f"({len(p)}){p}" for p in parts]) + "(0)"

def identity_pack():
    username = random.choice(["alice","bob","charlie","diana"])
    domain = random.choice(["example.com","corp.local"])
    device = random.choice(["WIN11-LAPTOP01","MACBOOK-PRO","LINUX-WS01"])
    mg_identity = f"{username}@{domain}"
    return mg_identity, device

def make_timestamps(n, days):
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    return [start + (end - start) * random.random() for _ in range(n)]

# --- generators ---
def gen_bind_category(dt):
    qn = rand_domain(); qt = rand_qtype(); client = rand_public_ipv4()
    return dt, f"{bind_ts(dt)} queries: info: client {client}#{random.randint(1024,65535)}: query: {qn} IN {qt} + (E=0)"

def gen_win_debug(dt):
    hhmmss = dt.strftime("%H:%M:%S")
    client = rand_public_ipv4()
    qname = rand_domain(); qtype = rand_qtype(); rcode = rand_rcode()
    wire = dns_wire_name(qname)
    return dt, f"{hhmmss} PACKET UDP Rcv {client} Q [8081 D {rcode}] {qtype:<6} {wire}"

def gen_win_analytic(dt):
    iface = rand_public_ipv4(); dest = rand_public_ipv4()
    qname = rand_domain(); qtype = rand_qtype(); rcode = rand_rcode()
    return dt, (f"{iso_ts(dt)} | EventID=257 | RESPONSE | TCP=0; InterfaceIP={iface}; "
                f"Destination={dest}; QNAME={qname}; QTYPE={qtype}; RCODE={rcode}")

def gen_umbrella_text(dt):
    mg, device = identity_pack()
    internal_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    external_ip = rand_public_ipv4()
    action = random.choice(["Allowed","Blocked"])
    qname = rand_domain()
    return dt, (f"Timestamp={iso_ts(dt)}; Identity={mg}; Device={device}; InternalIP={internal_ip}; "
                f"ExternalIP={external_ip}; Action={action}; Domain={qname}; QType={rand_qtype()}; RCode={rand_rcode()}")

def gen_bind_syslog(dt):
    host = random.choice(["dns01","resolver-1"])
    return dt, f"{syslog_ts(dt)} {host} named[1234]: client {rand_public_ipv4()} query: {rand_domain()} IN {rand_qtype()}"

GEN_MAP = {
    "bind_category": gen_bind_category,
    "win_debug": gen_win_debug,
    "win_analytic": gen_win_analytic,
    "umbrella_text": gen_umbrella_text,
    "bind_syslog": gen_bind_syslog,
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--total", type=int, default=30000)
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--outdir", type=str, default=".")
    args = ap.parse_args()

    per = args.total // len(FORMATS)
    rem = args.total % len(FORMATS)

    os.makedirs(args.outdir, exist_ok=True)

    for i, fmt in enumerate(FORMATS):
        n = per + (1 if i < rem else 0)
        ts_list = make_timestamps(n, args.days)
        lines = [GEN_MAP[fmt](dt)[1] for dt in ts_list]
        lines.sort()  # istersen zaman sıralı yapma: kaldır

        out_path = os.path.join(args.outdir, f"{fmt}.log")
        with open(out_path, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write(ln + "\n")

        print(f"[OK] {fmt}.log ({len(lines)} kayıt)")


if __name__ == "__main__":
    main()
