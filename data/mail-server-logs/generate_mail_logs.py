# -*- coding: utf-8 -*-
"""
Generate text-based mail logs in two formats into ONE merged file, chronologically sorted:
1) AIX-like MTA syslog lines (Postfix/Sendmail style)
2) IBM i Mail Server Journal (MSF) single-line structured entries

- Total logs default: 30_000 (50% MTA, 50% MSF)
- Timestamps within the last 30 days
- Uses given domains/relays/statuses/names
- Output: mail_merged.log in current working directory
"""

import os
import random
import string
from datetime import datetime, timedelta, timezone

# --------------------------
# User-provided reference lists
# --------------------------
domains = [
    "example.com", "test.org", "company.net", "mailservice.io", "alpha.tech",
    "securemail.gov", "university.edu", "mailbox.biz", "cloudmail.ai", "fastmail.pro",
    "corporate.co", "researchlab.org", "logistics.inc", "marketing.agency",
    "partner.solutions", "banksecure.fin"
]

relays = [
    "mailrelay.example.net", "mx.test.org", "smtp.company.net", "relay.mailservice.io",
    "smtp1.alpha.tech", "mx.securemail.gov", "outbound.university.edu", "relay.mailbox.biz",
    "smtp.cloudmail.ai", "mx1.fastmail.pro", "relay.corporate.co", "gw.researchlab.org",
    "mail.logistics.inc", "smtp.marketing.agency", "relay.partner.solutions", "smtp.banksecure.fin"
]

statuses = [
    "Sent (250 OK)", "Deferred (450 Timeout)", "Bounced (550 User unknown)",
    "Rejected (554 Relay access denied)", "Bounced (552 Message too large)",
    "Rejected (553 Invalid recipient)", "Deferred (451 Temporary local problem)",
    "Sent (250 Message queued)", "Bounced (554 Transaction failed)",
    "Rejected (550 Spam message blocked)"
]

names = [
    "john", "alice", "bob", "jane", "mark", "susan", "tom", "emma", "oliver", "lucy",
    "michael", "sophia", "daniel", "linda", "charles", "karen", "steven", "laura",
    "james", "emily", "brian", "natalie", "kevin", "olivia", "david", "grace",
    "andrew", "mia", "george", "zoe", "ryan", "chloe", "eric", "hannah",
    "justin", "sara", "adam", "nora", "luke", "bella", "henry", "ava"
]

random.seed(42)

# --------------------------
# Helpers
# --------------------------
MONTH_ABBR = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

def rand_ipv4():
    """Generate a public-ish IPv4 (avoid 0, 255 octets for realism)."""
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def pick_email():
    """Create an email like alice.42@example.com using given names/domains."""
    user = f"{random.choice(names)}.{random.randint(1,99)}"
    dom = random.choice(domains)
    return f"{user}@{dom}"

def syslog_ts(dt):
    """Syslog timestamp: 'Jul 01 00:00:23' (no year, fixed-width day)."""
    mon = MONTH_ABBR[dt.month - 1]
    day = f"{dt.day:2d}"
    return f"{mon} {day} {dt:%H:%M:%S}"

def ibmi_ts(dt):
    """IBM i journal timestamp: 'YYYY-MM-DD-HH.MM.SS.mmmmmm'."""
    return dt.strftime("%Y-%m-%d-%H.%M.%S.") + f"{dt.microsecond:06d}"

def queue_id():
    """MTA queue/message id like 'e73394' / 'y84918' (6 base36-ish chars)."""
    base36 = string.digits + string.ascii_lowercase
    return "".join(random.choice(base36) for _ in range(6))

def msg_id(dt, qid, host):
    """RFC822 style Message-ID bracketed with time + queue id + host."""
    return f"<{dt:%Y%m%d%H%M%S}.{qid}@{host}>"

def pid():
    """Pseudo process id."""
    return random.randint(10000, 99999)

def recipients(n):
    """Return (primary_recipient, nrcpts)."""
    nrcpts = n if n > 0 else 1
    return pick_email(), nrcpts

def proto_for_status(st):
    """ESMTP for most, sometimes SMTP for rejections to mimic variety."""
    if "Rejected" in st or "Bounced" in st:
        return random.choice(["ESMTP", "SMTP"])
    return "ESMTP"

def msf_entry_type_from_status(st):
    """Map MTA delivery status to IBM i journal entry type."""
    if st.startswith("Sent"):
        return "MDELV"  # delivered
    if st.startswith("Deferred"):
        return "MSENT"  # sent/queued, pending
    if st.startswith("Bounced") or st.startswith("Rejected"):
        return "MFAIL"
    return "MSENT"

def status_to_compact(st):
    """Extract compact status keyword for IBM i line (SENT/FAILED/DEFERRED/REJECTED)."""
    if st.startswith("Sent"):
        return "SENT"
    if st.startswith("Deferred"):
        return "DEFERRED"
    if st.startswith("Bounced"):
        return "FAILED"
    if st.startswith("Rejected"):
        return "REJECTED"
    return "SENT"

# --------------------------
# Generators
# --------------------------
def gen_mta_syslog_line(dt, host="aixhost"):
    """Generate one AIX-like MTA syslog line."""
    qid = queue_id()
    frm = pick_email()
    to_addr, nrcpts = recipients(random.choice([1,1,1,2]))  # mostly 1, sometimes 2
    relay_host = random.choice(relays)
    relay_ip = rand_ipv4()
    st = random.choice(statuses)
    proto = proto_for_status(st)
    dly = round(random.uniform(1.0, 30.0), 2)
    size = random.randint(900, 20000)
    mid = msg_id(dt, qid, host)
    return (
        f"{syslog_ts(dt)} {host} MTA[{pid()}]: {qid}: "
        f"from=<{frm}>, to=<{to_addr}>, "
        f"relay={relay_host} [{relay_ip}], proto={proto}, "
        f"delay={dly}, size={size}, nrcpts={nrcpts}, msgid={mid}, status={st}"
    )

def gen_ibmi_msf_line(dt):
    """
    Generate one IBM i Mail Server Journal single-line entry, key=value style
    (kept to one line for merged file convenience).
    """
    frm = pick_email().upper()
    to_addr = pick_email().upper()
    st = random.choice(statuses)
    etype = msf_entry_type_from_status(st)    # MSENT/MDELV/MFAIL
    compact = status_to_compact(st)           # SENT/DEFERRED/FAILED/REJECTED
    size = random.randint(900, 20000)
    # A QZHB-like message id: prefix + 12 digits
    qzhb = "QZHB" + "".join(random.choice(string.digits) for _ in range(12))
    reason = st.split("(", 1)[-1].rstrip(")") if "(" in st else "OK"

    # One-line structured (journal-inspired)
    # Example:
    # 2025-07-01-10.15.23.000123 MSENT Sender=USER@DOM Recipient=USER@DOM MsgID=QZHB... Size=2048 Status=DEFERRED Reason="451 Temporary local problem"
    return (
        f"{ibmi_ts(dt)} {etype} "
        f"Sender={frm} Recipient={to_addr} "
        f"MsgID={qzhb} Size={size} "
        f"Status={compact} Reason=\"{reason}\""
    )

# --------------------------
# Main
# --------------------------
def sample_timestamp_last_30_days(now_utc):
    """Random timestamp in the last 30 days (UTC)."""
    delta = timedelta(seconds=random.randint(0, 30*24*3600))
    return (now_utc - delta).astimezone(timezone.utc)

def generate_logs(total=30_000, mta_out="mail_mta.log", msf_out="mail_msf.log"):
    """Generate total logs split evenly between MTA and MSF, write to separate files."""
    assert total % 2 == 0, "Total should be divisible by 2."
    per_type = total // 2
    now = datetime.now(timezone.utc)

    mta_records = []
    msf_records = []

    for _ in range(per_type):
        dt = sample_timestamp_last_30_days(now)
        line = gen_mta_syslog_line(dt, host=random.choice(["aixhost","mailgw1","postfix01"]))
        mta_records.append((dt, line))

    for _ in range(per_type):
        dt = sample_timestamp_last_30_days(now)
        line = gen_ibmi_msf_line(dt)
        msf_records.append((dt, line))

    mta_records.sort(key=lambda x: x[0])
    msf_records.sort(key=lambda x: x[0])

    mta_path = os.path.join(os.getcwd(), mta_out)
    msf_path = os.path.join(os.getcwd(), msf_out)

    with open(mta_path, "w", encoding="utf-8") as f1:
        for _, line in mta_records:
            f1.write(line + "\n")

    with open(msf_path, "w", encoding="utf-8") as f2:
        for _, line in msf_records:
            f2.write(line + "\n")

    return mta_path, msf_path, len(mta_records), len(msf_records)

if __name__ == "__main__":
    mta_path, msf_path, n_mta, n_msf = generate_logs()
    print(f"✔ MTA logları yazıldı: {mta_path} ({n_mta} kayıt)")
    print(f"✔ MSF logları yazıldı: {msf_path} ({n_msf} kayıt)")

