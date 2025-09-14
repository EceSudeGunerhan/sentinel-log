import os
import random
import uuid
import ipaddress
from datetime import datetime, timedelta, timezone
import json

# ==============================
# Config
# ==============================
random.seed(42)

TOTAL_PER_FORMAT = 15000      # 15k + 15k = 30k total
ALLOW_RATIO_GCP = 0.80
ALLOW_RATIO_PROXY = 0.85
DAYS_SPAN = 30

OUTPUT_FILENAME = "combined_proxy_logs.log"

users = [
    "alice", "bob", "charlie", "diana", "eve", "frank", "grace", "heidi", "ivan", "judy",
    "karen", "leo", "mallory", "ned", "olivia", "peggy", "quinn", "rick", "sybil", "trent",
    "ursula", "victor", "wendy", "xavier", "yasmine", "zach", "ayse", "mehmet", "fatma", "ahmet",
    "sinem", "burak", "elif", "mert", "selin", "can", "gizem", "baran", "berfin", "enes"
]

# ==============================
# Utils
# ==============================
def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

def rand_ts_within(days: int = 30) -> str:
    now = datetime.now(timezone.utc)
    delta_seconds = random.randint(0, days * 24 * 3600)
    ts = now - timedelta(seconds=delta_seconds)
    return utc_iso(ts)

def rand_private_ip_with_port() -> str:
    nets = [ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16")]
    net = random.choice(nets)
    a, b, c, d = [random.randint(1, 254) for _ in range(4)]
    host_ip = f"{a}.{b}.{c}.{d}"
    return f"{host_ip}:{random.randint(1024, 65535)}"

def rand_public_ip_with_port() -> str:
    while True:
        a, b, c, d = [random.randint(1, 254) for _ in range(4)]
        ip_ = ipaddress.ip_address(f"{a}.{b}.{c}.{d}")
        if not ip_.is_private:
            return f"{ip_}:{random.choice([80, 443])}"

def rand_user_agent() -> str:
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1.15",
        "curl/7.74.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Firefox/125.0",
        "PostmanRuntime/7.39.0"
    ]
    return random.choice(agents)

def rand_domain():
    return random.choice([
        "www.example.com", "accounts.google.com", "www.youtube.com", "api.github.com",
        "login.microsoftonline.com", "cdn.jsdelivr.net", "news.ycombinator.com",
        "portal.office.com", "graph.facebook.com", "api.openai.com"
    ])

def rand_url():
    domain = rand_domain()
    paths = ["/", "/login", "/search?q=test", "/watch?v=abc123", "/docs", "/v1/user/profile"]
    return f"https://{domain}{random.choice(paths)}"

def rand_http_method(deny=False):
    return "CONNECT" if deny and random.random() < 0.5 else random.choice(["GET","POST","PUT","DELETE"])

def rand_category():
    return random.choice([
        "Business", "Streaming Media", "Social Networking",
        "Content Delivery Networks", "Malware", "Education"
    ])

def rand_identity():
    return random.choice(users)

def rand_status(deny=False):
    return random.choice([403,407,451]) if deny else random.choice([200,204,301,302,404,500])

def pick_action(deny=False):
    return "DENIED" if deny else "ALLOWED"

# ==============================
# Generators
# ==============================
def make_gcp_swp_entry(allow=True):
    deny = not allow
    hostname = rand_domain()
    method = rand_http_method(deny)
    obj = {
        "httpRequest": {
            **({"requestUrl": f"https://{hostname}/"} if method != "CONNECT" else {}),
            "requestMethod": method,
            "status": rand_status(deny),
            "userAgent": rand_user_agent(),
            "remoteIp": rand_private_ip_with_port(),
            "serverIp": rand_public_ip_with_port(),
            "latency": f"0.{random.randint(1,999999):06d}s",
            "protocol": random.choice(["HTTP/1.1","HTTP/2"])
        },
        "enforcedGatewaySecurityPolicy": {
            "hostname": hostname if method!="CONNECT" else f"{hostname}:443",
            "matchedRules": [
                {"action":"ALLOWED"} if allow else {"action":"DENIED"}
            ]
        },
        "timestamp": rand_ts_within(DAYS_SPAN),
        "severity": "INFO" if allow else "WARNING",
        "identity": rand_identity()
    }
    return json.dumps(obj, ensure_ascii=False)

def make_umbrella_text_line(allow=True):
    deny = not allow
    return " ".join([
        f"timestamp={rand_ts_within(DAYS_SPAN)}",
        f"identity={rand_identity()}",
        f"src_ip={rand_private_ip_with_port().split(':')[0]}",
        f"method={rand_http_method(deny)}",
        f"url={rand_url() if not deny else rand_domain()+':443'}",
        f"status={rand_status(deny)}",
        f"category={rand_category().replace(' ','_')}",
        f"action={pick_action(deny)}",
        f"user_agent=\"{rand_user_agent()}\"",
        f"request_id={uuid.uuid4()}"
    ])

# ==============================
# Main
# ==============================
if __name__ == "__main__":
    out_gcp = os.path.join(os.getcwd(), "gcp_proxy.log")
    out_umbrella = os.path.join(os.getcwd(), "umbrella_proxy.log")

    with open(out_gcp, "w", encoding="utf-8") as f:
        for _ in range(TOTAL_PER_FORMAT):
            f.write(make_gcp_swp_entry(allow=(random.random() < ALLOW_RATIO_GCP)) + "\n")

    with open(out_umbrella, "w", encoding="utf-8") as f:
        for _ in range(TOTAL_PER_FORMAT):
            f.write(make_umbrella_text_line(allow=(random.random() < ALLOW_RATIO_PROXY)) + "\n")

    print(f"✓ GCP Proxy log written to: {out_gcp}")
    print(f"✓ Umbrella Proxy log written to: {out_umbrella}")
    print(f"Total entries: {TOTAL_PER_FORMAT * 2}")

