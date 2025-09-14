# scripts/normalize_logs.py

import os, json, time, argparse, pathlib, re, random, uuid
from datetime import datetime, timezone
import httpx
from dotenv import load_dotenv
from tqdm import tqdm

from scripts.patterns import extract_basic_fields
from scripts.prompt_templates import SYSTEM_PROMPT, build_user_prompt, CANONICAL_KEYS

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3-32b")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

SLEEP_BETWEEN_S = 0.3
TIMEOUT = 40
MAX_RETRIES = 3


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clean_model_output(txt: str) -> str:
    if "<think>" in txt and "</think>" in txt:
        txt = txt.split("</think>", 1)[-1].strip()
    txt = re.sub(r"^```(json)?", "", txt.strip(), flags=re.I | re.M)
    txt = re.sub(r"```$", "", txt.strip(), flags=re.I | re.M)
    return txt.strip()


def safe_json_from_text(txt: str) -> dict | None:
    txt = clean_model_output(txt)
    try:
        return json.loads(txt)
    except:
        pass
    start = txt.find("{")
    end = txt.rfind("}")
    if start != -1 and end != -1 and end > start:
        block = txt[start:end+1]
        try:
            return json.loads(block)
        except:
            return None
    return None


def call_groq_chat(system_prompt: str, user_prompt: str) -> tuple[dict | None, dict]:
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0,
        "max_tokens": 1024,
    }

    retries = 0
    while retries < MAX_RETRIES:
        t0 = time.perf_counter()
        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                resp = client.post(GROQ_URL, headers=headers, json=payload)
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            data = resp.json()

            if resp.status_code == 429:
                wait_s = 2 ** retries + random.random()
                print(f"[WARN] Rate limit hit. Waiting {wait_s:.2f}s before retry...")
                time.sleep(wait_s)
                retries += 1
                continue

            if resp.status_code >= 400:
                return None, {
                    "status": resp.status_code,
                    "error": data.get("error", data),
                    "latency_ms": elapsed_ms,
                }

            content = data["choices"][0]["message"]["content"]
            parsed = safe_json_from_text(content)
            if parsed:
                return parsed, {
                    "status": resp.status_code,
                    "latency_ms": elapsed_ms,
                }
            else:
                print(f"[WARN] JSON parse failed. Retrying... ({retries+1})")
                retries += 1
                time.sleep(1.5)
        except Exception as e:
            wait_s = 2 ** retries
            print(f"[ERROR] Exception: {e}. Retrying in {wait_s}s...")
            time.sleep(wait_s)
            retries += 1

    return None, {"status": "fail", "error": "Max retries exceeded"}


def coerce_canonical(obj: dict) -> dict:
    fixed = {k: obj.get(k, None) for k in CANONICAL_KEYS}
    for k in CANONICAL_KEYS:
        if k not in fixed:
            fixed[k] = None
    return fixed


def fallback_record(pre: dict, raw: str, source_file: str) -> dict:
    """Fallback: even if LLM fails, build a minimal generic record."""
    sev = "info"
    if re.search(r"\berror\b", raw, re.I):
        sev = "error"
    elif re.search(r"\bwarn(ing)?\b", raw, re.I):
        sev = "warn"
    elif re.search(r"\bcritical\b", raw, re.I):
        sev = "critical"

    return {
        "timestamp_iso": pre.get("timestamp_iso"),
        "source": source_file or None,
        "src_ip": pre.get("src_ip"),
        "dst_ip": pre.get("dst_ip"),
        "protocol": pre.get("protocol"),
        "process": pre.get("process"),
        "severity": sev,
        "category": "system",  # LLM tahmini yoksa fallback
        "status_code": pre.get("status_code"),
        "message": raw[:200],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="artifacts/sampled_logs.jsonl")
    ap.add_argument("--output", default="artifacts/normalized_logs.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    inp = pathlib.Path(args.input)
    outp = pathlib.Path(args.output)
    outp.parent.mkdir(parents=True, exist_ok=True)

    if not inp.exists():
        print(f"Input not found: {inp}")
        return
    if not GROQ_API_KEY:
        print("Missing GROQ_API_KEY in .env")
        return

    total, written = 0, 0
    with inp.open("r", encoding="utf-8", errors="ignore") as fin, \
         outp.open("w", encoding="utf-8") as fout:

        for line in tqdm(fin, desc="Normalizing", unit="log"):
            if args.limit and total >= args.limit:
                break
            total += 1
            try:
                rec = json.loads(line)
                raw = rec.get("raw", "")
                source_file = rec.get("source_file", "")

                pre = extract_basic_fields(raw)
                user_prompt = build_user_prompt(raw, pre)

                parsed, meta = call_groq_chat(SYSTEM_PROMPT, user_prompt)

                if not parsed:
                    fixed = fallback_record(pre, raw, source_file)
                else:
                    for k, v in pre.items():
                        if parsed.get(k) in (None, "") and v is not None:
                            parsed[k] = v
                    fixed = coerce_canonical(parsed)
                    if not fixed.get("source"):
                        fixed["source"] = source_file or None

                fout.write(json.dumps(fixed, ensure_ascii=False) + "\n")
                written += 1

                time.sleep(SLEEP_BETWEEN_S)

            except Exception as e:
                fb = {
                    "timestamp_iso": None,
                    "source": None,
                    "src_ip": None,
                    "dst_ip": None,
                    "protocol": None,
                    "process": None,
                    "severity": "info",
                    "category": "system",
                    "status_code": None,
                    "message": line[:200],
                }
                fout.write(json.dumps(fb, ensure_ascii=False) + "\n")

    print(f"\nDone. total={total}, written={written}")
    print(f"Output -> {outp}")


if __name__ == "__main__":
    main()
