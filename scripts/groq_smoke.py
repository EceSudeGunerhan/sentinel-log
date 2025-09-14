# -*- coding: utf-8 -*-
# Minimal Groq smoke test (single provider, e.g. Qwen or Llama)
# Sends a 1-sentence prompt and measures latency.
# Comments are in English per user's preference.

import os, time, csv, pathlib
import httpx
from dotenv import load_dotenv
from tabulate import tabulate

load_dotenv()

ARTIFACTS = pathlib.Path(__file__).resolve().parents[1] / "artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)
CSV_PATH = ARTIFACTS / "groq_smoke_results.csv"

API_KEY = os.getenv("GROQ_API_KEY")
MODEL = os.getenv("GROQ_MODEL")  # e.g., "qwen/qwen3-32b" or "llama-3.1-8b-instant"

PROMPT = "Return exactly one word: pong."

def now_ms():
    return int(time.perf_counter() * 1000)

def post_chat_groq(prompt: str):
    if not API_KEY or not MODEL:
        return {"ok": False, "error": "Missing GROQ_API_KEY or GROQ_MODEL in .env."}

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 5,
    }

    start = now_ms()
    try:
        with httpx.Client(timeout=20) as client:
            resp = client.post(url, headers=headers, json=payload)
        elapsed = now_ms() - start
        data = resp.json()
        if resp.status_code >= 400:
            return {
                "ok": False,
                "latency_ms": elapsed,
                "status": resp.status_code,
                "error": data.get("error", data),
            }

        content = data["choices"][0]["message"]["content"].strip()
        return {
            "ok": True,
            "latency_ms": elapsed,
            "status": resp.status_code,
            "sample": content,
        }
    except Exception as e:
        elapsed = now_ms() - start
        return {"ok": False, "latency_ms": elapsed, "error": str(e)}

def main():
    result = post_chat_groq(PROMPT)
    headers = ["ok", "latency_ms", "status", "sample", "error"]
    row = [[
        str(result.get("ok")),
        str(result.get("latency_ms")),
        str(result.get("status")),
        str(result.get("sample") or "")[:80],
        str(result.get("error") or "")[:120],
    ]]
    print(tabulate(row, headers=headers, tablefmt="github"))

    # Save CSV
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerow({k: str(result.get(k, "")) for k in headers})
    print(f"\nSaved: {CSV_PATH}")

if __name__ == "__main__":
    main()
