#!/usr/bin/env python3
"""
ATDP Triage Agent
Accepts a Splunk alert as JSON (stdin or file arg), sends it to Claude,
returns a structured triage decision, and logs everything to triage_log.jsonl.

Usage:
  echo '{"src_ip":"185.220.101.47","alert":"SSH Brute Force"}' | python3 triage_agent.py
  python3 triage_agent.py alert.json
  python3 triage_agent.py --demo   # runs against a built-in sample alert
"""

import sys
import json
import os
import datetime
import argparse
import textwrap

import anthropic

# ── Config ────────────────────────────────────────────────────────────────────
MODEL            = "claude-opus-4-7"
LOG_FILE         = "triage_log.jsonl"
MAX_TOKENS       = 1024

SYSTEM_PROMPT = """\
You are an elite Active Defense analyst with deep expertise in MITRE ATT&CK,
MITRE ATLAS (adversarial ML), and enterprise threat intelligence. You receive
raw Splunk alert JSON and return a precise, structured triage decision.

Your environment includes:
- A deception layer with 8 honeytoken files watched by auditd (key=decoy_access)
- A Cowrie SSH honeypot on port 2222
- AI-powered attacker agents that self-annotate with MITRE ATLAS techniques
- Detection rules covering SSH brute force, decoy file access, port scanning, honeypot hits

Respond ONLY with a valid JSON object matching this exact schema — no prose, no markdown:
{
  "risk_score": <integer 0-100>,
  "mitre_attack_technique": "<ID> - <Name>",
  "mitre_atlas_technique": "<ID> - <Name> or N/A if not applicable",
  "likely_actor_type": "<human | automated | AI-assisted>",
  "confidence_level": "<low | medium | high | critical>",
  "investigation_steps": ["<step 1>", "<step 2>", ...],
  "is_deception_layer_hit": <true | false>,
  "recommended_action": "<one clear directive>",
  "analyst_summary": "<2-3 sentence narrative for the incident ticket>"
}

Risk score guidance:
  0-19   Informational — normal ops, no action
  20-49  Low — log and monitor, no immediate response
  50-74  Medium — investigate within 4 hours
  75-89  High — investigate within 1 hour, consider blocking
  90-100 Critical — immediate response, escalate to IR, assume breach

For is_deception_layer_hit: true if the alert involves cowrie port 2222,
auditd key=decoy_access, or any access to paths ending in .bak/.old/.1."""

DEMO_ALERT = {
    "_time": "2024-01-15T02:31:07.000Z",
    "host": "prod-api-01",
    "alert_name": "Decoy File Access — Deception Layer Hit",
    "src_ip": "185.220.101.47",
    "sourcetype": "linux:audit",
    "type": "SYSCALL",
    "syscall": "openat",
    "key": "decoy_access",
    "name": "/root/.aws/credentials.bak",
    "comm": "python3",
    "exe": "/usr/bin/python3.9",
    "pid": "14432",
    "uid": "0",
    "auid": "4294967295",
    "preceding_events": [
        "02:14:00 — SSH brute force from same src_ip (185.220.101.47), 16 failures in 60s",
        "02:31:00 — Cowrie honeypot connection from 185.220.101.47 on port 2222",
        "02:31:06 — Cowrie login success (root/toor)",
        "02:31:09 — Cowrie CMD: ls /root/.ssh/",
    ],
    "geo_ip": {"country": "Netherlands", "asn": "AS4766", "org": "Tor exit node"},
    "environment": "production"
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_alert(args):
    if args.demo:
        return DEMO_ALERT
    if args.file:
        with open(args.file) as f:
            return json.load(f)
    raw = sys.stdin.read().strip()
    if not raw:
        sys.exit("[!] No alert data. Pipe JSON or pass --file / --demo")
    return json.loads(raw)


def call_claude(alert_json: dict) -> dict:
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    user_message = f"""Triage this Splunk alert and return your structured JSON decision:

```json
{json.dumps(alert_json, indent=2)}
```

Remember: respond with ONLY the JSON object, no surrounding text."""

    response = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw_text = response.content[0].text.strip()

    # Strip markdown code fences if Claude added them despite instructions
    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]
    raw_text = raw_text.strip()

    return json.loads(raw_text)


def log_decision(alert: dict, decision: dict):
    record = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "alert": alert,
        "triage": decision,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


# ── Terminal rendering ────────────────────────────────────────────────────────

RISK_COLORS = {
    range(0,  20): "\033[32m",   # green
    range(20, 50): "\033[33m",   # yellow
    range(50, 75): "\033[38;5;208m",  # orange
    range(75, 90): "\033[31m",   # red
    range(90,101): "\033[1;31m", # bold red
}
RESET = "\033[0m"
BOLD  = "\033[1m"
CYAN  = "\033[36m"
PURPLE= "\033[35m"

def risk_color(score: int) -> str:
    for r, color in RISK_COLORS.items():
        if score in r:
            return color
    return ""

def render(alert: dict, d: dict):
    score   = d.get("risk_score", 0)
    color   = risk_color(score)
    bar_len = score // 5
    bar     = "█" * bar_len + "░" * (20 - bar_len)

    deception = d.get("is_deception_layer_hit", False)
    deception_str = f"\033[1;31m⚠  DECEPTION LAYER HIT{RESET}" if deception else f"\033[32m✓  Clean path{RESET}"

    steps = d.get("investigation_steps", [])
    steps_str = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(steps))

    print()
    print(f"{BOLD}{'═'*62}{RESET}")
    print(f"{BOLD}  ATDP Triage Decision{RESET}  [{alert.get('host','unknown')}]  {alert.get('_time','')}")
    print(f"{'═'*62}{RESET}")
    print()
    print(f"  {BOLD}Risk Score{RESET}   {color}{BOLD}{score:>3}/100{RESET}  {color}{bar}{RESET}")
    print(f"  {BOLD}Confidence{RESET}   {d.get('confidence_level','').upper()}")
    print(f"  {BOLD}Actor Type{RESET}   {d.get('likely_actor_type','')}")
    print()
    print(f"  {CYAN}{BOLD}ATT&CK Technique{RESET}  {d.get('mitre_attack_technique','N/A')}")
    print(f"  {PURPLE}{BOLD}ATLAS Technique  {RESET}  {d.get('mitre_atlas_technique','N/A')}")
    print()
    print(f"  {deception_str}")
    print()
    print(f"  {BOLD}Recommended Action{RESET}")
    print(f"  {color}▶  {d.get('recommended_action','')}{RESET}")
    print()
    print(f"  {BOLD}Investigation Steps{RESET}")
    print(steps_str)
    print()
    print(f"  {BOLD}Analyst Summary{RESET}")
    summary = d.get("analyst_summary","")
    for line in textwrap.wrap(summary, width=56):
        print(f"  {line}")
    print()
    print(f"{'═'*62}")
    print(f"  Logged to {LOG_FILE}")
    print(f"{'═'*62}")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ATDP AI Triage Agent")
    parser.add_argument("file", nargs="?", help="Path to alert JSON file")
    parser.add_argument("--demo", action="store_true", help="Run against built-in demo alert")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("[!] Set ANTHROPIC_API_KEY environment variable first.")

    print("[*] Loading alert...")
    alert = load_alert(args)

    print(f"[*] Sending to Claude ({MODEL}) for triage...")
    try:
        decision = call_claude(alert)
    except json.JSONDecodeError as e:
        sys.exit(f"[!] Claude returned invalid JSON: {e}")
    except Exception as e:
        sys.exit(f"[!] API error: {e}")

    log_decision(alert, decision)
    render(alert, decision)

    # Machine-readable output for piping into other tools
    if "--json" in sys.argv:
        print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
