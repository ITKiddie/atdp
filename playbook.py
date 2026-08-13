#!/usr/bin/env python3
"""
ATDP Attack Playbook — deterministic adversary-emulation sequence.

This replaces the previous LLM-in-the-loop "attacker brain" with a fixed,
reproducible playbook. Each entry is a decision dict in the SAME schema the
old call_claude() returned, so the executors, logging, and terminal rendering
in attacker_agent.py are unchanged.

Why deterministic instead of an LLM:
  - Reproducibility: detection engineers need the SAME telemetry every run to
    tune Sigma/auditd/Splunk rules and confirm a rule fires.
  - The "AI-driven attacker" ATLAS signature the operator wants to detect is a
    *behavioral cadence* — rapid sequential probes, exhaustive enumeration,
    tight credential cycling — which is produced by the STEP CADENCE and the
    credential list below, not by an LLM narrating. See AI_CADENCE_DELAY.

All targets are the operator's own self-hosted lab decoy host. Every path
below is a honeytoken (.bak/.old fake) created by generate_decoys.py; the
credentials are common defaults aimed at a Cowrie honeypot, not real accounts.

To customize: edit CREDENTIAL_LIST, DECOY_PATHS, or build_playbook() below.
"""

# Rapid inter-step delay (seconds). The tight, machine-uniform cadence is
# itself the AI/automation behavioral signature (MITRE ATLAS) the detection
# stack is meant to flag — a human operator's timing would be irregular.
AI_CADENCE_DELAY = 0.4

# Credential cycling list — common defaults an automated attacker would spray
# against the Cowrie SSH honeypot. The honeypot is configured to accept one of
# these; the rest generate "auth rejected" brute-force telemetry.
CREDENTIAL_LIST = [
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("root", "raspberry"),
    ("admin", "admin"),
    ("root", "admin"),        # honeypot typically accepts this one
]

# Decoy honeytoken files (all fakes from generate_decoys.py). Reading these
# trips the auditd decoy_access watch → the highest-value detection event.
DECOY_PATHS = [
    "/root/.aws/credentials.bak",
    "/root/.ssh/id_rsa.bak",
    "/etc/shadow.old",
    "/root/.bash_history.old",
    "/etc/crontab.bak",
]


def build_playbook(target: str) -> list:
    """Return the ordered list of decision dicts for a full attack simulation.

    Schema per entry matches the old LLM output exactly:
      phase, action, parameters, mitre_attack_technique,
      mitre_atlas_technique, reasoning, narration
    """
    steps = []

    # ── RECON ─────────────────────────────────────────────────────────────────
    steps.append({
        "phase": "RECON",
        "action": "nmap_scan",
        "parameters": {"target": target, "ports": "1-10000", "flags": "-sV --open -T4"},
        "mitre_attack_technique": "T1046 - Network Service Discovery",
        "mitre_atlas_technique": "AML.T0006 - Active Scanning",
        "reasoning": "Simulation start: enumerate open services on the lab host to "
                     "map the attack surface before attempting access.",
        "narration": "Simulated active scan of the lab host — exhaustive, machine-paced "
                     "port sweep is an AML.T0006 automation signature.",
    })
    steps.append({
        "phase": "RECON",
        "action": "http_probe",
        "parameters": {"url": f"http://{target}:8080"},
        "mitre_attack_technique": "T1595.002 - Active Scanning: Vulnerability Scanning",
        "mitre_atlas_technique": "AML.T0006 - Active Scanning",
        "reasoning": "Probe common web port to fingerprint any HTTP service surfaced "
                     "by the scan.",
        "narration": "Probing HTTP service for banner/version data as part of the "
                     "automated recon sweep.",
    })

    # ── INITIAL_ACCESS — credential cycling against the Cowrie honeypot ────────
    for user, pw in CREDENTIAL_LIST:
        steps.append({
            "phase": "INITIAL_ACCESS",
            "action": "ssh_attempt",
            "parameters": {"host": target, "port": 2222, "username": user, "password": pw},
            "mitre_attack_technique": "T1110.001 - Brute Force: Password Guessing",
            "mitre_atlas_technique": "AML.T0016 - Obtain Capabilities",
            "reasoning": f"Cycle default credential {user}:{pw} against the SSH honeypot "
                         f"on 2222. Rapid back-to-back guesses characterize automated spraying.",
            "narration": f"Trying {user}:{pw} — tight credential-cycling cadence is the "
                         f"automated brute-force signature the detection stack should flag.",
        })

    # ── ENUMERATION — post-access recon inside the honeypot shell ──────────────
    for cmd in ["id", "uname -a", "cat /etc/passwd", "ls -la /root", "find / -name '*.bak' 2>/dev/null"]:
        steps.append({
            "phase": "ENUMERATION",
            "action": "cowrie_command",
            "parameters": {"command": cmd},
            "mitre_attack_technique": "T1082 - System Information Discovery",
            "mitre_atlas_technique": "AML.T0007 - Discover ML Artifacts",
            "reasoning": f"Enumerate the compromised (honeypot) host: `{cmd}`. Exhaustive, "
                         f"scripted enumeration is an automation tell.",
            "narration": f"Enumerating host via `{cmd}` — methodical, exhaustive coverage "
                         f"is the automated-actor behavioral signature.",
        })

    # ── EXFIL — read decoy honeytokens (trips auditd decoy_access) ─────────────
    for path in DECOY_PATHS:
        steps.append({
            "phase": "EXFIL",
            "action": "read_decoy",
            "parameters": {"path": path},
            "mitre_attack_technique": "T1552.001 - Unsecured Credentials: Credentials In Files",
            "mitre_atlas_technique": "AML.T0035 - ML Artifact Collection",
            "reasoning": f"Access honeytoken {path}. This is the highest-value detection "
                         f"event — auditd decoy_access should fire immediately.",
            "narration": f"Reading decoy {path} — this deliberately trips the deception "
                         f"layer so the operator can confirm the alert fires.",
        })

    # ── COMPLETE ───────────────────────────────────────────────────────────────
    steps.append({
        "phase": "COMPLETE",
        "action": "complete",
        "parameters": {"summary": "Deterministic adversary-emulation sequence complete: "
                                  "recon, credential spray, enumeration, decoy access."},
        "mitre_attack_technique": "N/A",
        "mitre_atlas_technique": "N/A",
        "reasoning": "Playbook finished; all telemetry generated for rule tuning.",
        "narration": "Simulation complete — full attack telemetry written to the log.",
    })

    return steps
