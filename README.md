# Autonomous Threat Defense Platform (ATDP)

**Built by [IT-Kiddie](https://github.com/ITKiddie)**

> AI-powered attacker vs AI-powered defender with a full deception layer in between. Both agents speak MITRE ATT&CK and ATLAS in real time.

---

## Why I Built This

Most detection engineering work assumes a human on the other end of the keyboard. I wanted to flip that assumption and ask: *what does active defense actually look like when the attacker is also an AI?*

LLM-orchestrated tools don't behave like human attackers. They don't get tired, they don't make timing mistakes, and they read your `/etc/shadow.old` the same way they'd read any other structured text because to them it IS just structured text. That changes how you detect them.

This platform has three layers:

```
[ AI Attacker Agent ]  ──recon/exploit──►  [ Deception Layer ]  ──alerts──►  [ AI Defender / Triage Agent ]
       │                                         │                                       │
  Narrates its own MITRE                   Cowrie honeypot              Maps alert to ATT&CK + ATLAS,
  ATT&CK + ATLAS technique                 Decoy files (auditd)         scores risk, recommends action
  as it attacks                            Fake credentials
```

The thing that makes this different: the attacker AI self-annotates its own actions with MITRE ATLAS techniques as it executes them. So when the defender AI responds, both sides are speaking the exact same framework language.

---

## Repo Structure

```
atdp/
├── sigma/                          # Detection-as-Code (Sigma v2)
│   ├── ai_ssh_brute_force.yml
│   ├── decoy_file_access.yml
│   ├── ai_recon_pattern.yml
│   └── honeypot_service_interaction.yml
├── .github/workflows/
│   └── validate-detections.yml     # CI/CD: validate → SPL → test → MITRE coverage report
├── tests/
│   ├── fixtures/                   # TP + TN log samples for each rule
│   └── test_detections.py          # 27-test pytest suite (all green)
├── dashboards/
│   └── atdp_dashboard.xml          # Splunk Simple XML — live alerts, ATT&CK heatmap, ATLAS panel
├── generate_decoys.py              # Creates 8 honeytokens on target VM
├── audit.rules                     # auditd watches for every decoy path
├── triage_agent.py                 # Claude-powered alert triage with structured JSON output
├── attacker_agent.py               # LLM-orchestrated attacker (the demo centerpiece)
├── deploy_vm.sh                    # One-command CentOS setup script
└── requirements.txt
```

---

## Detection Rules

### 1. AI-Assisted SSH Brute Force
**`sigma/ai_ssh_brute_force.yml`**

Human attackers have noisy, inconsistent timing between attempts. AI-orchestrated tools hit with regularity because each attempt goes through the same LLM API round-trip. This rule catches that and not just the volume, but the pattern.

Threshold: `> 15 failures from same src_ip within 60s`

| Framework | ID | Technique |
|---|---|---|
| MITRE ATT&CK | T1110 | Brute Force |
| MITRE ATT&CK | T1110.001 | Brute Force: Password Guessing |
| MITRE ATT&CK | T1078 | Valid Accounts |
| MITRE ATLAS | AML.T0000 | ML Attack Staging |
| MITRE ATLAS | AML.T0040 | Network Security Reconnaissance |

**Level:** High

---

### 2. Decoy File Access
**`sigma/decoy_file_access.yml`**

Zero false positives. These files don't exist for any legitimate reason, they're honeytokens. Any process that opens them (`openat` syscall via auditd, `key=decoy_access`) is almost certainly automated enumeration. The file names were specifically chosen to match what AI recon tools search for: `credentials.bak`, `id_rsa.bak`, `shadow.old`.

| Framework | ID | Technique |
|---|---|---|
| MITRE ATT&CK | T1083 | File and Directory Discovery |
| MITRE ATT&CK | T1005 | Data from Local System |
| MITRE ATT&CK | T1552.001 | Credentials in Files |
| MITRE ATLAS | AML.T0035 | ML Artifact Collection |
| MITRE ATLAS | AML.T0048 | Victim Monitoring |

**Level:** Critical — zero-FP, any trigger = immediate response

---

### 3. AI Recon Pattern
**`sigma/ai_recon_pattern.yml`**

Standard nmap randomizes port order. When an LLM is in the loop deciding what to probe next, it groups by service category (web → db → auth → remote-access) and the inter-probe delay is regular because every decision costs an API round-trip. This rule catches that cluster+regularity pattern in firewall deny logs.

| Framework | ID | Technique |
|---|---|---|
| MITRE ATT&CK | T1595 | Active Scanning |
| MITRE ATT&CK | T1595.001 | Scanning IP Blocks |
| MITRE ATT&CK | T1046 | Network Service Discovery |
| MITRE ATLAS | AML.T0040 | Network Security Reconnaissance |
| MITRE ATLAS | AML.T0000 | ML Attack Staging |

**Level:** Medium

---

### 4. Honeypot Service Interaction
**`sigma/honeypot_service_interaction.yml`**

Port 2222 runs Cowrie exclusively. It's not in DNS, not in any config, has never received legitimate traffic. Any connection is confirmed hostile — doesn't matter if it's a human or an AI agent that found it via port scan. Zero-FP, immediate escalation.

| Framework | ID | Technique |
|---|---|---|
| MITRE ATT&CK | T1190 | Exploit Public-Facing Application |
| MITRE ATT&CK | T1021.004 | Remote Services: SSH |
| MITRE ATT&CK | T1078 | Valid Accounts |
| MITRE ATLAS | AML.T0000 | ML Attack Staging |
| MITRE ATLAS | AML.T0047 | ML-Enabled Product or Service |

**Level:** Critical

---

## Deception Layer:
Honeytokens

`generate_decoys.py` plants 8 files that look genuinely valuable to automated tools:

| File | What makes it attractive |
|---|---|
| `/etc/passwd.bak` | 40 entries — `svc_workday`, `db_admin`, `deploy_svc`, `hr_api_user` |
| `/etc/shadow.old` | Every svc account has a `$6$` format fake hash — hashcat bait |
| `/var/log/auth.log.1` | 200 lines including one suspicious successful login + `cat credentials.bak` in sudo log |
| `/var/log/secure.bak` | CentOS PAM logs with DB dump commands and Vault access |
| `/root/.ssh/id_rsa.bak` | Valid PEM format, random bytes inside — passes format checks, authenticates nowhere |
| `/root/.bash_history.old` | `aws secretsmanager get-secret-value`, `kubectl get secrets -o yaml`, lateral SSH commands |
| `/etc/crontab.bak` | Named jobs: `rotate_aws_creds.sh`, `hr_sync`, deploy webhook — a map of the environment |
| `/root/.aws/credentials.bak` | Three boto3 profiles with AKIA-style keys, session token, ARNs |

---

## Platform Components

| Script | What it does |
|---|---|
| `triage_agent.py` | Accepts Splunk alert JSON → Claude → structured triage decision (risk score, ATT&CK + ATLAS tags, recommended action) |
| `attacker_agent.py` | LLM-orchestrated attacker that reasons through recon → access → enumeration → exfil while narrating its own MITRE ATT&CK + ATLAS techniques |

---

## CI/CD Pipeline

Every push to main runs `.github/workflows/validate-detections.yml`:

1. Sigma syntax validation (`sigma check`)
2. SPL conversion (`sigma convert --target splunk`)
3. Pytest against TP/TN fixtures — 27 tests
4. Auto-generated MITRE ATT&CK + ATLAS coverage matrix posted as PR comment

---

## Quick Start

```bash
# On the target CentOS VM — one script does everything
curl -sSL https://raw.githubusercontent.com/ITKiddie/atdp/main/deploy_vm.sh | sudo bash

# Set your API key
export ANTHROPIC_API_KEY=your_key_here

# Run the triage agent against a demo alert
python3 triage_agent.py --demo

# Run the attacker agent against the lab VM
python3 attacker_agent.py --target 127.0.0.1
```

---

## MITRE Coverage Summary

| ATT&CK Technique | ATLAS Technique | Detecting Rule |
|---|---|---|
| T1110.001 — Brute Force: Password Guessing | AML.T0000 — ML Attack Staging | ai_ssh_brute_force |
| T1083 — File and Directory Discovery | AML.T0035 — ML Artifact Collection | decoy_file_access |
| T1552.001 — Credentials in Files | AML.T0048 — Victim Monitoring | decoy_file_access |
| T1595.001 — Scanning IP Blocks | AML.T0040 — Network Security Reconnaissance | ai_recon_pattern |
| T1021.004 — Remote Services: SSH | AML.T0047 — ML-Enabled Product or Service | honeypot_service_interaction |

---

## Tech Stack

- **Detection layer:** Sigma v2 → SPL (pySigma + Splunk backend)
- **Monitoring:** Splunk Enterprise + Universal Forwarder + auditd
- **Honeypot:** Cowrie SSH (port 2222)
- **AI brain:** Claude API (Anthropic)
- **CI/CD:** GitHub Actions
- **Target VM:** CentOS 7/8 (runs attacker, decoys, auditd, Cowrie, Splunk forwarder)

---

## Threat Model

Traditional detections are built for human behavioral signatures. This platform explicitly models **AI agents as attackers** tools where an LLM reasons about target state, selects next actions from a tool palette, and interprets results in a feedback loop.

Observable differences from human attackers:
- **Timing regularity** — API latency creates consistent inter-action delays
- **Systematic coverage** — LLMs enumerate exhaustively rather than following hunches
- **Vocabulary overlap** — AI tools search for files using the same keyword patterns used to describe them in security docs (`credentials`, `shadow`, `id_rsa`)
- **Self-documentation** — Agentic AI tools often log or narrate reasoning, creating forensic artifacts not present in human attacks

MITRE ATLAS covers adversarial ML. ATDP bridges it with classic ATT&CK tradecraft to cover the emerging case where **the LLM itself is the attacker's reasoning engine**.

---

*Built for Active Defense research. All simulation components are for use against dedicated lab infrastructure and educational purposes only.*

**— [IT-Kiddie](https://github.com/ITKiddie)**
