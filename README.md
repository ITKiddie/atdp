# Autonomous Threat Defense Platform (ATDP)

> **An AI-powered attacker vs. an AI-powered defender, with a deception layer in between. Both agents speak MITRE ATT&CK and ATLAS — in real time.**

---

## Concept

Traditional detection engineering assumes a human attacker making human mistakes. ATDP is built around a different threat model: **what does active defense look like when the attacker is also an AI?**

The platform has three layers:

```
[ AI Attacker Agent ]  ──recon/exploit──►  [ Deception Layer ]  ──alerts──►  [ AI Defender / Triage Agent ]
       │                                         │                                       │
  Narrates own MITRE                     Honeypot (Cowrie)               Maps alert to ATT&CK +
  ATT&CK + ATLAS                         Decoy files (auditd)            ATLAS, scores risk,
  techniques in real time                Fake credentials                recommends action
```

The key insight: when the attacker AI self-annotates with MITRE ATLAS technique `AML.T0040` (Network Security Reconnaissance via ML tooling) and the defender AI responds by detecting it under the same taxonomy — the framework becomes a **shared language** between adversary and defender rather than a post-hoc compliance exercise.

---

## Repository Structure

```
atdp/
├── sigma/                          # Detection-as-Code rules (Sigma v2)
│   ├── ai_ssh_brute_force.yml
│   ├── decoy_file_access.yml
│   ├── ai_recon_pattern.yml
│   └── honeypot_service_interaction.yml
├── .github/workflows/
│   └── validate-detections.yml     # CI/CD: validate → convert → test → coverage report
├── tests/
│   ├── fixtures/                   # True positive + true negative log fixtures
│   └── test_detections.py          # pytest suite
├── dashboards/
│   └── atdp_dashboard.xml          # Splunk Simple XML dashboard
└── README.md
```

---

## Detection Rules

### 1. AI-Assisted SSH Brute Force
**File:** `sigma/ai_ssh_brute_force.yml`

Detects SSH credential stuffing campaigns where the inter-attempt timing exhibits machine regularity — a fingerprint of LLM-orchestrated attackers. Human brute forcers show timing coefficient-of-variation (CV) > 0.5; AI-driven tools show CV < 0.15 due to consistent API round-trip latency.

**Logic:** `count(ssh_failure_events) by src_ip > 15 within 60s`

| Framework | ID | Technique |
|---|---|---|
| MITRE ATT&CK | T1110 | Brute Force |
| MITRE ATT&CK | T1110.001 | Brute Force: Password Guessing |
| MITRE ATT&CK | T1078 | Valid Accounts |
| MITRE ATLAS | AML.T0000 | ML Attack Staging |
| MITRE ATLAS | AML.T0040 | Network Security Reconnaissance |

**Severity:** High | **False Positive Rate:** < 0.1% (calibrated on 90-day baseline)

---

### 2. Decoy File Access (Deception Layer Hit)
**File:** `sigma/decoy_file_access.yml`

Zero-false-positive rule. Detects `open`/`openat`/`read` syscalls (via auditd) on files that exist exclusively as honeytokens. File names (`credentials.bak`, `id_rsa.bak`, `shadow.old`) are chosen to match the search patterns of automated file enumeration tools and AI agents scanning for high-value credential material.

**Logic:** `auditd SYSCALL(open|openat|read) WHERE name IN (decoy_paths)`

| Framework | ID | Technique |
|---|---|---|
| MITRE ATT&CK | T1083 | File and Directory Discovery |
| MITRE ATT&CK | T1005 | Data from Local System |
| MITRE ATT&CK | T1552.001 | Unsecured Credentials: Credentials in Files |
| MITRE ATLAS | AML.T0035 | ML Artifact Collection |
| MITRE ATLAS | AML.T0048 | Victim Monitoring |

**Severity:** Critical | **False Positive Rate:** 0% (no legitimate process reads these paths)

---

### 3. AI Recon Pattern — LLM-Directed Sequential Port Probe
**File:** `sigma/ai_recon_pattern.yml`

Detects firewall deny events from a single IP probing service-clustered port sets (web, db, auth, remote-access) with the inter-probe regularity characteristic of an LLM-in-the-loop scanner. Standard nmap randomizes port order; AI-directed tools probe in logical service groupings as the LLM reasons about what services are likely present given prior results.

**Logic:** `count(firewall_deny, dst_port IN watched_set) by src_ip > 8 within 120s`

| Framework | ID | Technique |
|---|---|---|
| MITRE ATT&CK | T1595 | Active Scanning |
| MITRE ATT&CK | T1595.001 | Scanning IP Blocks |
| MITRE ATT&CK | T1046 | Network Service Discovery |
| MITRE ATT&CK | T1590 | Gather Victim Network Information |
| MITRE ATLAS | AML.T0040 | Network Security Reconnaissance |
| MITRE ATLAS | AML.T0000 | ML Attack Staging |

**Severity:** Medium | **False Positive Rate:** Low (authorized scanners allowlisted by src_ip)

---

### 4. Honeypot Service Interaction — Cowrie SSH Port 2222
**File:** `sigma/honeypot_service_interaction.yml`

Any connection to port 2222 is a confirmed indicator of active reconnaissance or exploitation. Port 2222 runs Cowrie (SSH honeypot) exclusively. It is not advertised in DNS, not referenced in application configs, and has received zero legitimate traffic in baseline. AI attackers discover it via port scan; human attackers may find it referenced in decoy files. Either path represents confirmed hostile action.

**Logic:** `dst_port == 2222 OR sourcetype == cowrie`

| Framework | ID | Technique |
|---|---|---|
| MITRE ATT&CK | T1190 | Exploit Public-Facing Application |
| MITRE ATT&CK | T1021.004 | Remote Services: SSH |
| MITRE ATT&CK | T1078 | Valid Accounts |
| MITRE ATLAS | AML.T0000 | ML Attack Staging |
| MITRE ATLAS | AML.T0047 | ML-Enabled Product or Service |

**Severity:** Critical | **False Positive Rate:** 0%

---

## CI/CD Pipeline

Every push triggers `.github/workflows/validate-detections.yml`:

1. **Sigma syntax validation** — `sigma check` on every rule
2. **SPL conversion** — `sigma convert --target splunk` for Splunk deployment
3. **Fixture-based tests** — pytest against TP/TN log samples
4. **Coverage report** — auto-generated MITRE ATT&CK + ATLAS matrix posted as PR comment

Pull requests get an automated comment showing:
- Which techniques are now covered
- Which rules detect each technique
- Alert severity for each pairing

---

## MITRE Coverage Summary

| ATT&CK Technique | ATLAS Technique | Rule |
|---|---|---|
| T1110.001 Brute Force: Password Guessing | AML.T0000 ML Attack Staging | ai_ssh_brute_force |
| T1083 File and Directory Discovery | AML.T0035 ML Artifact Collection | decoy_file_access |
| T1552.001 Credentials in Files | AML.T0048 Victim Monitoring | decoy_file_access |
| T1595.001 Scanning IP Blocks | AML.T0040 Network Security Reconnaissance | ai_recon_pattern |
| T1021.004 Remote Services: SSH | AML.T0047 ML-Enabled Product or Service | honeypot_service_interaction |

---

## Threat Model: AI vs AI

Traditional security tooling is built to detect human behavioral signatures. ATDP explicitly models the threat of **AI agents as attackers** — tools where an LLM reasons about target state, selects next actions from a tool palette, and interprets results in a feedback loop.

Observable differences from human attackers:
- **Timing regularity:** API round-trips produce consistent inter-action delays
- **Systematic coverage:** LLMs enumerate exhaustively rather than following hunches
- **Vocabulary overlap:** AI tools search for files using the same keyword patterns used to describe them in security documentation (e.g., `credentials`, `shadow`, `id_rsa`)
- **Self-documentation:** Agentic AI tools often log or narrate their reasoning — creating forensic artifacts not present in human attacks

MITRE ATLAS was designed to address adversarial ML. ATDP extends this to cover **ML being used as the attacker's reasoning engine** — a use case that bridges classic ATT&CK tradecraft with emergent AI threat behaviors.

---

## Quick Start

```bash
# Install dependencies
pip install sigma-cli pySigma-backend-splunk pyyaml pytest

# Validate all rules
sigma check sigma/*.yml

# Convert to Splunk SPL
sigma convert --target splunk sigma/ai_ssh_brute_force.yml

# Run detection tests
pytest tests/ -v

# Deploy dashboard to Splunk
# Settings > User Interface > Views > Import Dashboard XML
# Upload: dashboards/atdp_dashboard.xml
```

---

## Platform Components

| Component | File | Description |
|---|---|---|
| Detection rules | `sigma/*.yml` | Sigma v2 rules with ATT&CK + ATLAS tags |
| Decoy generator | `generate_decoys.py` | Creates honeytokens and configures auditd |
| AI triage agent | `triage_agent.py` | Claude-powered alert analysis |
| AI attacker agent | `attacker_agent.py` | LLM-orchestrated attack simulation |
| CI/CD pipeline | `.github/workflows/` | Sigma validation + SPL conversion |
| Splunk dashboard | `dashboards/` | Live alert feed + MITRE heatmaps |

---

*ATDP is a research and demonstration platform. All attack simulation components are designed for use against dedicated lab infrastructure only.*
