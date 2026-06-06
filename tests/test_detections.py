"""
ATDP Detection Test Suite

Tests each Sigma rule against true-positive and true-negative log fixtures.
Uses field-pattern matching to validate detection logic without requiring a
live Splunk instance. Run with: pytest tests/ -v
"""

import json
import re
from pathlib import Path
import pytest
import yaml

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SIGMA_DIR = Path(__file__).parent.parent / "sigma"


def load_fixture(filename):
    """Load a JSON Lines fixture file into a list of event dicts."""
    events = []
    path = FIXTURES_DIR / filename
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def load_sigma_rule(filename):
    with open(SIGMA_DIR / filename) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# SSH Brute Force
# ---------------------------------------------------------------------------

def _count_ssh_failures_by_ip(events):
    """Aggregate failure count per src_ip (mirrors SPL count() by src_ip > 15)."""
    counts = {}
    failure_patterns = [
        "Failed password for",
        "Invalid user",
        "Failed publickey for",
        "Connection closed by authenticating user",
    ]
    for event in events:
        msg = event.get("message", "")
        if any(p in msg for p in failure_patterns):
            ip = event.get("src_ip", "")
            if ip and ip != "127.0.0.1":
                counts[ip] = counts.get(ip, 0) + 1
    return counts


class TestSSHBruteForce:
    def test_rule_yaml_valid(self):
        rule = load_sigma_rule("ai_ssh_brute_force.yml")
        assert rule["title"]
        assert rule["id"]
        assert rule["level"] in ("low", "medium", "high", "critical")

    def test_rule_has_attack_tags(self):
        rule = load_sigma_rule("ai_ssh_brute_force.yml")
        tags = rule.get("tags", [])
        attack_tags = [t for t in tags if t.startswith("attack.t")]
        assert len(attack_tags) >= 2, "Expected at least 2 ATT&CK technique tags"

    def test_rule_has_atlas_tags(self):
        rule = load_sigma_rule("ai_ssh_brute_force.yml")
        tags = rule.get("tags", [])
        atlas_tags = [t for t in tags if t.startswith("atlas.")]
        assert len(atlas_tags) >= 1, "Expected at least 1 ATLAS technique tag"

    def test_true_positive_triggers(self):
        events = load_fixture("ai_ssh_brute_force_tp.json")
        counts = _count_ssh_failures_by_ip(events)
        assert any(c > 15 for c in counts.values()), (
            f"TP fixture should produce >15 failures from one IP. Got: {counts}"
        )

    def test_true_negative_does_not_trigger(self):
        events = load_fixture("ai_ssh_brute_force_tn.json")
        counts = _count_ssh_failures_by_ip(events)
        assert all(c <= 15 for c in counts.values()), (
            f"TN fixture should NOT produce >15 failures. Got: {counts}"
        )

    def test_tp_source_ip_is_external(self):
        events = load_fixture("ai_ssh_brute_force_tp.json")
        ips = {e["src_ip"] for e in events if "src_ip" in e}
        internal_prefixes = ("10.", "192.168.", "127.")
        external_ips = [ip for ip in ips if not any(ip.startswith(p) for p in internal_prefixes)]
        assert len(external_ips) >= 1, "TP fixture should contain external attacker IP"


# ---------------------------------------------------------------------------
# Decoy File Access
# ---------------------------------------------------------------------------

DECOY_PATHS = [
    "/etc/passwd.bak",
    "/etc/shadow.old",
    "/var/log/auth.log.1",
    "/var/log/secure.bak",
    "/root/.ssh/id_rsa.bak",
    "/root/.bash_history.old",
    "/etc/crontab.bak",
    "/root/.aws/credentials.bak",
]


def _decoy_file_accessed(events):
    triggered = []
    for event in events:
        name = event.get("name", "")
        key = event.get("key", "")
        syscall = event.get("syscall", "")
        if any(name.endswith(p) for p in DECOY_PATHS):
            if syscall in ("open", "openat", "read", "creat") or key == "decoy_access":
                triggered.append(event)
    return triggered


class TestDecoyFileAccess:
    def test_rule_yaml_valid(self):
        rule = load_sigma_rule("decoy_file_access.yml")
        assert rule["title"]
        assert rule["level"] == "critical", "Decoy file access should be critical severity"

    def test_rule_has_attack_and_atlas_tags(self):
        rule = load_sigma_rule("decoy_file_access.yml")
        tags = rule.get("tags", [])
        assert any(t.startswith("attack.t") for t in tags)
        assert any(t.startswith("atlas.") for t in tags)

    def test_true_positive_triggers(self):
        events = load_fixture("decoy_file_access_tp.json")
        triggered = _decoy_file_accessed(events)
        assert len(triggered) >= 1, (
            f"TP fixture should trigger on decoy file access. Events: {len(events)}"
        )

    def test_true_negative_does_not_trigger(self):
        events = load_fixture("decoy_file_access_tn.json")
        triggered = _decoy_file_accessed(events)
        assert len(triggered) == 0, (
            f"TN fixture should not trigger. Got triggers: {triggered}"
        )

    def test_tp_covers_multiple_decoy_files(self):
        events = load_fixture("decoy_file_access_tp.json")
        triggered = _decoy_file_accessed(events)
        accessed_paths = {e.get("name", "") for e in triggered}
        assert len(accessed_paths) >= 2, "TP should show attacker accessing multiple decoys"


# ---------------------------------------------------------------------------
# AI Recon Pattern
# ---------------------------------------------------------------------------

WATCHED_PORTS = {"22", "80", "443", "3306", "5432", "6379", "8080", "8443", "9200", "27017", "445", "23"}


def _recon_detected(events, threshold=8, window_seconds=120):
    from collections import defaultdict
    probes_by_ip = defaultdict(list)
    for event in events:
        if event.get("action") == "deny" and event.get("dst_port") in WATCHED_PORTS:
            src = event.get("src_ip", "")
            if src:
                probes_by_ip[src].append(event)
    triggered = {}
    for ip, evts in probes_by_ip.items():
        if len(evts) > threshold:
            triggered[ip] = len(evts)
    return triggered


class TestAIReconPattern:
    def test_rule_yaml_valid(self):
        rule = load_sigma_rule("ai_recon_pattern.yml")
        assert rule["title"]
        assert rule["id"]

    def test_rule_has_both_tag_types(self):
        rule = load_sigma_rule("ai_recon_pattern.yml")
        tags = rule.get("tags", [])
        assert any(t.startswith("attack.") for t in tags)
        assert any(t.startswith("atlas.") for t in tags)

    def test_true_positive_triggers(self):
        events = load_fixture("ai_recon_pattern_tp.json")
        triggered = _recon_detected(events)
        assert len(triggered) >= 1, (
            f"TP fixture should trigger on sequential port scan. Events: {len(events)}"
        )

    def test_true_negative_does_not_trigger(self):
        events = load_fixture("ai_recon_pattern_tn.json")
        triggered = _recon_detected(events)
        assert len(triggered) == 0, (
            f"TN fixture should not trigger. Got: {triggered}"
        )

    def test_tp_shows_sequential_ports(self):
        events = load_fixture("ai_recon_pattern_tp.json")
        ports = [e.get("dst_port") for e in events if e.get("dst_port")]
        unique_ports = set(ports)
        assert len(unique_ports) >= 8, "TP should show multi-port probe pattern"


# ---------------------------------------------------------------------------
# Honeypot Service Interaction
# ---------------------------------------------------------------------------

def _honeypot_triggered(events):
    triggered = []
    for event in events:
        if event.get("dst_port") == 2222:
            triggered.append(event)
        elif event.get("eventid", "").startswith("cowrie."):
            triggered.append(event)
    return triggered


class TestHoneypotInteraction:
    def test_rule_yaml_valid(self):
        rule = load_sigma_rule("honeypot_service_interaction.yml")
        assert rule["title"]
        assert rule["level"] == "critical"

    def test_rule_references_cowrie(self):
        rule = load_sigma_rule("honeypot_service_interaction.yml")
        refs = rule.get("references", [])
        assert any("cowrie" in r for r in refs), "Rule should reference cowrie honeypot"

    def test_true_positive_triggers(self):
        events = load_fixture("honeypot_tp.json")
        triggered = _honeypot_triggered(events)
        assert len(triggered) >= 1, "TP fixture should trigger on port 2222 connection"

    def test_true_negative_does_not_trigger(self):
        events = load_fixture("honeypot_tn.json")
        triggered = _honeypot_triggered(events)
        assert len(triggered) == 0, f"TN fixture should not trigger. Got: {triggered}"

    def test_tp_captures_attacker_commands(self):
        events = load_fixture("honeypot_tp.json")
        cmd_events = [e for e in events if e.get("eventid") == "cowrie.command.input"]
        assert len(cmd_events) >= 1, "TP should show attacker issuing commands in honeypot"

    def test_tp_attacker_sought_decoy_files(self):
        events = load_fixture("honeypot_tp.json")
        cmd_events = [e for e in events if e.get("eventid") == "cowrie.command.input"]
        inputs = [e.get("input", "") for e in cmd_events]
        decoy_sought = any(
            any(d in inp for d in [".aws/credentials", "id_rsa", "shadow", "passwd"])
            for inp in inputs
        )
        assert decoy_sought, "TP should show attacker probing for decoy files inside honeypot"


# ---------------------------------------------------------------------------
# Cross-rule coverage test
# ---------------------------------------------------------------------------

class TestRuleCoverage:
    def test_all_rules_present(self):
        expected = {
            "ai_ssh_brute_force.yml",
            "decoy_file_access.yml",
            "ai_recon_pattern.yml",
            "honeypot_service_interaction.yml",
        }
        found = {f.name for f in SIGMA_DIR.glob("*.yml")}
        assert expected.issubset(found), f"Missing rules: {expected - found}"

    def test_all_rules_have_mitre_attack_tags(self):
        for rule_file in SIGMA_DIR.glob("*.yml"):
            rule = load_sigma_rule(rule_file.name)
            tags = rule.get("tags", [])
            attack_tags = [t for t in tags if t.startswith("attack.t")]
            assert len(attack_tags) >= 1, f"{rule_file.name} missing ATT&CK technique tags"

    def test_all_rules_have_atlas_tags(self):
        for rule_file in SIGMA_DIR.glob("*.yml"):
            rule = load_sigma_rule(rule_file.name)
            tags = rule.get("tags", [])
            atlas_tags = [t for t in tags if t.startswith("atlas.")]
            assert len(atlas_tags) >= 1, f"{rule_file.name} missing ATLAS technique tags"

    def test_all_rules_have_ids(self):
        ids = set()
        for rule_file in SIGMA_DIR.glob("*.yml"):
            rule = load_sigma_rule(rule_file.name)
            rule_id = rule.get("id", "")
            assert rule_id, f"{rule_file.name} missing rule ID"
            assert rule_id not in ids, f"Duplicate rule ID: {rule_id}"
            ids.add(rule_id)

    def test_all_rules_have_references(self):
        for rule_file in SIGMA_DIR.glob("*.yml"):
            rule = load_sigma_rule(rule_file.name)
            refs = rule.get("references", [])
            assert len(refs) >= 2, f"{rule_file.name} should have at least 2 references"
