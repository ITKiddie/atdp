#!/bin/bash
# ATDP CentOS VM Setup Script
# Run as root on your CentOS VM:
#   curl -sSL https://raw.githubusercontent.com/ITKiddie/atdp/main/deploy_vm.sh | sudo bash
# Or after cloning:
#   sudo bash deploy_vm.sh

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

echo -e "${RED}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ATDP — CentOS VM Setup                             ║"
echo "║  Autonomous Threat Defense Platform                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

[[ $EUID -ne 0 ]] && die "Must run as root (sudo bash deploy_vm.sh)"

# ── Detect package manager ────────────────────────────────────────────────────
if command -v dnf &>/dev/null; then
    PKG="dnf"
elif command -v yum &>/dev/null; then
    PKG="yum"
else
    die "Neither dnf nor yum found — is this CentOS?"
fi

# ── System packages ───────────────────────────────────────────────────────────
info "Installing system packages..."
$PKG install -y -q git python3 python3-pip nmap audit auditd curl wget 2>/dev/null || true
success "System packages installed"

# ── Clone / update repo ───────────────────────────────────────────────────────
REPO_DIR="/opt/atdp"
if [[ -d "$REPO_DIR/.git" ]]; then
    info "Repo already exists at $REPO_DIR — pulling latest..."
    cd "$REPO_DIR" && git pull --quiet
else
    info "Cloning ATDP repo to $REPO_DIR..."
    git clone --quiet https://github.com/ITKiddie/atdp.git "$REPO_DIR"
fi
cd "$REPO_DIR"
success "Repo ready at $REPO_DIR"

# ── Python dependencies ───────────────────────────────────────────────────────
info "Installing Python requirements..."
pip3 install -q -r requirements.txt
success "Python requirements installed"

# ── Generate decoy honeytokens ────────────────────────────────────────────────
info "Generating decoy honeytoken files..."
python3 generate_decoys.py
success "All 8 decoy files created"

# ── Configure auditd ─────────────────────────────────────────────────────────
info "Configuring auditd to watch decoy paths..."
cp audit.rules /etc/audit/rules.d/atdp-decoys.rules
# Use augenrules if available, otherwise auditctl direct load
if command -v augenrules &>/dev/null; then
    augenrules --load
else
    auditctl -R /etc/audit/rules.d/atdp-decoys.rules
fi
systemctl enable auditd 2>/dev/null || true
systemctl restart auditd
success "auditd configured and restarted"

# Verify rules loaded
RULE_COUNT=$(auditctl -l 2>/dev/null | grep -c decoy_access || echo 0)
success "auditd watching $RULE_COUNT decoy paths"

# ── Install Cowrie honeypot ───────────────────────────────────────────────────
info "Setting up Cowrie SSH honeypot on port 2222..."

# Dependencies
pip3 install -q cowrie 2>/dev/null || {
    # Manual install if pip fails
    $PKG install -y -q python3-virtualenv libssl-dev libffi-devel build-essential 2>/dev/null || true
    if [[ ! -d /opt/cowrie ]]; then
        git clone --quiet https://github.com/cowrie/cowrie.git /opt/cowrie
    fi
    cd /opt/cowrie
    python3 -m venv cowrie-env
    source cowrie-env/bin/activate
    pip install -q -r requirements.txt
    deactivate
    cd "$REPO_DIR"
}

# Cowrie config — redirect logs to /var/log/cowrie for Splunk pickup
COWRIE_DIR=""
if [[ -d /opt/cowrie ]]; then
    COWRIE_DIR="/opt/cowrie"
    cp "$COWRIE_DIR/etc/cowrie.cfg.dist" "$COWRIE_DIR/etc/cowrie.cfg" 2>/dev/null || true
    # Set listen port to 2222
    sed -i 's/^listen_port = .*/listen_port = 2222/' "$COWRIE_DIR/etc/cowrie.cfg" 2>/dev/null || true
    sed -i 's/^#listen_port/listen_port/' "$COWRIE_DIR/etc/cowrie.cfg" 2>/dev/null || true
    # Set JSON logging
    sed -i 's/^#logfile = /logfile = /' "$COWRIE_DIR/etc/cowrie.cfg" 2>/dev/null || true
fi

# Open port 2222 in firewall
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=2222/tcp &>/dev/null || true
    firewall-cmd --reload &>/dev/null || true
    success "firewall-cmd: port 2222 opened"
elif command -v iptables &>/dev/null; then
    iptables -I INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || true
    success "iptables: port 2222 opened"
fi

success "Cowrie honeypot configured"

# ── Splunk Universal Forwarder inputs ─────────────────────────────────────────
SPLUNK_INPUTS="/opt/splunkforwarder/etc/system/local/inputs.conf"
if [[ -f "$SPLUNK_INPUTS" ]]; then
    info "Configuring Splunk forwarder inputs for ATDP sources..."
    cat >> "$SPLUNK_INPUTS" << 'INPUTS'

# ATDP — auditd decoy file access events
[monitor:///var/log/audit/audit.log]
disabled = false
index    = main
sourcetype = linux:audit

# ATDP — Cowrie honeypot JSON log
[monitor:///var/log/cowrie/cowrie.json]
disabled = false
index    = main
sourcetype = cowrie

# ATDP — AI triage decisions
[monitor:///opt/atdp/triage_log.jsonl]
disabled = false
index    = main
sourcetype = atdp_triage
INPUTS
    /opt/splunkforwarder/bin/splunk restart --accept-license --answer-yes 2>/dev/null || true
    success "Splunk forwarder reconfigured"
else
    warn "Splunk forwarder not found at $SPLUNK_INPUTS — configure inputs.conf manually"
fi

# ── Verify decoy files ────────────────────────────────────────────────────────
echo ""
info "Verifying decoy files..."
DECOYS=(
    "/etc/passwd.bak"
    "/etc/shadow.old"
    "/var/log/auth.log.1"
    "/var/log/secure.bak"
    "/root/.ssh/id_rsa.bak"
    "/root/.bash_history.old"
    "/etc/crontab.bak"
    "/root/.aws/credentials.bak"
)
ALL_OK=true
for f in "${DECOYS[@]}"; do
    if [[ -f "$f" ]]; then
        LINES=$(wc -l < "$f")
        echo -e "  ${GREEN}✓${NC} $f  ($LINES lines)"
    else
        echo -e "  ${RED}✗${NC} $f  MISSING"
        ALL_OK=false
    fi
done

# ── Final instructions ────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ATDP VM Setup Complete${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo -e "  1. Set your API key:"
echo -e "     ${CYAN}export ANTHROPIC_API_KEY=sk-ant-...${NC}"
echo -e "     ${CYAN}echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> /etc/profile${NC}"
echo ""
echo -e "  2. Start Cowrie honeypot:"
if [[ -d /opt/cowrie ]]; then
echo -e "     ${CYAN}cd /opt/cowrie && source cowrie-env/bin/activate && bin/cowrie start${NC}"
else
echo -e "     ${CYAN}cowrie start${NC}"
fi
echo ""
echo -e "  3. Test the triage agent:"
echo -e "     ${CYAN}cd /opt/atdp && python3 triage_agent.py --demo${NC}"
echo ""
echo -e "  4. Run the attacker agent against this host:"
echo -e "     ${CYAN}cd /opt/atdp && python3 attacker_agent.py --target 127.0.0.1${NC}"
echo ""
echo -e "  5. Verify auditd is watching decoys:"
echo -e "     ${CYAN}auditctl -l | grep decoy_access${NC}"
echo -e "     ${CYAN}cat /etc/passwd.bak  # should trigger alert${NC}"
echo -e "     ${CYAN}ausearch -k decoy_access --start today${NC}"
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
