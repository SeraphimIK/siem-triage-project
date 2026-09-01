"""
siem_triage.py

Parses auth.log and connections.csv, detects suspicious patterns, and
maps each finding to a MITRE ATT&CK technique. This is a small,
self-contained stand-in for what a Splunk/ELK detection rule set would do,
built because Splunk/ELK and the full BOTS dataset aren't available in
this environment.

Detections implemented:
  1. SSH brute-force burst (many failed logins, one source, short window)
     -> T1110.001 (Brute Force: Password Guessing), Credential Access
  2. Successful login immediately following a brute-force burst
     -> T1078 (Valid Accounts), Defense Evasion / Persistence / Privilege Escalation / Initial Access
  3. Privilege escalation via sudo to read a sensitive file
     -> T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching), Privilege Escalation
  4. Rapid sequential connections to many ports from one source (port scan)
     -> T1046 (Network Service Discovery), Discovery
"""
import re
import csv
from collections import defaultdict
from datetime import datetime

FAILED_RE = re.compile(r"^(\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: Failed password for (\S+) from (\S+) port \d+")
ACCEPTED_RE = re.compile(r"^(\w+ \d+ \d+:\d+:\d+) \S+ sshd\[\d+\]: Accepted password for (\S+) from (\S+) port \d+")
SUDO_RE = re.compile(r"^(\w+ \d+ \d+:\d+:\d+) \S+ sudo:\s+(\S+) : .*USER=root ; COMMAND=(.+)$")

BRUTE_FORCE_THRESHOLD = 10   # failed attempts
BRUTE_FORCE_WINDOW_SEC = 300  # within 5 minutes
PORT_SCAN_THRESHOLD = 20     # distinct ports
PORT_SCAN_WINDOW_SEC = 120   # within 2 minutes

findings = []


def parse_ts(s):
    return datetime.strptime(f"2026 {s}", "%Y %b %d %H:%M:%S")


def detect_brute_force(lines):
    fails_by_src = defaultdict(list)
    for line in lines:
        m = FAILED_RE.match(line)
        if m:
            t, user, src = m.groups()
            fails_by_src[src].append((parse_ts(t), user))

    for src, attempts in fails_by_src.items():
        attempts.sort()
        window = []
        for t, user in attempts:
            window.append((t, user))
            window = [w for w in window if (t - w[0]).total_seconds() <= BRUTE_FORCE_WINDOW_SEC]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                findings.append({
                    "severity": "HIGH",
                    "title": f"SSH brute-force burst from {src}",
                    "detail": f"{len(window)} failed password attempts against user '{user}' within "
                              f"{BRUTE_FORCE_WINDOW_SEC}s, first seen {window[0][0]}",
                    "technique_id": "T1110.001",
                    "technique_name": "Brute Force: Password Guessing",
                    "tactic": "Credential Access",
                    "source": src,
                })
                return src, window[-1][0]
    return None, None


def detect_post_bruteforce_login(lines, attacker_ip, after_ts):
    for line in lines:
        m = ACCEPTED_RE.match(line)
        if m:
            t, user, src = m.groups()
            t = parse_ts(t)
            if src == attacker_ip and t >= after_ts:
                findings.append({
                    "severity": "CRITICAL",
                    "title": f"Successful login for '{user}' from brute-forced source {src}",
                    "detail": f"Login accepted at {t}, {(t - after_ts).total_seconds():.0f}s after the "
                              f"brute-force burst ended — strong indicator of a successful compromise.",
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                    "tactic": "Initial Access / Persistence / Privilege Escalation / Defense Evasion",
                    "source": src,
                })
                return t
    return None


def detect_privilege_escalation(lines, after_ts):
    for line in lines:
        m = SUDO_RE.match(line)
        if m:
            t, user, cmd = m.groups()
            t = parse_ts(t)
            if after_ts is None or t >= after_ts:
                sensitive = "shadow" in cmd or "passwd" in cmd or "/bin/bash" in cmd
                findings.append({
                    "severity": "HIGH" if sensitive else "MEDIUM",
                    "title": f"Privilege escalation via sudo by '{user}'",
                    "detail": f"At {t}, '{user}' ran as root: {cmd}",
                    "technique_id": "T1548.003",
                    "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                    "tactic": "Privilege Escalation",
                    "source": user,
                })


def detect_port_scan(rows):
    by_src = defaultdict(list)
    for row in rows:
        t = datetime.fromisoformat(row["timestamp"])
        by_src[row["src_ip"]].append((t, row["dst_port"]))

    for src, events in by_src.items():
        events.sort()
        window = []
        for t, port in events:
            window.append((t, port))
            window = [w for w in window if (t - w[0]).total_seconds() <= PORT_SCAN_WINDOW_SEC]
            distinct_ports = len(set(p for _, p in window))
            if distinct_ports >= PORT_SCAN_THRESHOLD:
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Port scan detected from {src}",
                    "detail": f"{distinct_ports} distinct destination ports touched within "
                              f"{PORT_SCAN_WINDOW_SEC}s, first seen {window[0][0]}",
                    "technique_id": "T1046",
                    "technique_name": "Network Service Discovery",
                    "tactic": "Discovery",
                    "source": src,
                })
                return


def main():
    with open("auth.log") as f:
        auth_lines = f.read().splitlines()

    attacker_ip, burst_end = detect_brute_force(auth_lines)
    login_ts = None
    if attacker_ip:
        login_ts = detect_post_bruteforce_login(auth_lines, attacker_ip, burst_end)
    detect_privilege_escalation(auth_lines, login_ts)

    with open("connections.csv") as f:
        rows = list(csv.DictReader(f))
    detect_port_scan(rows)

    print(f"\n{'='*70}\nSIEM TRIAGE RESULTS — {len(findings)} findings\n{'='*70}\n")
    for i, f_ in enumerate(findings, 1):
        print(f"[{i}] {f_['severity']:8} {f_['title']}")
        print(f"     ATT&CK: {f_['technique_id']} — {f_['technique_name']}  (Tactic: {f_['tactic']})")
        print(f"     {f_['detail']}\n")

    import json
    with open("triage_results.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)


if __name__ == "__main__":
    main()
