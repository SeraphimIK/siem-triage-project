"""
generate_sample_logs.py

Generates a synthetic auth.log-style dataset for the SIEM triage exercise.
This is self-generated sample data (NOT the real BOTS dataset) that models
realistic patterns: normal logins, a brute-force attempt, a subsequent
compromise, and privilege escalation via sudo.
"""
import random
from datetime import datetime, timedelta

random.seed(42)

USERS = ["jsmith", "mkoenig", "admin", "backup_svc", "root"]
NORMAL_IPS = ["10.0.1.15", "10.0.1.22", "10.0.1.41", "10.0.1.9"]
ATTACKER_IP = "185.220.101.47"

start = datetime(2026, 8, 29, 2, 0, 0)
lines = []


def ts(t):
    return t.strftime("%b %d %H:%M:%S")


# --- Normal background activity ---
t = start
for _ in range(40):
    t += timedelta(minutes=random.randint(2, 40))
    user = random.choice(USERS[:2])
    ip = random.choice(NORMAL_IPS)
    lines.append(f"{ts(t)} webhost01 sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")

# --- Brute-force burst against 'admin' from attacker IP ---
brute_start = start + timedelta(hours=3, minutes=12)
t = brute_start
for i in range(27):
    t += timedelta(seconds=random.randint(3, 9))
    lines.append(f"{ts(t)} webhost01 sshd[{random.randint(1000,9999)}]: Failed password for admin from {ATTACKER_IP} port {random.randint(30000,60000)} ssh2")

# --- Successful login right after the burst (likely compromise) ---
t += timedelta(seconds=6)
lines.append(f"{ts(t)} webhost01 sshd[{random.randint(1000,9999)}]: Accepted password for admin from {ATTACKER_IP} port {random.randint(30000,60000)} ssh2")

# --- Privilege escalation attempt shortly after compromise ---
t += timedelta(seconds=45)
lines.append(f"{ts(t)} webhost01 sudo: admin : TTY=pts/2 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash")
t += timedelta(seconds=20)
lines.append(f"{ts(t)} webhost01 sudo: admin : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")

# --- More normal background activity after the incident ---
for _ in range(15):
    t += timedelta(minutes=random.randint(5, 30))
    user = random.choice(USERS[:2])
    ip = random.choice(NORMAL_IPS)
    lines.append(f"{ts(t)} webhost01 sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")

lines.sort(key=lambda l: datetime.strptime(l[:15], "%b %d %H:%M:%S"))

with open("auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Generated {len(lines)} lines to auth.log")
