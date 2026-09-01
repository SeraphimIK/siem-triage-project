# Incident Triage Report — SSH Compromise & Privilege Escalation

**Analyst:** Seraphim Ikuomola
**Data source:** Self-generated sample `auth.log` and `connections.csv` (synthetic data built for this exercise — not a real production environment)
**Tooling:** Custom Python detection script (`siem_triage.py`), standing in for Splunk/ELK-style detection rules

## Summary

Five findings were surfaced from the sample dataset, tracing a single incident chain from initial brute-force access through privilege escalation, plus one unrelated reconnaissance event. Each finding is mapped to a specific MITRE ATT&CK technique.

## Findings

### 1. SSH Brute-Force Burst — HIGH
- **ATT&CK:** T1110.001 — Brute Force: Password Guessing (Credential Access)
- **Detail:** 10 failed password attempts against user `admin` from `185.220.101.47` within a 5-minute window, first seen 2026-08-29 05:12:06.
- **Why it matches:** A high-frequency sequence of failed authentication attempts against a single account from a single external source is the textbook signature of password-guessing brute force, as opposed to a user simply mistyping their password a couple of times.

### 2. Successful Login From Brute-Forced Source — CRITICAL
- **ATT&CK:** T1078 — Valid Accounts (Initial Access / Persistence / Privilege Escalation / Defense Evasion)
- **Detail:** Login accepted for `admin` from `185.220.101.47` at 2026-08-29 05:14:41 — 100 seconds after the brute-force burst ended.
- **Why it matches:** A successful authentication immediately following a failed-login burst from the same source is a strong indicator that the brute force succeeded and the attacker is now operating with valid, legitimate-looking credentials, which is exactly what makes T1078 dangerous — the activity blends in with normal logins.

### 3–4. Privilege Escalation via Sudo — HIGH
- **ATT&CK:** T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching (Privilege Escalation)
- **Detail:** At 05:15:26 and 05:15:46, `admin` executed `/bin/bash` and `cat /etc/shadow` as root via sudo — roughly 45–65 seconds after the suspected compromise.
- **Why it matches:** Spawning a root shell and reading the shadow password file are not routine admin actions; combined with the timing right after a suspicious login, this reads as an attacker using a compromised account's sudo rights to gain full root access and harvest credential hashes.

### 5. Port Scan — MEDIUM
- **ATT&CK:** T1046 — Network Service Discovery (Discovery)
- **Detail:** 20 distinct destination ports touched from `45.33.32.156` within a 2-minute window.
- **Why it matches:** Rapid, sequential connections to many ports on one host is classic service/port scanning behavior used to map what's running on a target before deciding how to attack it. This event used a different source IP than the SSH incident and is treated as a separate, unrelated reconnaissance event in this dataset.

## Incident Narrative (Findings 1–4)

1. An external actor at `185.220.101.47` ran a password-guessing attack against the `admin` account over SSH.
2. The attack succeeded, granting the actor a valid, authenticated session.
3. Within about a minute, the actor used the compromised account's sudo privileges to spawn a root shell and read `/etc/shadow`, indicating an attempt to escalate privileges and harvest password hashes for further movement or cracking.

## Recommendations

- Enforce account lockout or rate-limiting after a small number of failed SSH attempts (e.g., via `fail2ban` or equivalent) to blunt brute-force attempts like Finding 1.
- Require MFA for SSH access, particularly for privileged accounts like `admin`, so a guessed password alone isn't sufficient for access (mitigates T1078).
- Restrict and audit sudo rights for the `admin` account; reading `/etc/shadow` should not be a routine action and could trigger an alert on its own.
- Treat the `admin` account and host `webhost01` as compromised: rotate credentials, review for persistence mechanisms, and check the shadow file hashes for offline cracking exposure.
- Block or monitor `185.220.101.47` and `45.33.32.156` at the perimeter.

## Limitations of This Exercise

This triage was run against self-generated sample data designed to contain these specific patterns, not a live production environment or the real BOTS dataset (which wasn't accessible in this environment). The detection logic (burst thresholds, time windows) is intentionally simple and would need tuning against real traffic volume and noise before use in production. The goal of this exercise was to practice the actual skill — parsing raw logs, writing detection logic, and mapping findings to ATT&CK — not to claim a production-grade SIEM deployment.
