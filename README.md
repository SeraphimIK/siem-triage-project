# SIEM-Style Log Triage & MITRE ATT&CK Mapping

A small SOC-style triage project: parse authentication and network connection logs, detect suspicious patterns with custom Python detection logic, and map each finding to a specific MITRE ATT&CK technique with a written incident triage report.

## Why I built it

I wanted hands-on practice with the core SOC analyst workflow, reading raw logs, writing detection logic instead of just running someone else's tool, and mapping what I find to MITRE ATT&CK, without needing a full Splunk/ELK deployment to get started. This uses self-generated sample log data rather than a real dataset like BOTS v3, since standing up a full SIEM wasn't practical here, but the detection logic and analysis are genuinely my own work, actually run against the data.

## What it does

- generate_sample_logs.py / generate_netlog.py - generate the synthetic auth.log and connections.csv sample data used for the exercise
- siem_triage.py - parses both logs and detects SSH brute-force bursts (T1110.001), a successful login following a brute-force burst (T1078), privilege escalation via sudo (T1548.003), and port scans (T1046)
- triage_results.json - the actual output produced by running the script against the sample data
- TRIAGE_REPORT.md - a full incident triage writeup based on the real findings

## How to run

python3 generate_sample_logs.py
python3 generate_netlog.py
python3 siem_triage.py

This regenerates the sample data and re-runs detection, printing each finding with its severity, ATT&CK technique ID/name, tactic, and supporting detail.

## Limitations

This is a learning exercise built on self-generated sample data, not a production SIEM deployment or the real BOTS dataset.
