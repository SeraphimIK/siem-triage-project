"""
generate_netlog.py
Generates a synthetic connection log with a port-scan pattern from an
external IP, alongside normal internal traffic. Self-generated sample
data for the exercise.
"""
import random
from datetime import datetime, timedelta

random.seed(7)

INTERNAL_IPS = ["10.0.1.15", "10.0.1.22", "10.0.1.41"]
SCANNER_IP = "45.33.32.156"
TARGET = "10.0.1.5"

start = datetime(2026, 8, 29, 5, 0, 0)
lines = ["timestamp,src_ip,dst_ip,dst_port,protocol"]
t = start

for _ in range(30):
      t += timedelta(minutes=random.randint(1, 15))
      src = random.choice(INTERNAL_IPS)
      dst_port = random.choice([443, 80, 22, 3389])
      lines.append(f"{t.isoformat()},{src},10.0.1.5,{dst_port},TCP")

scan_start = start + timedelta(hours=2, minutes=5)
t = scan_start
ports = list(range(20, 1050, random.choice([1, 2, 3])))
random.shuffle(ports)
for p in ports[:120]:
      t += timedelta(milliseconds=random.randint(50, 400))
      lines.append(f"{t.isoformat()},{SCANNER_IP},{TARGET},{p},TCP")

with open("connections.csv", "w") as f:
      f.write("\n".join(lines) + "\n")

print(f"Generated {len(lines)-1} connection records to connections.csv")
