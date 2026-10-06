#!/usr/bin/env python3
"""Generate FAKE auth logs with planted attacks, for testing the analyzer.
All IPs use documentation ranges (RFC 5737) or private ranges. No real data."""
import random
from datetime import datetime, timedelta

random.seed(42)
USERS = {"alice": "10.0.0.11", "bob": "10.0.0.12", "carol": "10.0.0.13",
         "dave": "10.0.0.14", "erin": "10.0.0.15"}
lines = []


def add(t, ok, user, ip):
    verb = "Accepted" if ok else "Failed"
    inv = "" if ok or user in USERS else "invalid user "
    lines.append((t, f"{t:%Y-%m-%d %H:%M:%S} auth-server sshd: {verb} password for {inv}{user} from {ip} port {random.randint(30000, 65000)} ssh2"))


day0 = datetime(2026, 10, 3)
# Normal business-hours activity, with occasional single typos
for d in range(3):
    for user, ip in USERS.items():
        t = day0 + timedelta(days=d, hours=random.randint(8, 10), minutes=random.randint(0, 59))
        if random.random() < 0.3:
            add(t, False, user, ip)
            t += timedelta(seconds=20)
        add(t, True, user, ip)
        add(t + timedelta(hours=random.randint(3, 6)), True, user, ip)

# Planted scenario 1: brute force on 'admin' (no success)
t = datetime(2026, 10, 4, 2, 10)
for i in range(30):
    add(t + timedelta(seconds=6 * i), False, "admin", "203.0.113.45")

# Planted scenario 2: password spraying
t = datetime(2026, 10, 4, 14, 0)
for rnd in range(2):
    for i, u in enumerate(["admin", "root", "alice", "bob", "carol", "dave", "test"]):
        add(t + timedelta(minutes=rnd * 4, seconds=10 * i), False, u, "198.51.100.77")

# Planted scenario 3: brute force followed by success (account compromise)
t = datetime(2026, 10, 5, 3, 33)
for i in range(8):
    add(t + timedelta(seconds=15 * i), False, "carol", "203.0.113.99")
add(datetime(2026, 10, 5, 3, 41), True, "carol", "203.0.113.99")

# Planted scenario 4: plausible off-hours logins (may be false positives)
add(datetime(2026, 10, 4, 22, 30), True, "dave", "10.0.0.14")
add(datetime(2026, 10, 5, 5, 50), True, "erin", "10.0.0.15")

# Malformed lines to prove the parser is robust
lines.append((datetime(2026, 10, 4, 12, 0), "### corrupted entry ###"))
lines.append((datetime(2026, 10, 4, 12, 1), "2026-13-45 99:99:99 auth-server sshd: Failed password for bob from 10.0.0.12"))

lines.sort(key=lambda x: x[0])
with open("sample_auth.log", "w") as fh:
    fh.write("\n".join(l for _, l in lines) + "\n")
print(f"Wrote sample_auth.log ({len(lines)} lines)")
