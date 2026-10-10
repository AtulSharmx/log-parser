import re
import sys
import argparse
from collections import defaultdict

pattern = re.compile(r"(Failed|Accepted) password for (?:invalid user )?(\S+) from (\S+)")

ap = argparse.ArgumentParser()
ap.add_argument("logfile", nargs="?", default="sample_logs/auth.log")
ap.add_argument("--threshold", type=int, default=3)
args = ap.parse_args()

fails = defaultdict(int)
users_tried = defaultdict(set)
logins = []

try:
    with open(args.logfile, errors="ignore") as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue
            status, user, ip = m.groups()
            if status == "Failed":
                fails[ip] += 1
                users_tried[ip].add(user)
            else:
                logins.append((user, ip))
except FileNotFoundError:
    sys.exit(f"can't find {args.logfile}")

print(f"IPs with {args.threshold}+ failed logins:")
bad = [ip for ip in fails if fails[ip] >= args.threshold]
for ip in sorted(bad, key=lambda i: fails[i], reverse=True):
    print(f"  {ip}  {fails[ip]} fails  tried: {', '.join(sorted(users_tried[ip]))}")
if not bad:
    print("  none")

print("\nSuccessful logins:")
for user, ip in logins:
    note = "  <-- this IP also had failed logins!" if ip in fails else ""
    print(f"  {user} from {ip}{note}")
