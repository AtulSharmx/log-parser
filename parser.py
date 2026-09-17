# ssh ke auth.log se check karta hai kaunsi IP baar baar fail ho rahi hai
# chalane ke liye: python parser.py [logfile] [--threshold N]

import re
import sys
import argparse
from collections import defaultdict

# log line kuch aisi hoti hai:
# Jul 22 03:14:22 server sshd[1023]: Failed password for invalid user admin from 192.168.1.105 port 51234 ssh2
# isme se bas status, username aur ip chahiye
pattern = re.compile(r"(Failed|Accepted) password for (?:invalid user )?(\S+) from (\S+)")

ap = argparse.ArgumentParser()
ap.add_argument("logfile", nargs="?", default="sample_logs/auth.log")
ap.add_argument("--threshold", type=int, default=3)  # itne fail ke baad flag karna hai
args = ap.parse_args()

fails = defaultdict(int)        # har ip ke kitne fail hue
users_tried = defaultdict(set)  # ip ne kaun kaun se usernames try kiye
logins = []                     # jo login ho gaye (user, ip)

try:
    with open(args.logfile, errors="ignore") as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue  # baaki lines kaam ki nahi, skip
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
# sabse zyada fail wali upar dikhegi
for ip in sorted(bad, key=lambda i: fails[i], reverse=True):
    print(f"  {ip}  {fails[ip]} fails  tried: {', '.join(sorted(users_tried[ip]))}")
if not bad:
    print("  none")

print("\nSuccessful logins:")
for user, ip in logins:
    # agar same ip pehle fail hui thi aur ab login ho gayi to ye suspicious hai
    note = "  <-- this IP also had failed logins!" if ip in fails else ""
    print(f"  {user} from {ip}{note}")