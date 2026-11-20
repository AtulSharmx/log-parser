# log analyzer + brute force detector (mini project)
# run it like: python log_analyzer.py [logfile]  -> if u dont pass anything it uses auth.log
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
THRESHOLD = 5  # 5 or more fails...
WINDOW = 60    # ...inside 60 sec = brute force, thats my rule

# 2 regex, one for failed logins and one for the ones that worked
# the (?:invalid user )? bit is coz sshd adds that when the username doesnt even exist
# the " port NNNN" on the end matters. without it, a username like "bob from 9.9.9.9 port 22"
# makes the regex grab that fake ip instead of the real one sshd wrote at the end of the line.
# .+ is greedy on purpose so it keeps backtracking to the LAST "from <ip> port N" = the real one
FAIL_RE = re.compile(r"^(\w{3}\s+\d+ [\d:]+) .*Failed password for (?:invalid user )?(.+) from ([\d.]+) port \d+")
OK_RE = re.compile(r"^(\w{3}\s+\d+ [\d:]+) .*Accepted password for (.+) from ([\d.]+) port \d+")

def clean_user(u):
    # the username comes straight out of the log so i dont trust it for printing.
    # a newline or an escape code in there could fake a whole alert line in my summary
    u = "".join(c for c in u if c.isprintable())
    return u[:40] + "..." if len(u) > 40 else u


def to_time(ts):
    # auth.log has no year so i just stick 2024 in front (leap year, so feb 29 wont crash lol)
    # only the gaps between times matter here so the year doesnt really matter
    return datetime.strptime("2024 " + ts, "%Y %b %d %H:%M:%S")

def max_burst(times):
    # sliding window trick: whats the most fails squeezed inside WINDOW seconds?
    best, start = 0, 0
    for end in range(len(times)):
        while (times[end] - times[start]).total_seconds() > WINDOW:
            start += 1  # oldest fail is too old now, kick it out of the window
        best = max(best, end - start + 1)
    return best

fails = defaultdict(list)    # ip -> [(time, user), ...]
success = defaultdict(list)  # same thing but for logins that actually worked
lines = 0
try:
    with open(LOG_FILE, encoding="utf-8", errors="ignore") as f:
        for line in f:
            lines += 1
            m = FAIL_RE.search(line)
            if m:
                fails[m.group(3)].append((to_time(m.group(1)), clean_user(m.group(2))))
                continue
            m = OK_RE.search(line)
            if m:
                success[m.group(3)].append((to_time(m.group(1)), clean_user(m.group(2))))
except FileNotFoundError:
    sys.exit(f"oops, cant find '{LOG_FILE}', check the path once")

# sort every ip into 3 buckets: brute force / slow but sus / prob just typos
brute, slow, normal = [], [], []
for ip, tries in fails.items():
    tries.sort()
    times = [t for t, u in tries]
    burst = max_burst(times)
    users = sorted(set(u for t, u in tries))
    # the scary part: did this same ip get IN after all those fails??
    got_in = sorted(set(u for t, u in success.get(ip, []) if t > times[0]))
    row = (ip, len(tries), burst, users, got_in)
    if burst >= THRESHOLD:
        brute.append(row)
    elif len(tries) >= THRESHOLD:
        slow.append(row)  # not fast enough for my rule but still keeps trying, smells fishy
    else:
        normal.append(row)

# ok now print everything nicely
total_fails = sum(len(v) for v in fails.values())
top_users = Counter(u for v in fails.values() for t, u in v).most_common(5)
print("=" * 60)
print("      AUTH.LOG ANALYZER - BRUTE FORCE ALERT SUMMARY")
print("=" * 60)
print(f"File scanned   : {LOG_FILE} ({lines} lines)")
print(f"Failed logins  : {total_fails} from {len(fails)} IPs")
print(f"Detection rule : {THRESHOLD}+ fails within {WINDOW}s = brute force")
print("-" * 60)
if not brute and not slow:
    print("No attacks found, server is chillin :)")
for tag, rows in (("[ALERT] BRUTE FORCE", brute), ("[WARN]  SLOW REPEATED FAILS", slow)):
    for ip, total, burst, users, got_in in sorted(rows, key=lambda r: -r[1]):
        print(f"{tag} from {ip}")
        print(f"   {total} fails total, max {burst} inside {WINDOW}s")
        print(f"   users tried : {', '.join(users)}")
        if got_in:
            print(f"   !!! LOGIN SUCCESS after fails as: {', '.join(got_in)} -> check this box ASAP")
if normal:
    print("[INFO]  few fails, prob just typos: " + ", ".join(f"{r[0]} (x{r[1]})" for r in normal))
print("-" * 60)
print("Most targeted usernames: " + ", ".join(f"{u} ({c})" for u, c in top_users))
print("=" * 60)
