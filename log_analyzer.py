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
# both regex are pinned to the whole sshd line, start to end, on purpose:
#   - "\S+ sshd\[\d+\]:" so another program logging the words "Failed password for"
#     cant get its text counted as a real ssh attempt
#   - "port \d+ ssh2$" at the end so the ip i read is the one sshd wrote, not one the
#     attacker typed into their username (try logging in as "bob from 9.9.9.9 port 22")
#   - {1,256} on the username so a giant line cant make the regex chew forever
# openssh 9.8 split sshd into sshd-session, so accept both tags. the " ssh2" at the end
# is optional because not every build writes it, and if i require it i silently drop real
# attempts, which is the worst way for a detector to be wrong.
SSHD = r"\S+ sshd(?:-session)?\[\d+\]: "
TAIL = r" from ([\d.]+) port \d+(?: ssh2)?\s*$"
FAIL_RE = re.compile(r"^(\w{3}\s+\d+ [\d:]+) " + SSHD + r"Failed password for (?:invalid user )?(.{1,256}?)" + TAIL)
OK_RE = re.compile(r"^(\w{3}\s+\d+ [\d:]+) " + SSHD + r"Accepted password for (.{1,256}?)" + TAIL)

# syslog squashes identical lines into: message repeated 9 times: [ Failed password ... ]
# thats 9 real attempts hiding in one line. miss it and a steady brute force looks quiet.
REPEAT_RE = re.compile(r"^(\w{3}\s+\d+ [\d:]+) (\S+ sshd(?:-session)?\[\d+\]:) message repeated (\d+) times: \[ ?(.*?) ?\]\s*$")


def unwrap(line):
    # a "repeated N times" line stands for N attempts, but i dont rebuild N lines out of
    # it. i carry the number along and weigh it later, so a log claiming a billion repeats
    # costs the same memory as one claiming two.
    m = REPEAT_RE.match(line)
    if not m:
        return line, 1
    ts, tag, digits, inner = m.groups()
    # int() on a few thousand digits raises on python 3.11+, and one silly line
    # shouldnt be able to kill the whole run
    count = int(digits) if len(digits) <= 9 else 10 ** 9
    return f"{ts} {tag} {inner}", count

def clean_user(u):
    # the username comes straight out of the log so i dont trust it for printing.
    # a newline or an escape code in there could fake a whole alert line in my summary
    u = "".join(c for c in u if c.isprintable())
    return u[:40] + "..." if len(u) > 40 else u


def to_time(ts):
    # auth.log has no year so i just stick 2024 in front (leap year, so feb 29 wont crash lol)
    # only the gaps between times matter here so the year doesnt really matter
    return datetime.strptime("2024 " + ts, "%Y %b %d %H:%M:%S")

def max_burst(events):
    # sliding window trick: whats the most fails squeezed inside WINDOW seconds?
    # events are (time, count), because one syslog line can stand for many attempts
    best = running = start = 0
    for end in range(len(events)):
        running += events[end][1]
        while (events[end][0] - events[start][0]).total_seconds() > WINDOW:
            running -= events[start][1]  # oldest fail is too old now, kick it out
            start += 1
        best = max(best, running)
    return best

fails = defaultdict(list)    # ip -> [(time, user, count), ...]
success = defaultdict(list)  # same thing but for logins that actually worked
lines = 0
unreadable = 0
try:
    with open(LOG_FILE, encoding="utf-8", errors="ignore") as f:
        for raw in f:
            lines += 1
            line, count = unwrap(raw)
            m, bucket = FAIL_RE.search(line), fails
            if not m:
                m, bucket = OK_RE.search(line), success
            if not m:
                continue
            try:
                when = to_time(m.group(1))
            except ValueError:
                unreadable += 1  # a date like "Feb 30" shouldnt stop the whole run
                continue
            bucket[m.group(3)].append((when, clean_user(m.group(2)), count))
except FileNotFoundError:
    sys.exit(f"oops, cant find '{LOG_FILE}', check the path once")

# sort every ip into 3 buckets: brute force / slow but sus / prob just typos
brute, slow, normal = [], [], []
for ip, tries in fails.items():
    tries.sort()
    burst = max_burst([(t, c) for t, u, c in tries])
    total = sum(c for t, u, c in tries)
    users = sorted(set(u for t, u, c in tries))
    # the scary part: did this same ip get IN after all those fails??
    first = tries[0][0]
    got_in = sorted(set(u for t, u, c in success.get(ip, []) if t > first))
    row = (ip, total, burst, users, got_in)
    if burst >= THRESHOLD:
        brute.append(row)
    elif total >= THRESHOLD:
        slow.append(row)  # not fast enough for my rule but still keeps trying, smells fishy
    else:
        normal.append(row)

# ok now print everything nicely
total_fails = sum(c for v in fails.values() for t, u, c in v)
counts = Counter()
for v in fails.values():
    for t, u, c in v:
        counts[u] += c
top_users = counts.most_common(5)
print("=" * 60)
print("      AUTH.LOG ANALYZER - BRUTE FORCE ALERT SUMMARY")
print("=" * 60)
print(f"File scanned   : {LOG_FILE} ({lines} lines)")
print(f"Failed logins  : {total_fails} from {len(fails)} IPs")
print(f"Detection rule : {THRESHOLD}+ fails within {WINDOW}s = brute force")
if unreadable:
    print(f"Skipped        : {unreadable} line(s) with a date i couldnt read")
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
