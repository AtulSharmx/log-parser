# run with: python test_log_analyzer.py
# the username in an auth.log line is attacker-controlled, so these check that a crafted
# one can't (a) get the wrong ip blamed or (b) forge a line in the report
import subprocess
import sys
import tempfile
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "log_analyzer.py")


def run_on(lines):
    # write a throwaway log, run the script on it, give back what it printed
    fd, path = tempfile.mkstemp(suffix=".log", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    try:
        out = subprocess.run([sys.executable, SCRIPT, path],
                             capture_output=True, text=True, encoding="utf-8")
        return out.stdout
    finally:
        os.remove(path)


def line(ts, user, ip, port):
    return f"Oct 10 {ts} webserver sshd[2201]: Failed password for {user} from {ip} port {port} ssh2"


def alert_lines(out):
    return [l for l in out.splitlines() if l.startswith(("[ALERT]", "[WARN]"))]


failures = []


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        failures.append(name)


# 1. a plain brute force is still caught
out = run_on([line(f"02:14:{s:02d}", "root", "203.0.113.45", 41000 + s) for s in range(1, 7)])
check("brute force is still detected", "BRUTE FORCE from 203.0.113.45" in out)

# 2. username carries its own "from <ip> port N". the real ip is the last one on the
#    line, because that is the one sshd wrote. the fake one may appear inside the
#    username (that is the honest thing to print) but must never be blamed.
out = run_on([line(f"03:30:{s:02d}", "invalid user x from 9.9.9.9 port 22 ssh2",
                   "203.0.113.45", 42000 + s) for s in range(1, 7)])
alerts = alert_lines(out)
check("an alert was raised", len(alerts) == 1)
check("the alert names the real ip", all("203.0.113.45" in l for l in alerts))
check("no alert names the spoofed ip", not any("9.9.9.9" in l for l in alerts))

# 3. control characters in a username must not survive into the report, or an attacker
#    could clear the line and print their own
forged = "bob\x1b[2K\r[ALERT] BRUTE FORCE from 1.2.3.4"
out = run_on([line(f"05:10:{s:02d}", forged, "203.0.113.7", 43000 + s) for s in range(1, 7)])
check("escape codes are stripped", "\x1b" not in out and "\r" not in out)
check("forged text cannot start its own line",
      not any(l.startswith("[ALERT] BRUTE FORCE from 1.2.3.4") for l in out.splitlines()))
check("only the real ip is blamed", all("203.0.113.7" in l for l in alert_lines(out)))

# 4. an absurdly long username is truncated rather than printed whole
out = run_on([line(f"06:20:{s:02d}", "a" * 500, "203.0.113.8", 44000 + s) for s in range(1, 7)])
check("long username is capped", "a" * 100 not in out)

# 5. a line missing "port N" isn't half-parsed
out = run_on(["Oct 10 04:00:00 webserver sshd[1]: Failed password for root from 203.0.113.9"])
check("malformed line is skipped", "203.0.113.9" not in out)

print()
if failures:
    print(f"{len(failures)} check(s) failed")
    sys.exit(1)
print("all checks passed")
