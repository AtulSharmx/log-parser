# SSH Brute Force Detector

A Python script that reads a Linux `auth.log`, groups the SSH login attempts by IP and
flags the ones that look like brute force. It prints an alert summary in the terminal.

I made this while learning SOC basics. Reading raw auth logs line by line is slow, so I
wanted a quick way to answer three questions:

1. Which IPs are failing to log in again and again?
2. What usernames are they trying?
3. Did any of those IPs actually manage to log in afterwards?

It uses only the Python standard library, so there is nothing to install.

The first version of this just counted failures per IP. The problem with that is a slow
attack spread over two days looks exactly like a fast one. So the current version checks
failures inside a **time window** instead, which is what the counting version was missing.

## How the detection works

| Bucket | Rule | What it usually means |
|--------|------|----------------------|
| `[ALERT] BRUTE FORCE` | 5+ fails inside any 60s window | fast automated password guessing |
| `[WARN] SLOW REPEATED FAILS` | 5+ fails total, but spread out | slow bot trying to stay under the radar |
| `[INFO]` | fewer than 5 fails | normal user mistyping their password |

The 60 second check is a **sliding window**. The fail times are sorted, and two pointers
(`start` and `end`) move through them. Whenever the oldest fail is more than 60s older
than the newest one, `start` moves forward. The biggest window seen is that IP's burst
count.

Both numbers sit at the top of the script:

```python
THRESHOLD = 5  # fails...
WINDOW = 60    # ...within this many seconds
```

There is one more check that matters more than the buckets: if an IP failed a lot and
then **logged in successfully after those failures**, the script raises a critical line.
That pattern can mean the password was actually guessed, so it gets looked at first.

## How to run

Needs Python 3.8 or newer.

```bash
python log_analyzer.py
```

That runs on the sample `auth.log` in this folder. To point it at a real log:

```bash
python log_analyzer.py /var/log/auth.log
```

Reading the real `/var/log/auth.log` on Linux usually needs `sudo`.

```bash
python test_log_analyzer.py
```

That runs the checks on the parsing, described below.

## Not trusting the username

The username in an auth.log line is whatever the person connecting typed, so it is
attacker-controlled. Two things follow from that.

The regex is anchored to the ` port <number>` that sshd always writes at the end. Without
that anchor, someone logging in as `bob from 9.9.9.9 port 22` makes the line contain two
`from <ip> port N` sections, and the parser picks up the attacker's fake address instead
of the real one. The `.+` before it is greedy on purpose: it keeps backtracking until it
matches the **last** one on the line, which is the address sshd wrote.

The username is also stripped of unprintable characters and capped in length before it is
printed. An escape sequence in a username could otherwise clear the terminal line and
print a fake `[ALERT]` row into my own report.

`test_log_analyzer.py` covers both, plus the ordinary case.

## Sample output

```
============================================================
      AUTH.LOG ANALYZER - BRUTE FORCE ALERT SUMMARY
============================================================
File scanned   : auth.log (37 lines)
Failed logins  : 23 from 5 IPs
Detection rule : 5+ fails within 60s = brute force
------------------------------------------------------------
[ALERT] BRUTE FORCE from 203.0.113.45
   8 fails total, max 8 inside 60s
   users tried : admin, root, test
   !!! LOGIN SUCCESS after fails as: root -> check this box ASAP
[ALERT] BRUTE FORCE from 198.51.100.77
   6 fails total, max 6 inside 60s
   users tried : ftpuser, git, guest, oracle, postgres, ubuntu
[WARN]  SLOW REPEATED FAILS from 198.51.100.23
   6 fails total, max 1 inside 60s
   users tried : deploy
[INFO]  few fails, prob just typos: 192.0.2.10 (x1), 192.0.2.55 (x2)
------------------------------------------------------------
Most targeted usernames: deploy (6), root (5), admin (2), priya (2), atul (1)
============================================================
```

## Reading that output as an analyst

This is the part I actually care about, because the script only sorts the lines; someone
still has to decide what to do.

- **203.0.113.45** is the one to deal with first. 8 fails in under a minute against
  `admin`, `root` and `test` is automated guessing, mapped in MITRE ATT&CK as
  [T1110 (Brute Force)](https://attack.mitre.org/techniques/T1110/). But the important
  line is the next one: it then **logged in as root**. That has to be treated as a
  possible compromise rather than just an attack attempt: kill the sessions, rotate the
  password, and check what root did after that timestamp.
- **198.51.100.77** tried 6 different service accounts (`postgres`, `oracle`, `git`,
  `ftpuser`, `guest`, `ubuntu`) rather than guessing one password repeatedly. That is
  username enumeration: it is checking which accounts exist. Block it and confirm none
  of those accounts are actually enabled with a password.
- **198.51.100.23** never trips the 60s rule, max 1 fail per window, but it failed 6
  times on `deploy` alone. A human mistyping stops after three. This is the one a
  pure counter with no time window would rank the same as the fast attack, and the one
  a pure window rule would miss entirely, which is why both buckets exist.
- **192.0.2.10 and 192.0.2.55** are below threshold and almost certainly someone
  fat-fingering their own password. Worth nothing unless they show up again tomorrow.

Also worth noting: `root` appears in the successful logins at all. Direct root login over
SSH is normally disabled (`PermitRootLogin no`), so even without the attack that is a
config problem to raise with whoever owns the box.

## Project files

```
├── log_analyzer.py        # the main script
├── test_log_analyzer.py   # checks on the parsing
├── auth.log               # sample log with a few made-up attack scenarios
└── README.md
```

The sample `auth.log` is fake. Every IP in it comes from the reserved documentation
ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), so none of them belong to a real
machine.

## Concepts used

- Regular expressions (`re`) to parse the log lines
- `defaultdict` and `Counter` from `collections`
- `datetime` for parsing timestamps and measuring the gaps between them
- Sliding window / two pointer technique
- Basic file and error handling

## Limitations

- IPv4 only
- `auth.log` has no year in its timestamps, so a log crossing 31 Dec into 1 Jan sorts wrong
- Doesn't read rotated logs (`auth.log.1`, `auth.log.2.gz`)
- Only password logins, not public key logins or sudo commands

## What I want to add next

- Export alerts to CSV or JSON so they can go into something else
- Check flagged IPs against AbuseIPDB
- Public key logins and sudo command tracking
- Optional auto-block with `ufw` or `fail2ban`

## Author

**Atul Sharma**, BCA (Data Science) student, SGT University
GitHub: [@AtulSharmx](https://github.com/AtulSharmx)
