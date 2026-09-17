# log-parser

Small Python script I wrote while learning SOC basics. It reads a Linux SSH log (auth.log) and shows:

- IPs with too many failed logins (possible brute force)
- which usernames each of those IPs tried
- successful logins, with a warning if that IP also failed before

No libraries needed, just Python 3.

## Run

    python parser.py                        # uses sample_logs/auth.log
    python parser.py /var/log/auth.log      # your own log
    python parser.py --threshold 5          # change the limit (default 3)

## Output on the sample log

    IPs with 3+ failed logins:
      192.168.1.105  7 fails  tried: admin, administrator, root, test, ubuntu

    Successful logins:
      atul from 192.168.1.50
      root from 192.168.1.10
      atul from 192.168.1.50
      deploy from 192.168.1.15

## What I learned

- how sshd writes failed/accepted login lines
- 192.168.1.105 tried common default usernames (admin, root, ubuntu) one after another, which is what a brute-force or password-guessing attack looks like
- a root login over password (192.168.1.10) is worth checking even if it succeeded

## Next

- only count failures inside a time window (e.g. 5 in 1 minute)
- also catch "publickey" logins and sudo commands
- check flagged IPs on AbuseIPDB
