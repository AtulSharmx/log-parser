# log-parser

A small Python script that reads a Linux SSH log (`auth.log`) and points out login activity worth checking, like brute-force attempts.

I made this while learning SOC (Security Operations Center) basics. Reading raw auth logs line by line is slow, so I wanted a quick way to answer three questions:

1. Which IPs are failing to log in again and again?
2. What usernames are they trying?
3. Did any of those IPs actually manage to log in?

## How it works

Every SSH login attempt leaves a line in `auth.log` like this:

    Jul 22 03:14:22 server sshd[1023]: Failed password for invalid user admin from 192.168.1.105 port 51234 ssh2

The script:

- uses a regex to pull out the status (Failed / Accepted), the username and the IP
- counts failed attempts per IP and remembers which usernames each IP tried
- flags any IP that crosses the threshold (default 3)
- lists successful logins and marks the ones coming from an IP that also failed before

Only Python 3 is needed, no extra libraries.

## Usage

    python parser.py                        # runs on sample_logs/auth.log
    python parser.py /var/log/auth.log      # run on a real log (may need sudo on Linux)
    python parser.py --threshold 5          # flag only IPs with 5+ fails

## Example output

Running it on the sample log:

    IPs with 3+ failed logins:
      192.168.1.105  7 fails  tried: admin, administrator, root, test, ubuntu

    Successful logins:
      atul from 192.168.1.50
      root from 192.168.1.10
      atul from 192.168.1.50
      deploy from 192.168.1.15

## What the sample log shows

- **192.168.1.105** failed 7 times in about 8 minutes, trying common default usernames (admin, root, ubuntu, test). This looks like password guessing, mapped in MITRE ATT&CK as T1110 (Brute Force). As an analyst I would block this IP and check whether it hit other servers.
- **root logged in with a password** from 192.168.1.10. It succeeded, but direct root login over SSH is usually disabled on a secure server, so this is worth confirming with the admin.
- 192.168.1.201 tried "oracle" twice and 192.168.1.77 / .99 tried once each. Below the threshold, but they show how common random username guessing is.

If an IP fails many times and then shows up under successful logins, the script adds a warning next to it. That pattern can mean the attacker guessed a password, so it should be checked first.

## Limitations

- counts all failures in the whole file, not within a time window, so slow attacks spread over days look the same as fast ones
- only reads password logins, not public key logins
- works on the standard Ubuntu/Debian `auth.log` format; other systems may log differently

## What I want to add next

- time-window detection (for example 5 fails in 1 minute)
- public key logins and sudo command tracking
- checking flagged IPs against AbuseIPDB