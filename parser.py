#!/usr/bin/env python3
"""
SOC Log Parser - Authentication Log Analyzer
Parses Linux SSH authentication logs (auth.log) to detect failed login attempts,
flag brute-force patterns, track successful logins, and audit sudo command executions.
"""

import os
import re
import argparse
from collections import defaultdict

LOG_PATTERN = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'(?P<status>Failed|Accepted)\s+password\s+for\s+'
    r'(?:invalid user\s+)?(?P<user>\S+)\s+from\s+'
    r'(?P<ip>\S+)\s+port\s+(?P<port>\d+)'
)


def read_log_file(filepath):
    """Reads the log file and returns a list of non-empty, stripped lines."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found at: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


def parse_line(line):
    """Extracts status, user, and ip from a single log line."""
    match = LOG_PATTERN.search(line)
    if not match:
        return None
    return {
        "timestamp": match.group("timestamp"),
        "status": match.group("status"),
        "user": match.group("user"),
        "ip": match.group("ip"),
    }


def process_log(lines):
    """Parses every line, builds failed-attempt counts and usernames tried per IP."""
    ip_failed_counts = defaultdict(int)
    ip_users = defaultdict(set)
    total_matched = 0
    skipped_lines = 0

    for line in lines:
        parsed = parse_line(line)
        if parsed is None:
            skipped_lines += 1
            continue

        total_matched += 1
        if parsed["status"] == "Failed":
            ip_failed_counts[parsed["ip"]] += 1
            ip_users[parsed["ip"]].add(parsed["user"])

    return ip_failed_counts, ip_users, total_matched, skipped_lines


def flag_suspicious(ip_failed_counts, threshold=3):
    """Returns IPs meeting the threshold, sorted by failed count descending."""
    flagged = {ip: count for ip, count in ip_failed_counts.items() if count >= threshold}
    return dict(sorted(flagged.items(), key=lambda item: item[1], reverse=True))


def write_report(flagged_ips, ip_users, total_lines, total_matched, skipped_lines, output_path="output/report.txt", threshold=3):
    """Writes a human-readable summary report, automatically creating the output directory if missing."""
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=== SOC Security Log Parser Report ===\n\n")
        f.write(f"Total lines read:      {total_lines}\n")
        f.write(f"Lines matched:         {total_matched}\n")
        f.write(f"Lines skipped:         {skipped_lines}\n\n")

        if not flagged_ips:
            f.write(f"No suspicious IPs found with >={threshold} failed attempts.\n")
        else:
            f.write(f"Flagged IPs ({threshold}+ failed attempts):\n")
            f.write("-" * 60 + "\n")
            for ip, count in flagged_ips.items():
                users_tried = ", ".join(sorted(ip_users[ip]))
                f.write(f"IP: {ip:<18} | Failed Count: {count:<4} | Usernames tried: {users_tried}\n")

    print(f"[+] Report successfully generated at: {output_path}")


def main():
    arg_parser = argparse.ArgumentParser(description="Parse an SSH auth log and flag brute-force IPs.")
    arg_parser.add_argument("logfile", nargs="?", default="sample_logs/auth.log",
                             help="Path to the log file (default: sample_logs/auth.log)")
    arg_parser.add_argument("--output", default="output/report.txt",
                             help="Path to output report file (default: output/report.txt)")
    arg_parser.add_argument("--threshold", type=int, default=3,
                             help="Minimum failed attempts to flag an IP (default: 3)")
    args = arg_parser.parse_args()

    lines = read_log_file(args.logfile)
    ip_failed_counts, ip_users, total_matched, skipped_lines = process_log(lines)
    flagged = flag_suspicious(ip_failed_counts, threshold=args.threshold)
    write_report(flagged, ip_users, len(lines), total_matched, skipped_lines, output_path=args.output, threshold=args.threshold)


if __name__ == "__main__":
    main()