#!/usr/bin/env python3
"""
auth-log-analyzer
=================
Parse Linux authentication logs (/var/log/auth.log, secure) and surface
failed-login activity and likely SSH brute-force sources.

Detection logic
---------------
1. Parse every "Failed password" / "Invalid user" / "Accepted password" line.
2. Aggregate failures per source IP.
3. Flag an IP as a brute-force source when it exceeds --threshold failed
   attempts within a --window minute sliding window.
4. Emit a human-readable summary and, optionally, a CSV for reporting.

Usage
-----
    python auth_log_analyzer.py examples/auth.log
    python auth_log_analyzer.py examples/auth.log --threshold 10 --window 5
    python auth_log_analyzer.py examples/auth.log --csv report.csv

Standard library only — runs anywhere Python 3.8+ is available.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# --- Log line patterns (OpenSSH via syslog) ---------------------------------
# Example: "Nov 12 04:11:22 web01 sshd[2451]: Failed password for invalid user
#           admin from 203.0.113.44 port 55210 ssh2"
TS_FMT = "%b %d %H:%M:%S"

FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd.*"
    r"(?:Failed password|authentication failure).*?"
    r"(?:for(?:\sinvalid\suser)?\s(?P<user>\S+)\s)?"
    r"from\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd.*Accepted\s\w+\sfor\s(?P<user>\S+)\s"
    r"from\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
INVALID_USER_RE = re.compile(r"Invalid user\s(?P<user>\S+)")


@dataclass
class IPStat:
    ip: str
    failures: int = 0
    successes: int = 0
    users: set = field(default_factory=set)
    times: list = field(default_factory=list)  # datetimes of failures

    def max_burst(self, window_minutes: int) -> int:
        """Largest number of failures inside any sliding window."""
        if not self.times:
            return 0
        times = sorted(self.times)
        window = timedelta(minutes=window_minutes)
        best = 1
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            best = max(best, end - start + 1)
        return best


def _parse_ts(raw: str, year: int) -> datetime:
    # syslog timestamps have no year; caller supplies it
    return datetime.strptime(raw, TS_FMT).replace(year=year)


def analyze(lines, year: int) -> dict:
    stats: dict[str, IPStat] = defaultdict(lambda: IPStat(ip=""))
    for line in lines:
        m = FAILED_RE.search(line)
        if m:
            ip = m.group("ip")
            s = stats[ip]
            s.ip = ip
            s.failures += 1
            user = m.group("user")
            if not user:
                iu = INVALID_USER_RE.search(line)
                user = iu.group("user") if iu else None
            if user:
                s.users.add(user)
            try:
                s.times.append(_parse_ts(m.group("ts"), year))
            except ValueError:
                pass
            continue
        m = ACCEPTED_RE.search(line)
        if m:
            ip = m.group("ip")
            s = stats[ip]
            s.ip = ip
            s.successes += 1
            s.users.add(m.group("user"))
    return stats


def flag_bruteforce(stats: dict, threshold: int, window: int) -> list:
    flagged = []
    for s in stats.values():
        burst = s.max_burst(window)
        if s.failures >= threshold and burst >= threshold:
            flagged.append((s, burst))
    flagged.sort(key=lambda t: t[1], reverse=True)
    return flagged


def print_report(stats, flagged, threshold, window) -> None:
    total_fail = sum(s.failures for s in stats.values())
    total_ok = sum(s.successes for s in stats.values())
    print("=" * 60)
    print(" AUTH LOG ANALYSIS")
    print("=" * 60)
    print(f" Unique source IPs : {len(stats)}")
    print(f" Failed attempts   : {total_fail}")
    print(f" Successful logins : {total_ok}")
    print(f" Rule              : >= {threshold} failures in {window} min window")
    print("-" * 60)
    if not flagged:
        print(" No brute-force sources detected.")
        return
    print(f" {'SOURCE IP':<18}{'FAILS':>7}{'BURST':>7}  TARGETED USERS")
    for s, burst in flagged:
        users = ", ".join(sorted(s.users)[:5])
        if len(s.users) > 5:
            users += f" (+{len(s.users) - 5})"
        print(f" {s.ip:<18}{s.failures:>7}{burst:>7}  {users}")
    print("-" * 60)
    print(f" {len(flagged)} IP(s) flagged for brute-force behaviour.")


def write_csv(path, flagged) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["source_ip", "failures", "successes", "max_burst", "targeted_users"])
        for s, burst in flagged:
            w.writerow([s.ip, s.failures, s.successes, burst, ";".join(sorted(s.users))])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Detect SSH brute-force in auth logs.")
    p.add_argument("logfile", help="path to auth.log / secure")
    p.add_argument("--threshold", type=int, default=8, help="failures to flag (default 8)")
    p.add_argument("--window", type=int, default=5, help="sliding window minutes (default 5)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for timestamps")
    p.add_argument("--csv", help="write flagged sources to CSV")
    args = p.parse_args(argv)

    try:
        with open(args.logfile, "r", errors="ignore") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        print(f"error: file not found: {args.logfile}", file=sys.stderr)
        return 2

    stats = analyze(lines, args.year)
    flagged = flag_bruteforce(stats, args.threshold, args.window)
    print_report(stats, flagged, args.threshold, args.window)
    if args.csv:
        write_csv(args.csv, flagged)
        print(f" CSV written -> {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
