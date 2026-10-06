#!/usr/bin/env python3
"""Authentication log analyzer: flags suspicious login activity.

Detections:
  1. Brute force          - many failed logins from one IP in a short burst
  2. Password spraying    - one IP failing against many different usernames
  3. Possible compromise  - successful login right after a burst of failures
  4. Off-hours login      - successful login outside business hours (low severity)

Standard library only. Run:  python log_analyzer.py auth.log
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \S+ sshd: "
    r"(?P<status>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
TS_FORMAT = "%Y-%m-%d %H:%M:%S"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Event:
    time: datetime
    success: bool
    user: str
    ip: str


@dataclass
class Finding:
    severity: str
    category: str
    ip: str
    start: str
    end: str
    detail: str


def parse_lines(lines):
    """Return (events, skipped_count). Malformed lines are skipped, never fatal."""
    events, skipped = [], 0
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        m = LINE_RE.match(raw)
        if not m:
            skipped += 1
            continue
        try:
            t = datetime.strptime(m["ts"], TS_FORMAT)
        except ValueError:
            skipped += 1
            continue
        events.append(Event(t, m["status"] == "Accepted", m["user"], m["ip"]))
    events.sort(key=lambda e: e.time)
    return events, skipped


def _fmt(t):
    return t.strftime(TS_FORMAT)


def _failure_bursts(failures, window):
    """Group one IP's failures into bursts: gap between attempts <= window."""
    bursts, current = [], []
    for ev in failures:
        if current and ev.time - current[-1].time > window:
            bursts.append(current)
            current = []
        current.append(ev)
    if current:
        bursts.append(current)
    return bursts


def analyze(events, fail_threshold=5, window_minutes=10, spray_users=4,
            work_start=8, work_end=17):
    window = timedelta(minutes=window_minutes)
    findings = []

    failures_by_ip = defaultdict(list)
    for ev in events:
        if not ev.success:
            failures_by_ip[ev.ip].append(ev)

    # 1 & 2: brute force / password spraying
    flagged_bursts = {}  # ip -> list of (start, end)
    for ip, fails in failures_by_ip.items():
        for burst in _failure_bursts(fails, window):
            if len(burst) < fail_threshold:
                continue
            users = {e.user for e in burst}
            start, end = burst[0].time, burst[-1].time
            flagged_bursts.setdefault(ip, []).append((start, end))
            if len(users) >= spray_users:
                findings.append(Finding(
                    "HIGH", "Password spraying", ip, _fmt(start), _fmt(end),
                    f"{len(burst)} failed logins across {len(users)} different usernames."))
            else:
                sev = "HIGH" if len(burst) >= fail_threshold * 2 else "MEDIUM"
                findings.append(Finding(
                    sev, "Brute force", ip, _fmt(start), _fmt(end),
                    f"{len(burst)} failed logins against {len(users)} username(s): "
                    f"{', '.join(sorted(users))}."))

    # 3: success shortly after a flagged burst from the same IP
    for ev in events:
        if not ev.success:
            continue
        for start, end in flagged_bursts.get(ev.ip, []):
            if timedelta(0) <= ev.time - end <= window:
                findings.append(Finding(
                    "CRITICAL", "Possible account compromise", ev.ip, _fmt(start),
                    _fmt(ev.time),
                    f"Successful login as '{ev.user}' within {window_minutes} min of a "
                    f"failed-login burst from the same IP. Investigate and reset credentials."))
                break

    # 4: off-hours successful logins
    for ev in events:
        if ev.success and not (work_start <= ev.time.hour < work_end):
            findings.append(Finding(
                "LOW", "Off-hours login", ev.ip, _fmt(ev.time), _fmt(ev.time),
                f"'{ev.user}' logged in at {ev.time:%H:%M}, outside "
                f"{work_start:02d}:00-{work_end:02d}:00. May be legitimate; verify."))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.start))
    return findings


def text_report(findings, total_events, skipped):
    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1
    out = ["=" * 64, "AUTH LOG ANALYSIS REPORT", "=" * 64,
           f"Events parsed: {total_events}   Lines skipped: {skipped}",
           "Findings: " + (", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]) or "none"),
           ""]
    for f in findings:
        out += [f"[{f.severity}] {f.category}  (IP {f.ip})",
                f"    {f.start}  ->  {f.end}", f"    {f.detail}", ""]
    out.append("Note: findings are leads for a human to review, not verdicts.")
    return "\n".join(out)


def markdown_report(findings, total_events, skipped):
    lines = ["# Auth Log Analysis Report", "",
             f"- Events parsed: **{total_events}**", f"- Lines skipped: **{skipped}**",
             f"- Findings: **{len(findings)}**", "",
             "| Severity | Category | IP | From | To | Detail |", "|---|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f.severity} | {f.category} | {f.ip} | {f.start} | {f.end} | {f.detail} |")
    lines += ["", "_Findings are leads for a human analyst to review, not verdicts._"]
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description="Flag suspicious activity in SSH auth logs.")
    p.add_argument("logfile")
    p.add_argument("--fail-threshold", type=int, default=5, help="failures in a burst to flag (default 5)")
    p.add_argument("--window", type=int, default=10, help="burst window in minutes (default 10)")
    p.add_argument("--spray-users", type=int, default=4, help="distinct usernames to call it spraying (default 4)")
    p.add_argument("--work-start", type=int, default=8)
    p.add_argument("--work-end", type=int, default=17)
    p.add_argument("--json", help="write findings to this JSON file")
    p.add_argument("--markdown", help="write a Markdown report to this file")
    args = p.parse_args(argv)

    try:
        with open(args.logfile, encoding="utf-8") as fh:
            events, skipped = parse_lines(fh)
    except OSError as e:
        print(f"Error: cannot read {args.logfile}: {e}", file=sys.stderr)
        return 2

    findings = analyze(events, args.fail_threshold, args.window, args.spray_users,
                       args.work_start, args.work_end)
    print(text_report(findings, len(events), skipped))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(markdown_report(findings, len(events), skipped))
    return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
