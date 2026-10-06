# Auth Log Analyzer

A small Python tool that reads SSH authentication logs and flags suspicious login activity, ranked by severity so an analyst knows what to look at first.

Built as a hands-on project combining my IT support / audit background (log-based troubleshooting) with my MSc Cybersecurity studies (network security, penetration testing). No external dependencies.

> **Built with AI assistance (Claude).** I directed the design, ran and reviewed the code, and verified it with tests on synthetic data. I can explain every detection rule.

## What it detects

| Severity | Detection | Logic |
|---|---|---|
| CRITICAL | Possible account compromise | A successful login from an IP shortly after a burst of failures from that same IP |
| HIGH / MEDIUM | Brute force | Many failed logins from one IP in a short burst (HIGH at 2x the threshold) |
| HIGH | Password spraying | One IP failing against many *different* usernames |
| LOW | Off-hours login | Successful login outside business hours (needs human verification) |

## Quick start

```bash
python generate_sample_logs.py          # creates synthetic sample_auth.log
python log_analyzer.py sample_auth.log  # prints the report
python -m unittest -v                   # runs the tests
```

Optional flags: `--fail-threshold 5`, `--window 10` (minutes), `--spray-users 4`, `--work-start 8`, `--work-end 17`, `--json findings.json`, `--markdown report.md`.

The exit code is `1` when CRITICAL or HIGH findings exist, so it can be used in a script or CI job.

## Example output (synthetic data)

```
Events parsed: 90   Lines skipped: 2
Findings: 1 CRITICAL, 2 HIGH, 1 MEDIUM, 3 LOW

[CRITICAL] Possible account compromise  (IP 203.0.113.99)
    'carol' logged in within 10 min of a failed-login burst from the same IP.
[HIGH] Brute force  (IP 203.0.113.45)
    30 failed logins against 1 username(s): admin.
[HIGH] Password spraying  (IP 198.51.100.77)
    14 failed logins across 7 different usernames.
```

See `report.md` for a full sample report.

## How I verified it

- The sample generator plants four known scenarios (brute force, password spraying, brute force followed by a successful login, off-hours logins) plus normal traffic with occasional typos and two corrupted lines. The analyzer found all planted attacks.
- 9 unit tests cover each detection, the thresholds (4 failures must *not* trigger), burst separation, a success from a *different* IP not being flagged as compromise, and malformed lines being skipped instead of crashing.
- All data is synthetic. IPs use documentation ranges (RFC 5737) and private ranges. No real logs or credentials are included.

## Limitations (what I'd improve)

- **False positives:** the off-hours rule flagged two legitimate logins in the sample data. Real use would need per-user baselines or shift schedules.
- **Single log format:** it parses one SSH-style format. Real environments need parsers for multiple sources (Windows Event Logs, web servers, cloud audit logs).
- **Slow attacks:** a "low and slow" attacker spreading attempts over hours stays under the burst window. A longer-window or per-IP daily count would catch more.
- **No enrichment:** no IP reputation, geolocation, or allow-listing of known scanners.
- **Rules only:** detection is threshold-based and explainable. That is deliberate for a first version, but not adaptive.

## Possible next step: AI-assisted triage, with a human in the loop

Feed the Markdown report to an LLM to draft a plain-language incident summary and suggested next steps for an analyst. The analyzer stays the source of truth for *what* was detected; the model only helps explain it, and a person reviews before any action (resetting credentials, blocking IPs). That keeps accountability with the human rather than the model.

## Files

- `log_analyzer.py` - parser, detections, reports
- `generate_sample_logs.py` - synthetic log generator
- `test_log_analyzer.py` - unit tests
- `sample_auth.log`, `report.md` - sample input and output

---
*Author: Ricardo Ken-Morrison - MSc Cybersecurity & Emerging Threats, Middlesex University Dubai*
