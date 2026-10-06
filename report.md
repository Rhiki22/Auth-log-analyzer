# Auth Log Analysis Report

- Events parsed: **90**
- Lines skipped: **2**
- Findings: **7**

| Severity | Category | IP | From | To | Detail |
|---|---|---|---|---|---|
| CRITICAL | Possible account compromise | 203.0.113.99 | 2026-10-05 03:33:00 | 2026-10-05 03:41:00 | Successful login as 'carol' within 10 min of a failed-login burst from the same IP. Investigate and reset credentials. |
| HIGH | Brute force | 203.0.113.45 | 2026-10-04 02:10:00 | 2026-10-04 02:12:54 | 30 failed logins against 1 username(s): admin. |
| HIGH | Password spraying | 198.51.100.77 | 2026-10-04 14:00:00 | 2026-10-04 14:05:00 | 14 failed logins across 7 different usernames. |
| MEDIUM | Brute force | 203.0.113.99 | 2026-10-05 03:33:00 | 2026-10-05 03:34:45 | 8 failed logins against 1 username(s): carol. |
| LOW | Off-hours login | 10.0.0.14 | 2026-10-04 22:30:00 | 2026-10-04 22:30:00 | 'dave' logged in at 22:30, outside 08:00-17:00. May be legitimate; verify. |
| LOW | Off-hours login | 203.0.113.99 | 2026-10-05 03:41:00 | 2026-10-05 03:41:00 | 'carol' logged in at 03:41, outside 08:00-17:00. May be legitimate; verify. |
| LOW | Off-hours login | 10.0.0.15 | 2026-10-05 05:50:00 | 2026-10-05 05:50:00 | 'erin' logged in at 05:50, outside 08:00-17:00. May be legitimate; verify. |

_Findings are leads for a human analyst to review, not verdicts._