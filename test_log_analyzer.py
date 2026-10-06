import unittest
from datetime import datetime, timedelta
from log_analyzer import parse_lines, analyze


def fail(ts, user, ip):
    return f"{ts} srv sshd: Failed password for invalid user {user} from {ip} port 22 ssh2"


def ok(ts, user, ip):
    return f"{ts} srv sshd: Accepted password for {user} from {ip} port 22 ssh2"


def stamps(n, start="2026-10-04 10:00:00", step=5):
    t = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
    return [(t + timedelta(seconds=step * i)).strftime("%Y-%m-%d %H:%M:%S") for i in range(n)]


def run(lines, **kw):
    events, _ = parse_lines(lines)
    return analyze(events, **kw)


class TestAnalyzer(unittest.TestCase):
    def test_brute_force_detected(self):
        f = run([fail(t, "admin", "1.2.3.4") for t in stamps(6)])
        self.assertEqual([x.category for x in f], ["Brute force"])

    def test_below_threshold_not_flagged(self):
        self.assertEqual(run([fail(t, "bob", "10.0.0.12") for t in stamps(4)]), [])

    def test_password_spraying_classified(self):
        users = ["a", "b", "c", "d", "e", "f"]
        f = run([fail(t, u, "9.9.9.9") for t, u in zip(stamps(6), users)])
        self.assertEqual(f[0].category, "Password spraying")

    def test_success_after_burst_is_critical(self):
        lines = [fail(t, "carol", "5.5.5.5") for t in stamps(6)]
        lines.append(ok("2026-10-04 10:03:00", "carol", "5.5.5.5"))
        f = run(lines)
        self.assertEqual(f[0].severity, "CRITICAL")

    def test_success_from_different_ip_not_critical(self):
        lines = [fail(t, "carol", "5.5.5.5") for t in stamps(6)]
        lines.append(ok("2026-10-04 10:03:00", "carol", "10.0.0.13"))
        self.assertNotIn("CRITICAL", [x.severity for x in run(lines)])

    def test_off_hours_login_low(self):
        f = run([ok("2026-10-04 23:15:00", "dave", "10.0.0.14")])
        self.assertEqual((f[0].category, f[0].severity), ("Off-hours login", "LOW"))

    def test_normal_login_not_flagged(self):
        self.assertEqual(run([ok("2026-10-04 09:00:00", "alice", "10.0.0.11")]), [])

    def test_malformed_lines_skipped_not_fatal(self):
        events, skipped = parse_lines(["garbage", "", "2026-13-45 99:99:99 srv sshd: Failed password for x from 1.1.1.1"])
        self.assertEqual((len(events), skipped), (0, 2))

    def test_separate_bursts_not_merged(self):
        lines = [fail(t, "admin", "1.2.3.4") for t in stamps(3)]
        lines += [fail(t, "admin", "1.2.3.4") for t in stamps(3, start="2026-10-04 12:00:00")]
        self.assertEqual(run(lines), [])


if __name__ == "__main__":
    unittest.main()
