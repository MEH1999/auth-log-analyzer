"""Basic tests for auth_log_analyzer (run with: python -m pytest)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from auth_log_analyzer import analyze, flag_bruteforce  # noqa: E402


SAMPLE = [
    "Nov 12 04:00:01 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.44 port 5000 ssh2",
    "Nov 12 04:00:04 web01 sshd[2]: Failed password for root from 203.0.113.44 port 5001 ssh2",
    "Nov 12 04:00:07 web01 sshd[3]: Failed password for invalid user test from 203.0.113.44 port 5002 ssh2",
    "Nov 12 04:00:10 web01 sshd[4]: Failed password for root from 203.0.113.44 port 5003 ssh2",
    "Nov 12 04:11:00 web01 sshd[5]: Accepted password for deploy from 198.51.100.20 port 6000 ssh2",
]


def test_counts():
    stats = analyze(SAMPLE, year=2025)
    assert stats["203.0.113.44"].failures == 4
    assert stats["198.51.100.20"].successes == 1


def test_users_collected():
    stats = analyze(SAMPLE, year=2025)
    assert {"admin", "root", "test"} <= stats["203.0.113.44"].users


def test_bruteforce_flagged():
    stats = analyze(SAMPLE, year=2025)
    flagged = flag_bruteforce(stats, threshold=4, window=5)
    ips = [s.ip for s, _ in flagged]
    assert "203.0.113.44" in ips
    assert "198.51.100.20" not in ips


def test_below_threshold_not_flagged():
    stats = analyze(SAMPLE, year=2025)
    flagged = flag_bruteforce(stats, threshold=10, window=5)
    assert flagged == []


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all tests passed")
