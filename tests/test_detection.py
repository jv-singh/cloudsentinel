from datetime import timedelta

from monitoring.log_analyzer import detect_bruteforce, parse_failures, severity_for


def _line(sec: int, ip: str, user: str = "root") -> str:
    m, s = divmod(sec, 60)
    return (f"Oct 16 10:{m:02d}:{s:02d} srv sshd[99]: "
            f"Failed password for {user} from {ip} port 5000 ssh2")


def test_bruteforce_flagged_benign_ignored():
    lines = [_line(i * 10, "203.0.113.5") for i in range(12)]    # 12 in 2 min
    lines += [_line(i * 120, "198.51.100.7") for i in range(4)]  # slow, benign
    lines.sort()  # zero-padded timestamps -> lexicographic == chronological
    incidents = detect_bruteforce(parse_failures(lines, 2026),
                                  threshold=5, window=timedelta(minutes=5))
    assert [i.source_ip for i in incidents] == ["203.0.113.5"]
    assert incidents[0].attempts == 12
    assert incidents[0].severity == "HIGH"


def test_slow_attempts_outside_window_not_flagged():
    lines = [_line(i * 120, "203.0.113.7") for i in range(6)]  # 6 tries, 2 min apart
    assert detect_bruteforce(parse_failures(lines, 2026)) == []


def test_severity_boundaries():
    assert [severity_for(n) for n in (5, 9, 10, 19, 20)] == [
        "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL"] 