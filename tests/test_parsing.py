from datetime import datetime

from monitoring.log_analyzer import parse_failures, parse_successes

SYSLOG_FAIL = ("Oct 16 10:00:05 srv sshd[99]: Failed password for invalid user "
               "admin from 203.0.113.9 port 5000 ssh2")
ISO_FAIL = ("2026-10-16T10:00:05.123456+05:30 srv sshd[99]: Failed password "
            "for root from 203.0.113.9 port 5000 ssh2")


def test_syslog_format_parsed():
    ts, ip, user = next(parse_failures([SYSLOG_FAIL], 2026))
    assert (ts, ip, user) == (datetime(2026, 10, 16, 10, 0, 5), "203.0.113.9", "admin")


def test_iso_format_parsed():
    ts, ip, user = next(parse_failures([ISO_FAIL], 2026))
    assert ts == datetime(2026, 10, 16, 10, 0, 5, 123456)
    assert (ip, user) == ("203.0.113.9", "root")


def test_noise_lines_ignored():
    noise = ["Oct 16 10:00:00 srv CRON[1]: job ok",
             "Oct 16 10:00:01 srv sshd[2]: Connection closed by 198.51.100.4"]
    assert list(parse_failures(noise, 2026)) == []


def test_accepted_login_parsed():
    line = ("Oct 16 10:01:00 srv sshd[7]: Accepted publickey for ubuntu "
            "from 192.0.2.10 port 6000 ssh2")
    assert next(parse_successes([line], 2026))[1:] == ("192.0.2.10", "ubuntu")

