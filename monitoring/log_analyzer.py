"""SSH auth-log analyzer: brute-force detection, ATT&CK tagging, reports."""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Iterator

# Two timestamp styles: classic syslog ("Oct 17 10:15:32") and the
# ISO 8601 style used by newer Ubuntu auth.log ("2026-10-17T10:15:32.1+05:30")
_PREFIX = (
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) "
    r"\S+ sshd(?:-session)?\[\d+\]: "
)
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

FAILED_RE = re.compile(
    _PREFIX + r"Failed password for (?:invalid user )?(?P<user>\S+) from " + _IP
)
ACCEPTED_RE = re.compile(
    _PREFIX + r"Accepted (?:password|publickey) for (?P<user>\S+) from " + _IP
)

Event = tuple[datetime, str, str]  # (timestamp, ip, user)


def parse_timestamp(raw: str, year: int) -> datetime:
    if raw[0].isdigit():
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    return datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")


def _parse(lines: Iterable[str], pattern: re.Pattern, year: int) -> Iterator[Event]:
    for line in lines:
        match = pattern.match(line)
        if match:
            yield parse_timestamp(match["ts"], year), match["ip"], match["user"]


def parse_failures(lines: Iterable[str], year: int) -> Iterator[Event]:
    return _parse(lines, FAILED_RE, year)


def parse_successes(lines: Iterable[str], year: int) -> Iterator[Event]:
    return _parse(lines, ACCEPTED_RE, year)

@dataclass
class Incident:
    source_ip: str
    attempts: int
    first_seen: str
    last_seen: str
    users: list[str]
    severity: str
    recommended_action: str
    technique: str = ""
    compromise_suspected: bool = False


def severity_for(attempts: int) -> str:
    if attempts >= 20:
        return "CRITICAL"
    if attempts >= 10:
        return "HIGH"
    return "MEDIUM"


def detect_bruteforce(events: Iterable[Event], threshold: int = 5,
                      window: timedelta = timedelta(minutes=5)) -> list[Incident]:
    """Events must be chronological (true for auth.log and journalctl)."""
    windows: dict[str, deque] = defaultdict(deque)
    flagged: dict[str, dict] = {}

    for ts, ip, user in events:
        if ip in flagged:
            agg = flagged[ip]
            agg["attempts"] += 1
            agg["last"] = ts
            agg["users"].add(user)
            continue
        q = windows[ip]
        q.append((ts, user))
        while ts - q[0][0] > window:
            q.popleft()
        if len(q) >= threshold:
            flagged[ip] = {
                "attempts": len(q),
                "first": q[0][0],
                "last": ts,
                "users": {u for _, u in q},
            }
            del windows[ip]

    return [
        Incident(
            source_ip=ip,
            attempts=a["attempts"],
            first_seen=a["first"].isoformat(),
            last_seen=a["last"].isoformat(),
            users=sorted(a["users"]),
            severity=severity_for(a["attempts"]),
            recommended_action=(
                f"Add a NACL deny rule or fail2ban ban for {ip}; check for "
                "successful logins from this IP; enforce key-only SSH."
            ),
        )
        for ip, a in flagged.items()
    ]

def tag_technique(incident: Incident, spray_min_users: int = 5,
                  spray_max_ratio: float = 2.0) -> Incident:
    n_users = len(incident.users)
    ratio = incident.attempts / n_users
    if n_users >= spray_min_users and ratio <= spray_max_ratio:
        incident.technique = "T1110.003 Password Spraying"
    else:
        incident.technique = "T1110.001 Password Guessing"
    return incident


def successful_logins_by_ip(events: Iterable[Event]) -> dict[str, list[datetime]]:
    by_ip: dict[str, list[datetime]] = defaultdict(list)
    for ts, ip, _ in events:
        by_ip[ip].append(ts)
    return by_ip


def mark_compromise(incident: Incident,
                    successes: dict[str, list[datetime]]) -> Incident:
    first = datetime.fromisoformat(incident.first_seen)
    if any(ts >= first for ts in successes.get(incident.source_ip, [])):
        incident.compromise_suspected = True
        incident.severity = "CRITICAL"
        incident.recommended_action = (
            "ESCALATE NOW: successful login after repeated failures. "
            + incident.recommended_action
        )
    return incident

def analyze(lines: list[str], year: int) -> list[Incident]:
    successes = successful_logins_by_ip(parse_successes(lines, year))
    incidents = detect_bruteforce(parse_failures(lines, year))
    return [mark_compromise(tag_technique(i), successes) for i in incidents]


def write_report(incidents: list[Incident], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([asdict(i) for i in incidents], indent=2),
                   encoding="utf-8")


if __name__ == "__main__":
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample_logs/auth.log")
    text = log_path.read_text(encoding="utf-8", errors="replace")
    found = analyze(text.splitlines(), datetime.now().year)
    write_report(found, Path("incidents/auth_incidents.json"))
    for inc in found:
        flag = "  !! COMPROMISE" if inc.compromise_suspected else ""
        print(f"[{inc.severity}] {inc.source_ip} | {inc.attempts} attempts | "
              f"{inc.technique}{flag}")
    print(f"{len(found)} incident(s) -> incidents/auth_incidents.json")