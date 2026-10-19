"""Generate a synthetic SSH auth log with four scenarios (no real data)."""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

START = datetime(2026, 10, 18, 10, 0, 0)
OUT = Path(__file__).resolve().parents[1] / "sample_logs" / "auth.log"
SPRAY_USERS = ["alice", "bob", "carol", "dave", "erin",
               "frank", "grace", "heidi", "ivan", "judy"]


def _line(offset_s: int, pid: int, msg: str) -> tuple[datetime, str]:
    ts = START + timedelta(seconds=offset_s)
    return ts, f"{ts:%b %d %H:%M:%S} srv sshd[{pid}]: {msg}"


def build() -> list[str]:
    events: list[tuple[datetime, str]] = []
    # 1) Password guessing: one IP hammers root, 15 tries in ~2 minutes
    events += [_line(i * 8, 1100, f"Failed password for root from "
                     f"203.0.113.5 port {50000 + i} ssh2") for i in range(15)]
    # 2) Password spraying: one IP, 10 different users, one try each
    events += [_line(300 + i * 5, 1200, f"Failed password for invalid user "
                     f"{u} from 198.51.100.23 port {51000 + i} ssh2")
               for i, u in enumerate(SPRAY_USERS)]
    # 3) Benign: real user mistypes twice, then logs in
    events += [
        _line(600, 1300, "Failed password for student from 192.168.1.20 port 52000 ssh2"),
        _line(610, 1300, "Failed password for student from 192.168.1.20 port 52001 ssh2"),
        _line(620, 1300, "Accepted password for student from 192.168.1.20 port 52002 ssh2"),
    ]
    # 4) Compromise: the guessing IP finally gets in
    events.append(_line(200, 1400, "Accepted password for root from "
                        "203.0.113.5 port 50999 ssh2"))
    return [text for _, text in sorted(events)]


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(build()) + "\n", encoding="utf-8")
    print(f"Wrote {OUT}")