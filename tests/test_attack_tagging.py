from datetime import datetime

from monitoring.log_analyzer import Incident, mark_compromise, tag_technique


def _inc(attempts: int, users: list[str],
         first: str = "2026-10-16T10:00:00") -> Incident:
    return Incident("203.0.113.5", attempts, first, first, users, "HIGH", "Block IP.")


def test_guessing():
    assert tag_technique(_inc(30, ["root"])).technique.startswith("T1110.001")


def test_spraying():
    users = [f"user{i}" for i in range(10)]
    assert tag_technique(_inc(12, users)).technique.startswith("T1110.003")


def test_few_users_is_still_guessing():
    assert tag_technique(_inc(8, ["a", "b", "c", "d"])).technique.startswith("T1110.001")


def test_success_after_failures_escalates():
    successes = {"203.0.113.5": [datetime(2026, 10, 16, 10, 3, 0)]}
    inc = mark_compromise(_inc(12, ["root"]), successes)
    assert inc.compromise_suspected is True
    assert inc.severity == "CRITICAL"
    assert inc.recommended_action.startswith("ESCALATE")


def test_success_before_attack_ignored():
    successes = {"203.0.113.5": [datetime(2026, 10, 16, 9, 0, 0)]}
    assert mark_compromise(_inc(12, ["root"]), successes).compromise_suspected is False