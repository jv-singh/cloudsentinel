from monitoring.health_check import collect_metrics, evaluate, service_active


def test_breaches_flagged_with_severity():
    alerts = evaluate({"cpu": 97.0, "memory": 50.0, "disk": 91.0})
    by_metric = {a["metric"]: a["severity"] for a in alerts}
    assert by_metric == {"cpu": "CRITICAL", "disk": "HIGH"}


def test_healthy_system_no_alerts():
    assert evaluate({"cpu": 10.0, "memory": 40.0, "disk": 30.0}) == []


def test_exact_threshold_triggers_alert():
    alerts = evaluate({"cpu": 85.0, "memory": 0.0, "disk": 0.0})
    assert [a["metric"] for a in alerts] == ["cpu"]


def test_real_metrics_in_range():
    assert all(0 <= v <= 100 for v in collect_metrics().values())


def test_service_active_returns_valid_type():
    assert service_active("ssh") in (True, False, None)