from monitoring.log_analyzer import analyze
from monitoring.synthetic import build


def test_full_pipeline_on_synthetic_log():
    incidents = {i.source_ip: i for i in analyze(build(), 2026)}
    assert set(incidents) == {"203.0.113.5", "198.51.100.23"}  # benign user ignored

    guess = incidents["203.0.113.5"]
    assert guess.technique.startswith("T1110.001")
    assert guess.compromise_suspected and guess.severity == "CRITICAL"

    spray = incidents["198.51.100.23"]
    assert spray.technique.startswith("T1110.003")
    assert not spray.compromise_suspected