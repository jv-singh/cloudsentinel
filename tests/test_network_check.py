import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

from monitoring import network_check as nc


def test_dns_failure_detected():
    # .invalid TLD is guaranteed never to resolve (RFC 2606)
    assert nc.diagnose("http://host.invalid").failed_layer is nc.Layer.DNS


def test_tcp_failure_detected(monkeypatch):
    monkeypatch.setattr(nc, "resolve", lambda host: "127.0.0.1")
    result = nc.diagnose("http://example.com:1", timeout=1)
    assert result.failed_layer is nc.Layer.TCP


def test_healthy_endpoint():
    server = HTTPServer(("127.0.0.1", 0), SimpleHTTPRequestHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = nc.diagnose(f"http://127.0.0.1:{server.server_port}/")
        assert result.failed_layer is nc.Layer.OK
        assert result.latency_ms is not None
    finally:
        server.shutdown()