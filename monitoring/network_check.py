"""Layered network diagnosis: report the first failing layer."""
from __future__ import annotations

import json
import socket
import sys
import time
from dataclasses import asdict, dataclass
from enum import Enum
from urllib.parse import urlparse

import requests


class Layer(str, Enum):
    DNS = "DNS"
    TCP = "TCP"
    HTTP = "HTTP"
    OK = "OK"


@dataclass(frozen=True)
class Diagnosis:
    target: str
    failed_layer: Layer
    detail: str
    latency_ms: float | None = None


def resolve(host: str) -> str:
    """DNS step: name -> IP (same job as nslookup)."""
    return socket.gethostbyname(host)


def tcp_connect(ip: str, port: int, timeout: float = 3.0) -> float:
    """TCP step: 3-way handshake (same job as Test-NetConnection)."""
    start = time.perf_counter()
    with socket.create_connection((ip, port), timeout=timeout):
        pass
    return (time.perf_counter() - start) * 1000


def diagnose(url: str, timeout: float = 3.0) -> Diagnosis:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        ip = resolve(host)
    except socket.gaierror as exc:
        return Diagnosis(url, Layer.DNS, f"Name resolution failed: {exc}")

    try:
        latency = tcp_connect(ip, port, timeout)
    except OSError as exc:
        return Diagnosis(url, Layer.TCP, f"{ip}:{port} unreachable: {exc}")

    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        return Diagnosis(url, Layer.HTTP, f"Request failed: {exc}", latency)

    if resp.status_code >= 500:
        return Diagnosis(url, Layer.HTTP, f"Server error {resp.status_code}", latency)
    return Diagnosis(url, Layer.OK, f"HTTP {resp.status_code}", latency)


if __name__ == "__main__":
    for target in sys.argv[1:] or ["https://www.google.com"]:
        print(json.dumps(asdict(diagnose(target)), indent=2))