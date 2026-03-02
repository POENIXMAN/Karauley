"""
Unit tests for timestamp-based detection (C2 beacon, IP-over-DNS rate).
No BPF/kernel required — only detector logic with mock events.

Run from dns_tunnel_monitor directory:
  pytest tests/ -v
  or: python -m pytest tests/ -v
"""
import sys
import os
_monitor_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _monitor_root not in sys.path:
    sys.path.insert(0, _monitor_root)

from detectors.c2 import C2Detector
from detectors.ip_over_dns import IPOverDNSDetector


def test_c2_beacon_regular_intervals():
    """Regular queries every 10s should trigger C2_BEACON after MIN_SAMPLES."""
    det = C2Detector()
    base_ns = 1_000_000_000_000
    domain = "test-beacon.example.com"
    cgroup_id = 12345

    for i in range(7):
        event = {
            "domain": domain,
            "direction": "query",
            "cgroup_id": cgroup_id,
            "timestamp_ns": base_ns + i * 10 * 1_000_000_000,
            "dns_type": 1,
        }
        is_c2, reasons = det.check(event)

    assert is_c2, f"Expected C2 beacon to fire, got reasons={reasons}"
    beacon_reasons = [r for r in reasons if "C2_BEACON" in r]
    assert len(beacon_reasons) >= 1, f"Expected C2_BEACON in reasons: {reasons}"


def test_c2_beacon_ignores_responses():
    """Only query timestamps are used; responses should not trigger beacon."""
    det = C2Detector()
    base_ns = 1_000_000_000_000
    domain = "test.example.com"
    cgroup_id = 1

    for i in range(6):
        det.check({
            "domain": domain,
            "direction": "query",
            "cgroup_id": cgroup_id,
            "timestamp_ns": base_ns + i * 10 * 1_000_000_000,
            "dns_type": 1,
        })
    is_c2_query, _ = det.check({
        "domain": domain,
        "direction": "query",
        "cgroup_id": cgroup_id,
        "timestamp_ns": base_ns + 60 * 1_000_000_000,
        "dns_type": 1,
    })
    assert is_c2_query

    det2 = C2Detector()
    for i in range(6):
        det2.check({
            "domain": domain,
            "direction": "response",
            "cgroup_id": cgroup_id,
            "timestamp_ns": base_ns + i * 10 * 1_000_000_000,
            "dns_type": 1,
        })
    is_c2_response, reasons = det2.check({
        "domain": domain,
        "direction": "response",
        "cgroup_id": cgroup_id,
        "timestamp_ns": base_ns + 60 * 1_000_000_000,
        "dns_type": 1,
    })
    beacon_reasons = [r for r in reasons if "C2_BEACON" in r]
    assert len(beacon_reasons) == 0, "Beacon should not fire on response-only history"


def test_ip_over_dns_high_rate():
    """Many requests in a short time should trigger HIGH_RATE (rate > 50/sec, elapsed_sec > 1)."""
    det = IPOverDNSDetector()
    base_ns = 1_000_000_000_000
    domain = "rate-test.example.com"
    cgroup_id = 1
    # 60 events over just over 1 second => rate ~60/sec (> RATE_THRESHOLD 50). Detector only computes rate when elapsed_sec > 1.
    step_ns = 17_000_000  # 59 * 17e6 = 1.003e9 ns > 1e9

    for i in range(60):
        event = {
            "domain": domain,
            "cgroup_id": cgroup_id,
            "timestamp_ns": base_ns + i * step_ns,
            "dns_type": 1,
            "dns_answers": 0,
        }
        is_tunnel, reasons = det.check(event)

    assert is_tunnel, f"Expected HIGH_RATE or other, got reasons={reasons}"
    rate_reasons = [r for r in reasons if "HIGH_RATE" in r]
    assert len(rate_reasons) >= 1, f"Expected HIGH_RATE in reasons: {reasons}"


def test_ip_over_dns_null_record():
    """NULL (type 10) should always add NULL_RECORD reason."""
    det = IPOverDNSDetector()
    event = {
        "domain": "x.iodine.example.com",
        "cgroup_id": 1,
        "timestamp_ns": 1_000_000_000_000,
        "dns_type": 10,
        "dns_answers": 0,
    }
    is_tunnel, reasons = det.check(event)
    assert is_tunnel
    assert any("NULL_RECORD" in r for r in reasons)


def test_c2_no_timestamp_no_beacon():
    """Without timestamp_ns, beacon logic should not fire (no intervals)."""
    det = C2Detector()
    for i in range(7):
        det.check({
            "domain": "notime.example.com",
            "direction": "query",
            "cgroup_id": 1,
            "timestamp_ns": 0,
            "dns_type": 1,
        })
    is_c2, reasons = det.check({
        "domain": "notime.example.com",
        "direction": "query",
        "cgroup_id": 1,
        "timestamp_ns": 0,
        "dns_type": 1,
    })
    beacon_reasons = [r for r in reasons if "C2_BEACON" in r]
    assert len(beacon_reasons) == 0, "C2_BEACON should not fire when timestamp_ns is 0"
