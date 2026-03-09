from dns_tunnel_monitor import config
from dns_tunnel_monitor.detectors.c2 import C2Detector
from dns_tunnel_monitor.detectors.exfil import ExfiltrationDetector
from dns_tunnel_monitor.detectors.ip_over_dns import IPOverDNSDetector

REASON_WEIGHTS = {
    "C2_BEACON": 3,
    "C2_TXT_REQUEST": 1,
    "HIGH_ENTROPY": 2,
    "LONG_DOMAIN": 1,
    "HIGH_DIGIT_RATIO": 1,
    "HEX_SUBDOMAIN": 2,
    "BASE64_SUBDOMAIN": 2,
    "MANY_SUBDOMAINS": 2,
    "HIGH_RATE": 3,
    "NULL_RECORD": 2,
    "MANY_ANSWERS": 2,
}
SCORE_THRESHOLD = 2 


def _score_reasons(reasons):
    total = 0
    for r in reasons:
        for prefix, w in REASON_WEIGHTS.items():
            if r.startswith(prefix):
                total += w
                break
    return total


class TunnelDetector:
    def __init__(self):
        self.c2_detector = C2Detector()
        self.exfil_detector = ExfiltrationDetector()
        self.ipodns_detector = IPOverDNSDetector()

    def analyze(self, event):
        domain = event.get("domain", "") or ""
        if not domain or domain.startswith("<"):
            return False, None, [], 0
        if config.is_legitimate_cluster_dns(domain):
            return False, None, [], 0

        all_reasons = []
        threat_types = []

        is_c2, c2_reasons = self.c2_detector.check(event)
        if is_c2:
            threat_types.append("C2")
            all_reasons.extend(c2_reasons)

        is_exfil, exfil_reasons = self.exfil_detector.check(event)
        if is_exfil:
            threat_types.append("EXFIL")
            all_reasons.extend(exfil_reasons)

        is_ipodns, ipodns_reasons = self.ipodns_detector.check(event)
        if is_ipodns:
            threat_types.append("TUNNEL")
            all_reasons.extend(ipodns_reasons)

        score = _score_reasons(all_reasons)
        is_suspicious = score >= SCORE_THRESHOLD
        threat_type = '+'.join(threat_types) if threat_types else None
        return is_suspicious, threat_type, all_reasons, score
