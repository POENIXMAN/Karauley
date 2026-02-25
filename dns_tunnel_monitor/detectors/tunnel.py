"""TunnelDetector: runs C2, Exfil, IP-Over-DNS."""
from dns_tunnel_monitor.detectors.c2 import C2Detector
from dns_tunnel_monitor.detectors.exfil import ExfiltrationDetector
from dns_tunnel_monitor.detectors.ip_over_dns import IPOverDNSDetector


class TunnelDetector:
    def __init__(self):
        self.c2_detector = C2Detector()
        self.exfil_detector = ExfiltrationDetector()
        self.ipodns_detector = IPOverDNSDetector()

    def analyze(self, event):
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

        is_suspicious = len(all_reasons) > 0
        threat_type = '+'.join(threat_types) if threat_types else None
        return is_suspicious, threat_type, all_reasons
