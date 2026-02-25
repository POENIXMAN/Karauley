"""DNS tunnel detectors: C2, Exfil, IP-Over-DNS."""
from dns_tunnel_monitor.detectors.c2 import C2Detector
from dns_tunnel_monitor.detectors.exfil import ExfiltrationDetector
from dns_tunnel_monitor.detectors.ip_over_dns import IPOverDNSDetector
from dns_tunnel_monitor.detectors.tunnel import TunnelDetector

tunnel_detector = TunnelDetector()

__all__ = ["C2Detector", "ExfiltrationDetector", "IPOverDNSDetector", "TunnelDetector", "tunnel_detector"]
