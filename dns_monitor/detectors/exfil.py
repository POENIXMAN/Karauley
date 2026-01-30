"""Exfiltration detector: entropy, long domains, Base64/hex subdomains."""
import re
from collections import defaultdict

from dns_monitor.dns_parsing import calculate_entropy


class ExfiltrationDetector:
    """Detect data exfiltration via DNS: high entropy, long domains, base64/hex subdomains."""

    def __init__(self):
        self.subdomain_counts = defaultdict(set)
        self.ENTROPY_THRESHOLD = 4.0
        self.LENGTH_THRESHOLD = 60
        self.DIGIT_RATIO_THRESHOLD = 0.3
        self.SUBDOMAIN_COUNT_THRESHOLD = 20

    def check(self, event):
        reasons = []
        domain = event.get('domain', '')
        if not domain or domain.startswith('<'):
            return False, reasons

        domain_clean = domain.replace('.', '')
        entropy = calculate_entropy(domain_clean)
        if entropy > self.ENTROPY_THRESHOLD:
            reasons.append(f"HIGH_ENTROPY({entropy:.2f})")
        if len(domain) > self.LENGTH_THRESHOLD:
            reasons.append(f"LONG_DOMAIN({len(domain)})")
        if len(domain_clean) > 0:
            digit_ratio = sum(c.isdigit() for c in domain_clean) / len(domain_clean)
            if digit_ratio > self.DIGIT_RATIO_THRESHOLD:
                reasons.append(f"HIGH_DIGIT_RATIO({digit_ratio:.0%})")

        parts = domain.split('.')
        if len(parts) > 2:
            first_subdomain = parts[0]
            if len(first_subdomain) > 20:
                if re.match(r'^[A-Za-z0-9+/=]+$', first_subdomain):
                    reasons.append("BASE64_SUBDOMAIN")
                elif re.match(r'^[0-9a-fA-F]+$', first_subdomain):
                    reasons.append("HEX_SUBDOMAIN")

        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
            self.subdomain_counts[base_domain].add(subdomain)
            if len(self.subdomain_counts[base_domain]) > self.SUBDOMAIN_COUNT_THRESHOLD:
                reasons.append(f"MANY_SUBDOMAINS({len(self.subdomain_counts[base_domain])})")

        return len(reasons) > 0, reasons
