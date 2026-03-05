"""Exfiltration detector: entropy, long domains, Base64/hex subdomains."""
import re
from collections import defaultdict

from dns_tunnel_monitor.dns_parsing import calculate_entropy


class ExfiltrationDetector:
    # BUG-16: ограничение роста — храним не более MAX_SUBDOMAINS_STORED поддоменов на base_domain
    MAX_SUBDOMAINS_STORED = 50

    def __init__(self):
        self.subdomain_counts = defaultdict(list)  # list для ограничения размера (evict oldest)
        self.ENTROPY_THRESHOLD = 4.1
        self.LENGTH_THRESHOLD = 60
        self.DIGIT_RATIO_THRESHOLD = 0.3
        self.SUBDOMAIN_COUNT_THRESHOLD = 40

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
                # Проверяем hex первым: hex-символы — подмножество base64, иначе HEX_SUBDOMAIN никогда не сработает (BUG-14)
                if re.match(r'^[0-9a-fA-F]+$', first_subdomain):
                    reasons.append("HEX_SUBDOMAIN")
                elif re.match(r'^[A-Za-z0-9+/=]+$', first_subdomain):
                    reasons.append("BASE64_SUBDOMAIN")

        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
            lst = self.subdomain_counts[base_domain]
            if subdomain not in lst:
                lst.append(subdomain)
                if len(lst) > self.MAX_SUBDOMAINS_STORED:
                    lst.pop(0)
            if len(lst) > self.SUBDOMAIN_COUNT_THRESHOLD:
                reasons.append(f"MANY_SUBDOMAINS({len(lst)})")

        return len(reasons) > 0, reasons
