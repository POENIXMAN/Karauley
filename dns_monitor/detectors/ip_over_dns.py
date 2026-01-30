"""IP-Over-DNS detector: NULL records, high rate, many answers."""
from collections import defaultdict


class IPOverDNSDetector:
    """Detect IP-Over-DNS (iodine, dns2tcp): NULL type, high rate, many answers."""

    def __init__(self):
        self.request_counts = defaultdict(int)
        self.window_start = 0
        self.WINDOW_NS = 10 * 1e9
        self.RATE_THRESHOLD = 50

    def check(self, event):
        reasons = []
        timestamp = event.get('timestamp_ns', 0)
        if self.window_start == 0:
            self.window_start = timestamp
        elif timestamp - self.window_start > self.WINDOW_NS:
            self.request_counts.clear()
            self.window_start = timestamp

        domain = event.get('domain', '')
        parts = domain.split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        key = (event.get('pid', 0), base_domain)
        self.request_counts[key] += 1

        elapsed_sec = (timestamp - self.window_start) / 1e9
        if elapsed_sec > 1:
            rate = self.request_counts[key] / elapsed_sec
            if rate > self.RATE_THRESHOLD:
                reasons.append(f"HIGH_RATE({rate:.1f}/sec)")

        dns_type = event.get('dns_type', 1)
        if dns_type == 10:  # NULL
            reasons.append("NULL_RECORD(iodine)")
        dns_answers = event.get('dns_answers', 0)
        if dns_answers > 5:
            reasons.append(f"MANY_ANSWERS({dns_answers})")

        return len(reasons) > 0, reasons
