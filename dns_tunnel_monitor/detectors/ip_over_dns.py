"""IP-Over-DNS detector: NULL records, high rate, many answers."""
from collections import OrderedDict


class IPOverDNSDetector:
    # NEW-01: ограничение числа ключей — LRU eviction (как в c2.py)
    MAX_KEYS = 10_000

    def __init__(self):
        # key -> (request_count, first_seen_ns); OrderedDict для LRU
        self._key_data = OrderedDict()
        self.WINDOW_NS = 10 * 1e9
        self.RATE_THRESHOLD = 50

    def check(self, event):
        reasons = []
        timestamp = event.get('timestamp_ns', 0)
        domain = event.get('domain', '')
        parts = domain.split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        key = (event.get('cgroup_id', 0), base_domain)

        if key in self._key_data:
            count, first_seen = self._key_data.pop(key)
            if timestamp and (timestamp - first_seen) > self.WINDOW_NS:
                first_seen = timestamp
                count = 0
            count += 1
            self._key_data[key] = (count, first_seen)
        else:
            if len(self._key_data) >= self.MAX_KEYS:
                self._key_data.popitem(last=False)
            first_seen = timestamp if timestamp else 0
            count = 1
            self._key_data[key] = (count, first_seen)

        if timestamp and self._key_data.get(key):
            count, first_seen = self._key_data[key]
            if first_seen:
                elapsed_sec = (timestamp - first_seen) / 1e9
                if elapsed_sec > 1:
                    rate = count / elapsed_sec
                    if rate > self.RATE_THRESHOLD:
                        reasons.append(f"HIGH_RATE({rate:.1f}/sec)")

        dns_type = event.get('dns_type', 1)
        if dns_type == 10:
            reasons.append("NULL_RECORD(iodine)")
        dns_answers = event.get('dns_answers', 0)
        if dns_answers > 5:
            reasons.append(f"MANY_ANSWERS({dns_answers})")

        return len(reasons) > 0, reasons
