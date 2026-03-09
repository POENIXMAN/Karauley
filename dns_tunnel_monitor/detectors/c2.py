from collections import OrderedDict

from dns_tunnel_monitor.whitelist_loader import load_txt_whitelist

_txt_whitelist_cache = None


def _get_txt_whitelist():
    global _txt_whitelist_cache
    if _txt_whitelist_cache is None:
        _txt_whitelist_cache = load_txt_whitelist()
    return _txt_whitelist_cache


class C2Detector:
    MAX_QUERY_HISTORY_KEYS = 10_000

    def __init__(self):
        self.query_history = OrderedDict()
        self.MAX_HISTORY = 20
        self.MIN_SAMPLES = 5
        self.REGULARITY_THRESHOLD = 0.15

    def check(self, event):
        reasons = []
        parts = event.get('domain', '').split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else event.get('domain', '')

        key = (event.get('cgroup_id', 0), base_domain)
        timestamp = event.get('timestamp_ns', 0)
        if event.get('direction') == 'query' and timestamp:
            if key in self.query_history:
                timestamps = self.query_history.pop(key)
            else:
                timestamps = []
                if len(self.query_history) >= self.MAX_QUERY_HISTORY_KEYS:
                    self.query_history.popitem(last=False)
            timestamps.append(timestamp)
            if len(timestamps) > self.MAX_HISTORY:
                timestamps = timestamps[-self.MAX_HISTORY:]
            self.query_history[key] = timestamps

        timestamps = self.query_history.get(key, [])
        if len(timestamps) >= self.MIN_SAMPLES and timestamp:
            intervals = [(timestamps[i+1] - timestamps[i]) / 1e9 for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval > 0:
                variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                cv = std_dev / avg_interval
                if cv < self.REGULARITY_THRESHOLD and avg_interval > 5:
                    reasons.append(f"C2_BEACON(interval={avg_interval:.1f}s, regularity={1-cv:.0%})")

        dns_type = event.get('dns_type', 1)
        if dns_type == 16:
            domain_full = event.get('domain', '')
            legit_txt_prefixes, txt_whitelist_domains, txt_whitelist_roots = _get_txt_whitelist()

            is_legit_txt_prefix = any(
                domain_full.startswith(p) or f'.{p}' in domain_full
                for p in legit_txt_prefixes
            )
            is_whitelisted_domain = (
                domain_full in txt_whitelist_roots
                or any(domain_full.endswith(w) for w in txt_whitelist_domains)
            )

            if not is_legit_txt_prefix and not is_whitelisted_domain:
                reasons.append("C2_TXT_REQUEST")

        return len(reasons) > 0, reasons
