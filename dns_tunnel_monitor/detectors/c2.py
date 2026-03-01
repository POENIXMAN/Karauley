"""C2 detector: regularity, TXT requests."""
from collections import defaultdict


class C2Detector:
    def __init__(self):
        self.query_history = defaultdict(list)
        self.MAX_HISTORY = 20
        self.MIN_SAMPLES = 5
        self.REGULARITY_THRESHOLD = 0.15

    def check(self, event):
        reasons = []
        parts = event.get('domain', '').split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else event.get('domain', '')

        key = (event.get('cgroup_id', 0), base_domain)
        timestamp = event.get('timestamp_ns', 0)
        # Beacon regularity: only use query timestamps (responses would skew intervals)
        if event.get('direction') == 'query' and timestamp:
            self.query_history[key].append(timestamp)
        if len(self.query_history[key]) > self.MAX_HISTORY:
            self.query_history[key] = self.query_history[key][-self.MAX_HISTORY:]

        timestamps = self.query_history[key]
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
            if not any(base_domain.endswith(w) for w in ['.google.com', '.microsoft.com', '.cloudflare.com']):
                reasons.append("C2_TXT_REQUEST")

        return len(reasons) > 0, reasons
