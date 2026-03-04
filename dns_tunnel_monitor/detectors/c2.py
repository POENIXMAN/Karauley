"""C2 detector: regularity, TXT requests."""
from collections import OrderedDict


class C2Detector:
    # BUG-11: ограничение числа ключей (cgroup_id, base_domain) — LRU eviction
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
        # Beacon regularity: only use query timestamps (responses would skew intervals)
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

            # Легитимные TXT-префиксы: SPF/DKIM/DMARC/MTA-STS/BIMI/ACME — всегда легитимные
            legit_txt_prefixes = (
                '_dmarc.', '_domainkey.', '_mta-sts.', '_smtp._tls.',
                '_acme-challenge.', '_bimi.', '_dnslink.',
                '_spf.', '_amazonses.', '_google.',
            )
            is_legit_txt_prefix = any(
                domain_full.startswith(p) or f'.{p}' in domain_full
                for p in legit_txt_prefixes
            )

            # Домены, TXT которых всегда легитимны (root SPF, etc.)
            txt_whitelist_domains = (
                '.google.com', '.googleapis.com', '.microsoft.com', '.cloudflare.com',
                '.amazonaws.com', '.github.com', '.githubusercontent.com', '.atlassian.com',
                '.fastly.com', '.apple.com', '.googledomains.com', '.yandex.ru', '.yandex.net',
                '.cloudflare.net', '.akamai.net', '.facebook.com', '.meta.com', '.twitter.com',
                '.linkedin.com', '.zoom.us', '.slack.com', '.dropbox.com', '.box.com',
                '.stripe.com', '.paypal.com', '.spotify.com', '.twitch.tv', '.redhat.com',
                '.openshift.com', '.kubernetes.io', '.k8s.io',
                '.netflix.com', '.adobe.com', '.oracle.com', '.ibm.com', '.cisco.com',
                '.vmware.com', '.salesforce.com', '.hubspot.com', '.mailchimp.com',
                '.sendgrid.com', '.postmark.pm', '.protonmail.com', '.tutanota.com',
                '.yahoo.com', '.mail.ru', '.outlook.com', '.icloud.com',
                '.shopify.com', '.wordpress.com', '.notion.so', '.figma.com', '.vercel.com',
                '.docker.com', '.nginx.com', '.nginx.org', '.debian.org', '.ubuntu.com',
                '.mozilla.org', '.discord.com',
            )

            is_whitelisted_domain = (
                domain_full in ('google.com', 'yahoo.com', 'microsoft.com', 'apple.com',
                                'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
                                'github.com', 'cloudflare.com', 'netflix.com', 'spotify.com',
                                'adobe.com', 'oracle.com', 'ibm.com', 'cisco.com', 'vmware.com',
                                'salesforce.com', 'slack.com', 'zoom.us', 'dropbox.com',
                                'mailchimp.com', 'sendgrid.com', 'paypal.com', 'stripe.com',
                                'shopify.com', 'wordpress.com', 'reddit.com', 'mozilla.org',
                                'gitlab.com', 'atlassian.com', 'notion.so', 'figma.com',
                                'protonmail.com', 'tutanota.com', 'fastmail.com', 'zoho.com',
                                'yandex.ru', 'mail.ru', 'outlook.com', 'icloud.com')
                or any(domain_full.endswith(w) for w in txt_whitelist_domains)
            )

            if not is_legit_txt_prefix and not is_whitelisted_domain:
                reasons.append("C2_TXT_REQUEST")

        return len(reasons) > 0, reasons
