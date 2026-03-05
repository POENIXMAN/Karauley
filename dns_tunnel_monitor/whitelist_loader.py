"""Load TXT whitelist from file (UTF-8). No rebuild needed — mount ConfigMap, set env, restart pod."""
import os

from dns_tunnel_monitor import config

# Секции в файле: [domains] — суффиксы (.google.com), [prefixes] — префиксы (_dmarc.), [roots] — точное совпадение (sendgrid.com)
SECTIONS = ("domains", "prefixes", "roots")


def _parse_whitelist_file(path):
    """Parse file: [domains], [prefixes], [roots]. Returns dict section -> set of strings."""
    result = {s: set() for s in SECTIONS}
    current = None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower() == "[domains]":
                    current = "domains"
                elif line.lower() == "[prefixes]":
                    current = "prefixes"
                elif line.lower() == "[roots]":
                    current = "roots"
                elif current:
                    result[current].add(line)
    except OSError:
        return None
    return result


def load_txt_whitelist():
    """
    Load TXT whitelist: built-in + optional file (env TXT_WHITELIST_FILE).
    File is UTF-8; sections [domains], [prefixes], [roots] add to built-in.
    Returns (prefixes_tuple, domains_suffix_tuple, roots_set).
    """
    # Встроенные списки (как в коде сейчас)
    builtin_prefixes = (
        "_dmarc.", "_domainkey.", "_mta-sts.", "_smtp._tls.",
        "_acme-challenge.", "_bimi.", "_dnslink.",
        "_spf.", "_amazonses.", "_google.",
    )
    builtin_domains = (
        ".google.com", ".googleapis.com", ".microsoft.com", ".cloudflare.com",
        ".amazonaws.com", ".github.com", ".githubusercontent.com", ".atlassian.com",
        ".fastly.com", ".apple.com", ".googledomains.com", ".yandex.ru", ".yandex.net",
        ".cloudflare.net", ".akamai.net", ".facebook.com", ".meta.com", ".twitter.com",
        ".linkedin.com", ".zoom.us", ".slack.com", ".dropbox.com", ".box.com",
        ".stripe.com", ".paypal.com", ".spotify.com", ".twitch.tv", ".redhat.com",
        ".openshift.com", ".kubernetes.io", ".k8s.io",
        ".netflix.com", ".adobe.com", ".oracle.com", ".ibm.com", ".cisco.com",
        ".vmware.com", ".salesforce.com", ".hubspot.com", ".mailchimp.com",
        ".sendgrid.com", ".postmark.pm", ".protonmail.com", ".tutanota.com",
        ".yahoo.com", ".mail.ru", ".outlook.com", ".icloud.com",
        ".shopify.com", ".wordpress.com", ".notion.so", ".figma.com", ".vercel.com",
        ".docker.com", ".nginx.com", ".nginx.org", ".debian.org", ".ubuntu.com",
        ".mozilla.org", ".discord.com",
        ".microsoftonline.com", ".windows.net", ".npmjs.org", ".npmjs.com",
        ".bing.com", ".live.com", ".office.com", ".office365.com",
        ".akamai.com", ".docker.io",
    )
    builtin_roots = {
        "google.com", "yahoo.com", "microsoft.com", "apple.com",
        "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
        "github.com", "cloudflare.com", "netflix.com", "spotify.com",
        "adobe.com", "oracle.com", "ibm.com", "cisco.com", "vmware.com",
        "salesforce.com", "slack.com", "zoom.us", "dropbox.com",
        "mailchimp.com", "sendgrid.com", "paypal.com", "stripe.com",
        "shopify.com", "wordpress.com", "reddit.com", "mozilla.org",
        "gitlab.com", "atlassian.com", "notion.so", "figma.com",
        "protonmail.com", "tutanota.com", "fastmail.com", "zoho.com",
        "yandex.ru", "mail.ru", "outlook.com", "icloud.com",
        "discord.com", "box.com", "vercel.com", "redhat.com",
        "fastly.com", "akamai.com", "hubspot.com", "npmjs.com",
        "docker.com", "nginx.com", "nginx.org", "debian.org", "ubuntu.com",
    }

    prefixes = set(builtin_prefixes)
    domains = set(builtin_domains)
    roots = set(builtin_roots)

    path = os.environ.get(config.ENV_TXT_WHITELIST_FILE, "").strip()
    if path and os.path.isfile(path):
        parsed = _parse_whitelist_file(path)
        if parsed:
            prefixes |= parsed["prefixes"]
            domains |= parsed["domains"]
            roots |= parsed["roots"]

    return (tuple(prefixes), tuple(domains), roots)
