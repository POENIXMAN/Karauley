"""Handle normalized DNS event: stats, detectors, metrics, log."""
from collections import defaultdict

from dns_tunnel_monitor import config
from dns_tunnel_monitor.dns_parsing import calculate_entropy, get_dns_type_name
from dns_tunnel_monitor.detectors import tunnel_detector
from dns_tunnel_monitor import metrics

RED = config.RED
GREEN = config.GREEN
YELLOW = config.YELLOW
BLUE = config.BLUE
CYAN = config.CYAN
BOLD = config.BOLD
RESET = config.RESET

stats = {
    "total": 0,
    "udp_queries": 0,
    "udp_responses": 0,
    "suspicious": 0,
    "domains": set(),
    "by_pod": defaultdict(int),
}


def handle_event(event):
    """Process one normalized event (dict from loader)."""
    global stats
    domain = event.get("domain", "<unparseable>")
    direction = event.get("direction", "query")
    protocol = event.get("protocol", "UDP")
    client_pod = event.get("client_pod", "unknown")
    dns_id = event.get("dns_id", 0)
    dns_flags = event.get("dns_flags", 0)
    dns_type = event.get("dns_type", 1)
    dns_answers = event.get("dns_answers", 0)

    is_response = direction == "response"
    dns_type_name = get_dns_type_name(dns_type)

    stats["total"] += 1
    stats["by_pod"][client_pod] += 1

    if protocol == "UDP":
        if is_response:
            stats["udp_responses"] += 1
            if metrics.FLASK_AVAILABLE:
                metrics.dns_responses_total.labels(protocol="UDP").inc()
        else:
            stats["udp_queries"] += 1
            if metrics.FLASK_AVAILABLE:
                metrics.dns_queries_total.labels(protocol="UDP").inc()

    if domain and not domain.startswith("<"):
        stats["domains"].add(domain)
        if metrics.FLASK_AVAILABLE:
            metrics.dns_domains_unique.set(len(stats["domains"]))

    direction_label = "query" if not is_response else "response"
    process = event.get("process", "unknown")
    if metrics.FLASK_AVAILABLE:
        metrics.dns_events_by_process.labels(process=process, client_pod=client_pod, direction=direction_label).inc()
        metrics.dns_events_by_pod.labels(client_pod=client_pod, direction=direction_label).inc()

    event_data = {
        "domain": domain,
        "dns_type": dns_type,
        "dns_answers": dns_answers,
        "cgroup_id": event.get("cgroup_id", 0),
    }
    is_suspicious, threat_type, threat_reasons = tunnel_detector.analyze(event_data)

    if is_suspicious:
        stats["suspicious"] += 1
        if metrics.FLASK_AVAILABLE:
            metrics.dns_suspicious_total.labels(threat_type=threat_type or "UNKNOWN").inc()

    color = RED if is_suspicious else (BLUE if is_response else GREEN)
    dir_label = "RESPONSE" if is_response else "QUERY"
    print(f"{color}{protocol:3} {dir_label:8}{RESET} | ID:{dns_id:04x} | {process} @ {client_pod} | {dns_type_name:>5} | {domain}")

    if is_suspicious:
        print(f"         {RED}SUSPICIOUS [{threat_type}]: {', '.join(threat_reasons)}{RESET}")
        if domain and not domain.startswith("<"):
            entropy = calculate_entropy(domain.replace(".", ""))
            print(f"         {YELLOW}Entropy: {entropy:.2f} | Flags: 0x{dns_flags:04x}{RESET}")


def print_stats():
    print("\n" + "=" * 60)
    print(f"{BOLD}  DNS Tunnel Monitor — stats{RESET}")
    print("=" * 60)
    print(f"  Total events:    {stats['total']}")
    print(f"  UDP queries:     {stats['udp_queries']}")
    print(f"  UDP responses:   {stats['udp_responses']}")
    print(f"  Suspicious:      {RED}{stats['suspicious']}{RESET}")
    print(f"  Unique domains: {len(stats['domains'])}")
    if stats["by_pod"]:
        print("  By pod:")
        for pod, count in sorted(stats["by_pod"].items(), key=lambda x: -x[1])[:10]:
            print(f"    {pod:<40} {count:>5}")
    print("=" * 60)
