"""Event handler: handle_event(cpu, data, size), stats, print_stats."""
import ctypes
import socket
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime

from dns_monitor import config
from dns_monitor.dns_parsing import (
    calculate_entropy,
    get_dns_type_name,
    parse_dns_name,
    parse_dns_type,
)
from dns_monitor.event_struct import DNSEvent
from dns_monitor.devmode import dev_log
from dns_monitor.pod_resolver import PodResolver
from dns_monitor.detectors import tunnel_detector
from dns_monitor import metrics

RED = config.RED
GREEN = config.GREEN
YELLOW = config.YELLOW
BLUE = config.BLUE
CYAN = config.CYAN
BOLD = config.BOLD
RESET = config.RESET

stats = {
    'total': 0,
    'udp_queries': 0,
    'udp_responses': 0,
    'tcp_queries': 0,
    'tcp_responses': 0,
    'by_process': defaultdict(int),
    'by_pod': defaultdict(int),
    'suspicious': 0,
    'domains': set()
}

pod_resolver = PodResolver()


def handle_event(cpu, data, size):
    """Process one eBPF event (Perf Buffer)."""
    global stats
    event = ctypes.cast(data, ctypes.POINTER(DNSEvent)).contents

    raw = event.dns_data
    data_len = event.data_len or len(raw)
    if data_len >= 12:
        domain = parse_dns_name(list(raw)[:data_len], offset=12)
    else:
        domain = None
    if not domain:
        domain = "<unparseable>"

    dns_payload = list(raw)[:data_len] if data_len else list(raw)
    dns_type = parse_dns_type(dns_payload)
    dns_type_name = get_dns_type_name(dns_type)

    is_response = (event.direction == 2)
    direction = "RESPONSE" if is_response else "QUERY"
    protocol = "TCP" if event.protocol == 6 else "UDP"
    comm = event.comm.decode('utf-8', errors='ignore').rstrip('\x00')

    pod_info = pod_resolver.get_pod_info(event.pid, event.cgroup_id, event.netns_id)
    pod_str = ""
    if pod_info:
        if pod_info.get("namespace_name"):
            pod_str = pod_info["namespace_name"]
        elif pod_info['type'] == 'kubernetes':
            pod_str = f"pod:{pod_info['pod_uid']}"
        else:
            pod_str = f"container:{pod_info['container_id']}"
    pod_label = pod_str or "host"

    dev_log("event", f"pid={event.pid} comm={comm!r} cgroup_id={event.cgroup_id} pod_str={pod_label!r}")

    saddr = socket.inet_ntoa(struct.pack('I', event.saddr)) if event.saddr else "0.0.0.0"
    daddr = socket.inet_ntoa(struct.pack('I', event.daddr)) if event.daddr else "0.0.0.0"

    if event.timestamp_ns > 0:
        boot_time = time.time() - (time.monotonic())
        ts_seconds = boot_time + (event.timestamp_ns / 1e9)
        ts = datetime.fromtimestamp(ts_seconds).strftime('%H:%M:%S.%f')[:-3]
    else:
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]

    dns_id = event.dns_id
    dns_flags = event.dns_flags

    stats['total'] += 1
    stats['by_process'][comm] += 1
    if pod_str:
        stats['by_pod'][pod_str] += 1

    if protocol == "UDP":
        if is_response:
            stats['udp_responses'] += 1
            if metrics.FLASK_AVAILABLE:
                metrics.dns_responses_total.labels(protocol='UDP').inc()
        else:
            stats['udp_queries'] += 1
            if metrics.FLASK_AVAILABLE:
                metrics.dns_queries_total.labels(protocol='UDP', direction='query').inc()
    else:
        if is_response:
            stats['tcp_responses'] += 1
            if metrics.FLASK_AVAILABLE:
                metrics.dns_responses_total.labels(protocol='TCP').inc()
        else:
            stats['tcp_queries'] += 1
            if metrics.FLASK_AVAILABLE:
                metrics.dns_queries_total.labels(protocol='TCP', direction='query').inc()

    if domain and not domain.startswith("<"):
        stats['domains'].add(domain)
        if metrics.FLASK_AVAILABLE:
            metrics.dns_domains_unique.set(len(stats['domains']))

    if metrics.FLASK_AVAILABLE:
        metrics.dns_events_by_process.labels(process=comm or "unknown", pod=pod_label).inc()
        metrics.dns_events_by_pod.labels(pod=pod_label).inc()

    event_data = {
        'domain': domain,
        'dns_type': dns_type,
        'dns_answers': event.dns_answers,
        'timestamp_ns': event.timestamp_ns,
        'pid': event.pid,
        'comm': comm,
    }
    is_suspicious, threat_type, threat_reasons = tunnel_detector.analyze(event_data)
    entropy = calculate_entropy(domain.replace('.', ''))

    if is_suspicious:
        stats['suspicious'] += 1
        if metrics.FLASK_AVAILABLE:
            threat_label = threat_type if threat_type else 'UNKNOWN'
            metrics.dns_suspicious_total.labels(threat_type=threat_label).inc()

    color = RED if is_suspicious else (BLUE if is_response else GREEN)
    pod_display = f" [{CYAN}{pod_str}{RESET}]" if pod_str else ""
    if is_response:
        ip_info = f"{daddr}←{saddr}"
    else:
        ip_info = f"{saddr}→{daddr}"

    print(f"[{ts}] {color}{protocol:3} {direction:8}{RESET} | "
          f"ID:{dns_id:04x} | "
          f"PID:{event.pid:>6} {comm:>15}{pod_display} | "
          f"{dns_type_name:>5} | {domain}")

    if is_suspicious:
        threat_label = f"[{threat_type}]" if threat_type else ""
        print(f"         {RED}⚠ SUSPICIOUS {threat_label}: {', '.join(threat_reasons)}{RESET}")
        print(f"         {YELLOW}   IP: {ip_info} | Entropy: {entropy:.2f} | Flags: 0x{dns_flags:04x}{RESET}")


def print_stats():
    """Print summary statistics."""
    print("\n" + "=" * 80)
    print(f"{BOLD}                    СТАТИСТИКА (УЛУЧШЕННАЯ ВЕРСИЯ){RESET}")
    print("=" * 80)
    print(f"""
  Всего событий:           {stats['total']}

  UDP:
    Запросов:              {stats['udp_queries']}
    Ответов:               {stats['udp_responses']}

  TCP:
    Запросов:              {stats['tcp_queries']}
    Ответов:               {stats['tcp_responses']}

  Подозрительных:          {RED}{stats['suspicious']}{RESET}
  Уникальных доменов:      {len(stats['domains'])}
""")
    print("  По процессам:")
    for proc, count in sorted(stats['by_process'].items(), key=lambda x: -x[1])[:10]:
        print(f"    {proc:<20} {count:>5}")
    if stats['by_pod']:
        print("\n  По подам/контейнерам:")
        for pod, count in sorted(stats['by_pod'].items(), key=lambda x: -x[1])[:10]:
            print(f"    {pod:<30} {count:>5}")
    print("=" * 80)
