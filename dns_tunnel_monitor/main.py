"""Entry point: load BPF, start metrics HTTP, poll perf buffer."""
import os
import sys
import signal
import threading

from dns_tunnel_monitor import config
from dns_tunnel_monitor.loader import load_bpf
from dns_tunnel_monitor.event_handler import handle_event, print_stats
from dns_tunnel_monitor import metrics

RED = config.RED
GREEN = config.GREEN
CYAN = config.CYAN
BOLD = config.BOLD
RESET = config.RESET


def main():
    cgroup_path = os.environ.get(config.ENV_CGROUP_PATH, "/sys/fs/cgroup")
    metrics_port = int(os.environ.get(config.ENV_METRICS_PORT, "9999"))

    print("=" * 60)
    print(f"{BOLD}  DNS Tunnel Monitor (cgroup_skb){RESET}")
    print("=" * 60)
    print(f"  CGROUP_PATH={cgroup_path}")
    print(f"  METRICS_PORT={metrics_port}")
    print("=" * 60)

    result = load_bpf(cgroup_path, handle_event)
    if result[0] is None:
        print(f"{RED}[!] Failed to load BPF: {result[1]}{RESET}", file=sys.stderr)
        sys.exit(1)
    bpf, cgroup_fd = result

    if metrics.FLASK_AVAILABLE:
        thread = threading.Thread(
            target=metrics.start_http_server,
            args=(metrics_port,),
            daemon=True,
            name="metrics",
        )
        thread.start()
        print(f"{GREEN}[+] Metrics: http://0.0.0.0:{metrics_port}/metrics (Prometheus){RESET}")
        print(f"    /healthz, /ready")
    else:
        print(f"[!] Metrics disabled (install flask, prometheus_client)")

    def on_exit(sig, frame):
        print_stats()
        try:
            os.close(cgroup_fd)
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, on_exit)
    signal.signal(signal.SIGTERM, on_exit)

    print("[*] Monitoring DNS (Ctrl+C to stop)...")
    print("-" * 60)

    try:
        while True:
            bpf.perf_buffer_poll(300)
    except KeyboardInterrupt:
        pass
    finally:
        print_stats()
        try:
            os.close(cgroup_fd)
        except OSError:
            pass


if __name__ == "__main__":
    main()
