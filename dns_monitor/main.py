"""Main: banner, RLIMIT, load BPF, start HTTP, signal, poll loop."""
import os
import resource
import signal
import sys
import threading
import time
import traceback

from dns_monitor import config
from dns_monitor.devmode import dev_log, devmode
from dns_monitor.loader import load_bpf
from dns_monitor.event_handler import handle_event, print_stats
from dns_monitor import metrics

RED = config.RED
GREEN = config.GREEN
YELLOW = config.YELLOW
CYAN = config.CYAN
BOLD = config.BOLD
RESET = config.RESET

# eBPF debug failure reasons (must match dns_ebpf_improved.bpf.c EBPF_DEBUG_*)
EBPF_DEBUG_NAMES = {
    1: "udp_send_iter_read_fail",
    2: "udp_send_data_ptr_null",
    3: "udp_send_probe_read_fail",
    4: "udp_recv_no_ptr",
    5: "udp_recv_probe_read_fail",
}


def log_ebpf_debug_counts(bpf):
    """Read eBPF debug failure map and log to stderr (shows in container logs)."""
    try:
        tbl = bpf["ebpf_debug_fail"]
        parts = []
        for i in range(1, 6):
            try:
                v = tbl[i]
                count = getattr(v, "value", v)
                if count is None:
                    count = 0
                else:
                    count = int(count)
            except Exception:
                count = 0
            if count > 0:
                name = EBPF_DEBUG_NAMES.get(i, f"reason_{i}")
                parts.append(f"{name}={count}")
        if parts:
            print(f"[eBPF debug] data_len=0 failures: {', '.join(parts)}", file=sys.stderr, flush=True)
    except KeyError:
        pass  # map not present (old eBPF object)
    except Exception as e:
        dev_log("bpf", f"ebpf_debug_fail read: {e}")


def _ebpf_debug_loop(bpf_obj, interval_sec):
    """Daemon thread: log eBPF failure counts every interval_sec."""
    while True:
        time.sleep(interval_sec)
        log_ebpf_debug_counts(bpf_obj)


def signal_handler(sig, frame):
    print_stats()
    sys.exit(0)


def main():
    print("=" * 80)
    print(f"{BOLD}       DNS TUNNEL DETECTOR v2.1 (Ring Buffer){RESET}")
    print("=" * 80)
    print(f"  Детекция типов туннелей:")
    print(f"    ✓ {CYAN}C2{RESET}     - Command & Control (регулярность, TXT)")
    print(f"    ✓ {CYAN}EXFIL{RESET}  - Data Exfiltration (entropy, Base64)")
    print(f"    ✓ {CYAN}TUNNEL{RESET} - IP-Over-DNS (iodine, NULL records)")
    print(f"  Возможности:")
    print(f"    ✓ UDP + TCP DNS")
    print(f"    ✓ Kubernetes pod идентификация")
    print(f"    ✓ Kernel timestamp (для анализа частоты)")
    print(f"    ✓ {GREEN}Perf Buffer{RESET} (совместимость при ограничениях памяти)")
    print("=" * 80)

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        soft_s = "unlimited" if soft == -1 else f"{soft} bytes"
        hard_s = "unlimited" if hard == -1 else f"{hard} bytes"
        dev_log("bpf", f"RLIMIT_MEMLOCK: soft={soft_s}, hard={hard_s}")
        if devmode:
            print(f"\n[DEBUG] RLIMIT_MEMLOCK: soft={soft_s}, hard={hard_s}")
    except (ValueError, OSError, AttributeError) as e:
        dev_log("bpf", f"RLIMIT_MEMLOCK: N/A ({e})")
        print(f"\n[DEBUG] RLIMIT_MEMLOCK: N/A ({e})")

    print(f"\n[*] Загрузка eBPF из {config.BPF_SOURCE_FILE}...")
    bpf, err = load_bpf(handle_event)
    if bpf is None:
        print(f"{RED}[!] Ошибка загрузки eBPF: {err}{RESET}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

    metrics_port = int(os.environ.get(config.ENV_METRICS_PORT, '9999'))
    if metrics.FLASK_AVAILABLE:
        http_thread = threading.Thread(
            target=metrics.start_http_server,
            args=(metrics_port,),
            daemon=True,
            name='HTTP-Server'
        )
        http_thread.start()
        print(f"{GREEN}[+] HTTP сервер запущен на порту {metrics_port}{RESET}")
        print(f"    - /healthz - liveness probe")
        print(f"    - /ready - readiness probe")
        print(f"    - /metrics - Prometheus metrics")
    else:
        print(f"{YELLOW}[!] HTTP сервер недоступен (Flask не установлен){RESET}")

    signal.signal(signal.SIGINT, signal_handler)
    print(f"[*] Используется Perf Buffer")
    # Log eBPF failure reasons to stderr every 30s (visible in container logs when data_len=0)
    try:
        debug_thread = threading.Thread(
            target=_ebpf_debug_loop,
            args=(bpf, 30),
            daemon=True,
            name='eBPF-debug',
        )
        debug_thread.start()
    except Exception:
        pass
    print("-" * 80)

    while True:
        try:
            bpf.perf_buffer_poll(300)
        except KeyboardInterrupt:
            break

    print_stats()
