"""Load BPF program: read source, compile, open perf buffer. Kprobe mode only."""
import os
import sys
import traceback

from bcc import BPF

from dns_monitor import config
from dns_monitor.devmode import dev_log


def load_bpf(handle_event_cb):
    """
    Read BPF source, compile, open perf buffer. Returns (bpf, None) or (None, error_msg).
    Uses dns_ebpf_improved.bpf.c (kprobe on udp/tcp_sendmsg, recvmsg).
    """
    bpf_path = config.BPF_SOURCE_FILE
    dev_log("bpf", f"Loading eBPF from {bpf_path}")

    try:
        print(f"[*] Шаг 1/3: чтение файла...")
        with open(bpf_path, 'r') as f:
            bpf_text = f.read()
        print(f"[*] Шаг 1/3: OK ({len(bpf_text)} байт)")
    except Exception as e:
        print(f"[!] Ошибка на шаге 1 (чтение файла): {e}", file=sys.stderr)
        dev_log("bpf", f"Step 1 error: {e}")
        traceback.print_exc()
        return None, str(e)

    try:
        print("[*] Шаг 2/3: BPF(text=...) — компиляция и загрузка в ядро...")
        bpf = BPF(text=bpf_text)
        print("[+] Шаг 2/3: OK — eBPF программа загружена")
    except Exception as e:
        print(f"[!] Ошибка на шаге 2 (BPF load): {e}", file=sys.stderr)
        dev_log("bpf", f"Step 2 error: {e}")
        traceback.print_exc()
        return None, str(e)

    try:
        print("[*] Шаг 3/3: открытие perf buffer (map 'events')...")
        bpf["events"].open_perf_buffer(handle_event_cb)
        print("[+] Шаг 3/3: OK — perf buffer открыт")
    except Exception as e:
        print(f"[!] Ошибка на шаге 3 (open_perf_buffer): {e}", file=sys.stderr)
        dev_log("bpf", f"Step 3 error: {e}")
        traceback.print_exc()
        return None, str(e)

    return bpf, None
