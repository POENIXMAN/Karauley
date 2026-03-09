import os
import sys
import ctypes
import time

from bcc import BPF
from bcc import BPFAttachType

from dns_tunnel_monitor import config
from dns_tunnel_monitor.event_struct import CgroupDNSEvent
from dns_tunnel_monitor.dns_parsing import parse_dns_name, parse_dns_type, get_dns_type_name
from dns_tunnel_monitor.pod_resolver import PodResolver


def _parse_payload(payload_bytes):
    data = list(payload_bytes)
    domain = None
    if len(data) >= 12:
        domain = parse_dns_name(data, offset=12)
    if not domain:
        domain = "<unparseable>"
    dns_id = (data[0] << 8 | data[1]) if len(data) >= 2 else 0
    dns_flags = (data[2] << 8 | data[3]) if len(data) >= 4 else 0
    dns_questions = (data[4] << 8 | data[5]) if len(data) >= 6 else 0
    dns_answers = (data[6] << 8 | data[7]) if len(data) >= 8 else 0
    dns_type = parse_dns_type(data) if data else 1
    return domain, dns_id, dns_flags, dns_answers, dns_type


def load_bpf(cgroup_path, event_callback):
    """Returns (bpf_object, cgroup_fd) or (None, error_msg). event_callback(normalized_event_dict) per packet."""
    if not os.path.isfile(config.BPF_SOURCE_FILE):
        return None, f"BPF source not found: {config.BPF_SOURCE_FILE}"

    try:
        with open(config.BPF_SOURCE_FILE, "r") as f:
            bpf_text = f.read()
    except Exception as e:
        return None, str(e)

    try:
        bpf = BPF(text=bpf_text)
        fn_egress = bpf.load_func("egress_hook", BPF.CGROUP_SKB)
        fn_ingress = bpf.load_func("ingress_hook", BPF.CGROUP_SKB)
        cgroup_fd = os.open(cgroup_path, os.O_RDONLY)
        bpf.attach_func(fn_egress, cgroup_fd, BPFAttachType.CGROUP_INET_EGRESS)
        bpf.attach_func(fn_ingress, cgroup_fd, BPFAttachType.CGROUP_INET_INGRESS)
    except Exception as e:
        return None, str(e)

    resolver = PodResolver()

    def _ringbuf_cb(ctx, data, size):
        if size < ctypes.sizeof(CgroupDNSEvent):
            return
        raw_event = ctypes.string_at(data, size)
        ev = CgroupDNSEvent.from_buffer_copy(raw_event[:ctypes.sizeof(CgroupDNSEvent)])
        payload_bytes = bytes(ev.payload)
        domain, dns_id, dns_flags, dns_answers, dns_type = _parse_payload(payload_bytes)
        is_response = (dns_flags & 0x8000) != 0
        direction = "response" if is_response else "query"
        client_pod, process = resolver.resolve_with_process(ev.cgroup_id)
        normalized = {
            "domain": domain,
            "direction": direction,
            "protocol": "UDP",
            "client_pod": client_pod,
            "process": process,
            "cgroup_id": ev.cgroup_id,
            "dns_id": dns_id,
            "dns_flags": dns_flags,
            "dns_answers": dns_answers,
            "dns_type": dns_type,
            "timestamp_ns": time.time_ns(),
            "ip_version": getattr(ev, "ip_version", 4),
        }
        if domain == "<unparseable>":
            normalized["payload_sample_hex"] = payload_bytes[:12].hex()
        try:
            event_callback(normalized)
        except Exception as e:
            print(f"[!] event_callback error: {e}", file=sys.stderr, flush=True)

    try:
        bpf["events"].open_ring_buffer(_ringbuf_cb)
    except Exception as e:
        try:
            os.close(cgroup_fd)
        except OSError:
            pass
        return None, f"Failed to open ring buffer (requires BCC/kernel ringbuf support): {e}"
    return bpf, cgroup_fd
