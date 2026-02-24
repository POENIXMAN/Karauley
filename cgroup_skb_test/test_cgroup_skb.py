#!/usr/bin/env python3
"""
Minimal test: load CGROUP_SKB program, attach to cgroup, print DNS payload bytes.
Run as root. Generate DNS (e.g. nslookup google.com) in another terminal.
"""
import os
import sys

# Default cgroup v2 root; override with CGROUP_PATH env
CGROUP_PATH = os.environ.get("CGROUP_PATH", "/sys/fs/cgroup")

def main():
    try:
        from bcc import BPF
        try:
            from bcc import BPFAttachType
        except ImportError:
            BPFAttachType = None
    except ImportError as e:
        print("Need BCC: pip install bpfcc (or python3-bpfcc)", file=sys.stderr)
        sys.exit(1)

    # Log BCC version and available attach helpers
    try:
        import bcc.version
        print(f"[*] BCC version: {getattr(bcc.version, '__version__', 'unknown')}")
    except Exception:
        print("[*] BCC version: unknown")
    print(f"[*] BPF.CGROUP_SKB = {getattr(BPF, 'CGROUP_SKB', 'N/A')}")
    print(f"[*] BPFAttachType: CGROUP_INET_EGRESS={getattr(BPFAttachType, 'CGROUP_INET_EGRESS', None)}, CGROUP_INET_INGRESS={getattr(BPFAttachType, 'CGROUP_INET_INGRESS', None)}")
    print(f"[*] Has attach_func: {hasattr(BPF, 'attach_func')}, Has attach_cgroup: {hasattr(BPF, 'attach_cgroup')}")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    bpf_src = os.path.join(script_dir, "dns_cgroup_minimal.bpf.c")
    if not os.path.isfile(bpf_src):
        print(f"[!] BPF source not found: {bpf_src}", file=sys.stderr)
        sys.exit(1)

    with open(bpf_src, "r") as f:
        text = f.read()

    print(f"[*] Loading BPF from {bpf_src} ...")
    bpf = BPF(text=text)
    print("[*] BPF loaded successfully")

    print(f"[*] Opening cgroup: {CGROUP_PATH}")
    try:
        cgroup_fd = os.open(CGROUP_PATH, os.O_RDONLY)
    except OSError as e:
        print(f"[!] Failed to open cgroup {CGROUP_PATH}: {e}", file=sys.stderr)
        print("    Try: mount | grep cgroup2  and use that mount point", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Cgroup fd: {cgroup_fd}")

    # BCC uses load_func(prog_type=CGROUP_SKB, attach_type=...) then attach_func(fn, cgroup_fd, attach_type)
    if BPFAttachType is None:
        print("[!] BPFAttachType not available; cannot attach cgroup programs", file=sys.stderr)
        os.close(cgroup_fd)
        sys.exit(1)
    at_egress = BPFAttachType.CGROUP_INET_EGRESS   # 1
    at_ingress = BPFAttachType.CGROUP_INET_INGRESS  # 0

    try:
        print("[*] Loading egress program (CGROUP_SKB, CGROUP_INET_EGRESS) ...")
        fn_egress = bpf.load_func(b"egress", BPF.CGROUP_SKB, attach_type=at_egress)
        print("[*] Loading ingress program (CGROUP_SKB, CGROUP_INET_INGRESS) ...")
        fn_ingress = bpf.load_func(b"ingress", BPF.CGROUP_SKB, attach_type=at_ingress)
        print("[*] Attaching egress to cgroup ...")
        BPF.attach_func(fn_egress, cgroup_fd, at_egress)
        print("[*] Attaching ingress to cgroup ...")
        BPF.attach_func(fn_ingress, cgroup_fd, at_ingress)
        print("[+] Attached egress and ingress to cgroup")
    except Exception as e:
        print(f"[!] Attach failed: {type(e).__name__}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        os.close(cgroup_fd)
        sys.exit(1)
    os.close(cgroup_fd)

    # Event: direction (1 byte) + payload (64 bytes). BCC passes (cpu, data, size); data is raw pointer.
    import ctypes
    class Event(ctypes.Structure):
        _fields_ = [("direction", ctypes.c_uint8), ("payload", ctypes.c_uint8 * 64)]

    def on_event(cpu, data, size):
        if size < 1:
            return
        ev = ctypes.cast(data, ctypes.POINTER(Event)).contents
        label = "egress" if ev.direction == 1 else "ingress"
        payload_len = min(size - 1, 64)
        if payload_len <= 0:
            return
        payload = bytes(ev.payload[:payload_len])
        hex_str = ' '.join(f'{b:02x}' for b in payload[:32])
        if payload_len > 32:
            hex_str += " ..."
        print(f"{label}: {hex_str}")

    bpf["events"].open_perf_buffer(on_event)
    print("[*] Perf buffer opened. Polling for DNS events (generate traffic, e.g. nslookup google.com). Ctrl+C to stop.")
    while True:
        try:
            bpf.perf_buffer_poll(300)
        except KeyboardInterrupt:
            break
    print("[*] Done.")

if __name__ == "__main__":
    main()
