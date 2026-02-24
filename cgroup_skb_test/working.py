#!/usr/bin/env python3
"""
DNS monitor via cgroup_skb: cluster-agnostic (any CNI, any K8s), identifies source pod by cgroup_id.
Run as root. On host: CGROUP_PATH=/sys/fs/cgroup. In K8s: mount host /sys/fs/cgroup, set CGROUP_PATH.
"""
import os
import sys
import ctypes
import json
import ssl
import urllib.error
import urllib.request

try:
    from bcc import BPF
    from bcc import BPFAttachType
except ImportError:
    print("Need BCC: pip install bpfcc (or python3-bpfcc)", file=sys.stderr)
    sys.exit(1)

# BPF: load from file next to this script (single source of truth)
BPF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_cgroup_working.bpf.c")


def _load_bpf_source():
    if not os.path.isfile(BPF_FILE):
        raise FileNotFoundError(
            f"BPF source not found: {BPF_FILE}. Run from cgroup_skb_test/ or ensure dns_cgroup_working.bpf.c is next to working.py."
        )
    with open(BPF_FILE, "r") as f:
        return f.read()

# --- cgroup_id → pod resolver (best-effort; works in K8s when path is available) ---
BPF_CGROUP_GET_FD_BY_ID = 26
# Syscall number for bpf(2); differs by arch (x86_64=321, aarch64=280, x86=386, ...)
def _syscall_bpf():
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        return None
    machine = os.uname().machine
    SYS_bpf = {"x86_64": 321, "aarch64": 280, "armv7l": 386, "i686": 357}.get(machine, 321)
    def _get_fd(cgroup_id):
        class BpfAttr(ctypes.Structure):
            _fields_ = [("cgroup_id", ctypes.c_uint64)]
        attr = BpfAttr(cgroup_id=cgroup_id)
        fd = libc.syscall(ctypes.c_long(SYS_bpf), ctypes.c_uint(BPF_CGROUP_GET_FD_BY_ID), ctypes.byref(attr), ctypes.c_uint(ctypes.sizeof(attr)))
        return int(fd) if fd >= 0 else -1
    return _get_fd

_bpf_cgroup_get_fd = None
def _bpf_cgroup_get_fd_by_id(cgroup_id):
    global _bpf_cgroup_get_fd
    if _bpf_cgroup_get_fd is None:
        _bpf_cgroup_get_fd = _syscall_bpf()
    if _bpf_cgroup_get_fd is None:
        return -1
    return _bpf_cgroup_get_fd(cgroup_id)

def _cgroup_path_from_fd(fd):
    """Try to get cgroup path from fd (readlink or fdinfo). Returns path or None."""
    try:
        link = os.readlink(f"/proc/self/fd/{fd}")
        if link and link.startswith("/") and "cgroup" in link:
            return link
    except (OSError, FileNotFoundError):
        pass
    try:
        with open(f"/proc/self/fdinfo/{fd}", "r") as f:
            for line in f:
                if line.startswith("cgroup:"):
                    parts = line.strip().split(":", 1)
                    if len(parts) == 2 and parts[1].strip().startswith("/"):
                        return parts[1].strip().split()[0]
    except (OSError, FileNotFoundError):
        pass
    return None

def _pod_uid_from_cgroup_path(path):
    """Extract pod UID (12 chars) from cgroup v2 path (kubepods.slice/.../pod<uid>.slice/...)."""
    if not path or "kubepods" not in path:
        return None
    parts = path.replace("\\", "/").split("/")
    for part in parts:
        if "-pod" in part and ".slice" in part:
            idx = part.find("-pod") + 4
            uid_part = part[idx:].split(".slice")[0].replace("_", "-")
            if uid_part and uid_part[0].isalnum():
                return uid_part[:12]
    return None

def _k8s_resolve_uid_to_pod(uid_12):
    """Resolve pod UID to namespace/name via K8s API. Returns 'ns/name' or None."""
    if not os.environ.get("KUBERNETES_SERVICE_HOST") or not os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"):
        return None
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r") as f:
            token = f.read().strip()
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        ctx = ssl.create_default_context(cafile=ca) if os.path.exists(ca) else ssl.create_default_context()
        url = f"https://{host}:{port}/api/v1/pods?limit=500"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            uid = (meta.get("uid") or "")
            if uid.startswith(uid_12) or uid_12 in uid:
                ns = meta.get("namespace", "default")
                name = meta.get("name", "")
                return f"{ns}/{name}"
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, KeyError):
        pass
    return None

class PodResolver:
    """Resolve cgroup_id to pod identifier (pod_uid or namespace/name)."""
    def __init__(self):
        self._cache = {}

    def resolve(self, cgroup_id):
        if cgroup_id == 0:
            return "host?"
        if cgroup_id in self._cache:
            return self._cache[cgroup_id]
        out = self._do_resolve(cgroup_id)
        self._cache[cgroup_id] = out
        return out

    def _do_resolve(self, cgroup_id):
        fd = _bpf_cgroup_get_fd_by_id(cgroup_id)
        if fd < 0:
            return f"cgroup_id={cgroup_id}"
        try:
            path = _cgroup_path_from_fd(fd)
            if path:
                uid = _pod_uid_from_cgroup_path(path)
                if uid:
                    ns_name = _k8s_resolve_uid_to_pod(uid)
                    if ns_name:
                        return ns_name
                    return f"pod_uid:{uid}"
            return f"cgroup_id={cgroup_id}"
        finally:
            try:
                os.close(fd)
            except OSError:
                pass


def main():
    CGROUP_PATH = os.environ.get("CGROUP_PATH", "/sys/fs/cgroup")

    print("[*] Cluster-agnostic DNS monitor (cgroup_skb); attach to cgroup, identify pod by cgroup_id")
    bpf_text = _load_bpf_source()
    print(f"[*] Compiling BPF and attaching to {CGROUP_PATH}...")
    try:
        b = BPF(text=bpf_text)
        fn_egress = b.load_func("egress_hook", BPF.CGROUP_SKB)
        fn_ingress = b.load_func("ingress_hook", BPF.CGROUP_SKB)
        fd = os.open(CGROUP_PATH, os.O_RDONLY)
        b.attach_func(fn_egress, fd, BPFAttachType.CGROUP_INET_EGRESS)
        b.attach_func(fn_ingress, fd, BPFAttachType.CGROUP_INET_INGRESS)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    class Event(ctypes.Structure):
        _fields_ = [
            ("direction", ctypes.c_uint8),
            ("_pad", ctypes.c_uint8 * 7),
            ("cgroup_id", ctypes.c_uint64),
            ("payload", ctypes.c_uint8 * 64),
        ]

    resolver = PodResolver()

    def print_event(cpu, data, size):
        if size < 8 + 64:
            return
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        payload_bytes = bytes(event.payload)
        printable = "".join([chr(b) if 32 <= b <= 126 else "." for b in payload_bytes])
        query_parts = printable.split("..")
        detected_name = "Unknown"
        for part in query_parts:
            if len(part) > 3:
                detected_name = part.strip(".")
                break

        direction = "OUT" if event.direction == 1 else "IN "
        pod_label = resolver.resolve(event.cgroup_id)
        print(f"[{direction}] pod={pod_label} | {detected_name}")

        for part in detected_name.split("."):
            if len(part) > 40:
                print(f"      [!!!] TUNNELING ALERT: long label ({len(part)} chars) from pod={pod_label}")

    b["events"].open_perf_buffer(print_event)
    print("[+] Monitor active. Generate DNS (e.g. nslookup ...). Ctrl+C to stop.")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
