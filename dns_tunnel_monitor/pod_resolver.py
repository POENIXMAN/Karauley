"""Resolve cgroup_id to ns/podname (priority) or cgroup_id=... / host."""
import os
import ctypes
import json
import ssl
import urllib.error
import urllib.request

BPF_CGROUP_GET_FD_BY_ID = 26
_SYS_bpf = {"x86_64": 321, "aarch64": 280, "armv7l": 386, "i686": 357}
_bpf_get_fd = None


def _bpf_cgroup_get_fd_by_id(cgroup_id):
    global _bpf_get_fd
    if _bpf_get_fd is None:
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            machine = os.uname().machine
            SYS_bpf = _SYS_bpf.get(machine, 321)

            def get_fd(cgid):
                class BpfAttr(ctypes.Structure):
                    _fields_ = [("cgroup_id", ctypes.c_uint64)]
                attr = BpfAttr(cgroup_id=cgid)
                fd = libc.syscall(
                    ctypes.c_long(SYS_bpf),
                    ctypes.c_uint(BPF_CGROUP_GET_FD_BY_ID),
                    ctypes.byref(attr),
                    ctypes.c_uint(ctypes.sizeof(attr)),
                )
                return int(fd) if fd >= 0 else -1
            _bpf_get_fd = get_fd
        except OSError:
            _bpf_get_fd = lambda _: -1
    return _bpf_get_fd(cgroup_id)


def _cgroup_path_from_fd(fd):
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


def _k8s_resolve_uid_to_ns_name(uid_12):
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
    """Resolve cgroup_id to ns/podname (priority) or fallback."""

    def __init__(self):
        self._cache = {}

    def resolve(self, cgroup_id):
        if cgroup_id == 0:
            return "host"
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
                    ns_name = _k8s_resolve_uid_to_ns_name(uid)
                    if ns_name:
                        return ns_name
                    return f"pod_uid:{uid}"
            return f"cgroup_id={cgroup_id}"
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
