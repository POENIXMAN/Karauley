"""Resolve process (host PID) to pod/container via cgroup. Optional K8s API for namespace/name."""
import json
import os
import ssl
import urllib.error
import urllib.request

from dns_monitor import config
from dns_monitor.devmode import dev_log


class PodResolver:
    """Resolve cgroup_id / host PID to pod (UID or namespace/name)."""

    def __init__(self):
        self.cgroup_cache = {}
        self._uid_to_ns_name = {}
        self._k8s_resolve_enabled = None

    def _in_cluster(self):
        if self._k8s_resolve_enabled is None:
            self._k8s_resolve_enabled = bool(os.environ.get("KUBERNETES_SERVICE_HOST"))
        return self._k8s_resolve_enabled

    def _resolve_uid_to_namespace_name(self, uid_12):
        """Resolve pod UID (12 chars) to namespace/name via K8s API. Cached."""
        if uid_12 in self._uid_to_ns_name:
            return self._uid_to_ns_name[uid_12]
        if not self._in_cluster():
            return None
        try:
            token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            if not host or not os.path.exists(token_path):
                return None
            with open(token_path, "r") as f:
                token = f.read().strip()
            ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
            ctx = ssl.create_default_context(cafile=ca) if os.path.exists(ca) else ssl.create_default_context()
            url = f"https://{host}:{port}/api/v1/pods?limit=500"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            for item in data.get("items", []):
                meta = item.get("metadata", {})
                uid = meta.get("uid", "")
                if uid.startswith(uid_12):
                    ns = meta.get("namespace", "default")
                    name = meta.get("name", "")
                    result = f"{ns}/{name}"
                    self._uid_to_ns_name[uid_12] = result
                    return result
            self._uid_to_ns_name[uid_12] = None
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError, KeyError) as e:
            dev_log("pod", f"K8s API resolve uid_12={uid_12!r}: {e}")
        return None

    def get_pod_info(self, pid, cgroup_id, netns_id):
        """Get pod info (cgroup -> uid; optionally namespace/name)."""
        if cgroup_id in self.cgroup_cache:
            return self.cgroup_cache[cgroup_id]

        pod_info = self._resolve_from_cgroup(pid)

        if pod_info and pod_info.get("type") == "kubernetes":
            uid = pod_info.get("pod_uid", "")
            if uid:
                ns_name = self._resolve_uid_to_namespace_name(uid)
                if ns_name:
                    pod_info["namespace_name"] = ns_name
        self.cgroup_cache[cgroup_id] = pod_info  # cache result (including None) to avoid repeated /proc reads
        return pod_info

    def _resolve_from_cgroup(self, pid):
        """Read host /proc/<pid>/cgroup to get pod/container. Use HOST_PROC."""
        proc_root = os.environ.get(config.ENV_HOST_PROC, "/proc")
        cgroup_path = os.path.join(proc_root, str(pid), "cgroup")
        try:
            exists = os.path.exists(cgroup_path)
            first_line = "n/a"
            if exists:
                try:
                    with open(cgroup_path, 'r') as f:
                        first_line = (f.readline() or "").strip()[:120]
                except Exception as e:
                    first_line = f"read_err:{e}"
            dev_log("pod", f"pid={pid} HOST_PROC={proc_root!r} path={cgroup_path!r} exists={exists} cgroup_line={first_line!r}")

            if not exists:
                return None

            with open(cgroup_path, 'r') as f:
                for line in f:
                    if 'kubepods' in line or 'docker' in line or 'containerd' in line:
                        parts = line.strip().split('/')

                        for i, part in enumerate(parts):
                            if part.startswith('pod') and not part.startswith('pod.'):
                                pod_uid = part[3:]
                                if pod_uid and pod_uid[0].isalnum():
                                    container_id = parts[i+1] if i+1 < len(parts) else None
                                    result = {
                                        'type': 'kubernetes',
                                        'pod_uid': pod_uid[:12],
                                        'container_id': container_id[:12] if container_id else None,
                                        'full_path': line.strip()
                                    }
                                    dev_log("pod", f"pid={pid} -> pod_uid={result['pod_uid']} (v1) container_id={result.get('container_id')}")
                                    return result

                        for part in parts:
                            if 'kubepods' in part and '-pod' in part and '.slice' in part:
                                idx = part.find('-pod') + 4
                                uid_part = part[idx:].split('.slice')[0]
                                uid_part = (uid_part or "").replace('_', '-')
                                uid_12 = uid_part[:12] if uid_part else ""
                                if uid_12 and uid_12[0].isalnum():
                                    result = {
                                        'type': 'kubernetes',
                                        'pod_uid': uid_12,
                                        'container_id': None,
                                        'full_path': line.strip()
                                    }
                                    dev_log("pod", f"pid={pid} -> pod_uid={result['pod_uid']} (v2) container_id={result.get('container_id')}")
                                    return result

                        for part in parts:
                            if len(part) == 64 and part.isalnum():
                                result = {
                                    'type': 'docker',
                                    'container_id': part[:12],
                                    'full_path': line.strip()
                                }
                                dev_log("pod", f"pid={pid} -> container_id={result['container_id']}")
                                return result

            return None

        except (IOError, PermissionError) as e:
            dev_log("pod", f"pid={pid} path={cgroup_path!r} error={e}")
            return None
