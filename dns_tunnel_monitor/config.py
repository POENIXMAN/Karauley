"""Config: CGROUP_PATH, METRICS_PORT, BPF path, colors."""
import os

_here = os.path.dirname(os.path.abspath(__file__))
BPF_SOURCE_FILE = os.path.join(_here, "bpf", "dns_cgroup.bpf.c")

ENV_CGROUP_PATH = "CGROUP_PATH"
ENV_METRICS_PORT = "METRICS_PORT"
ENV_DEVMODE = "DEVMODE"
ENV_CLUSTER_DNS_SUFFIXES = "CLUSTER_DNS_SUFFIXES"
ENV_POD_RESOLVER_CACHE_TTL = "POD_RESOLVER_CACHE_TTL"
ENV_TXT_WHITELIST_FILE = "TXT_WHITELIST_FILE"

# BUG-26: TTL кэша PodResolver (секунды). После истечения запись считается устаревшей и переразрешается.
POD_RESOLVER_CACHE_TTL_SEC = int(os.environ.get(ENV_POD_RESOLVER_CACHE_TTL, "300").strip() or "300")

# K8s/cluster-internal DNS — не детектируем (ISSUE K8S). Можно переопределить через env (через запятую).
_default_cluster_suffixes = ".svc.cluster.local,.cluster.local,.pod.cluster.local"
CLUSTER_DNS_SUFFIXES = [
    s.strip() for s in os.environ.get(ENV_CLUSTER_DNS_SUFFIXES, _default_cluster_suffixes).split(",")
    if s.strip()
]
if not CLUSTER_DNS_SUFFIXES:
    CLUSTER_DNS_SUFFIXES = [".svc.cluster.local", ".cluster.local", ".pod.cluster.local"]

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
