"""Config: CGROUP_PATH, METRICS_PORT, BPF path, colors."""
import os
import re

_here = os.path.dirname(os.path.abspath(__file__))
BPF_SOURCE_FILE = os.path.join(_here, "bpf", "dns_cgroup.bpf.c")

ENV_CGROUP_PATH = "CGROUP_PATH"
ENV_METRICS_PORT = "METRICS_PORT"
ENV_DEVMODE = "DEVMODE"
ENV_CLUSTER_DNS_SUFFIXES = "CLUSTER_DNS_SUFFIXES"
ENV_POD_RESOLVER_CACHE_TTL = "POD_RESOLVER_CACHE_TTL"
ENV_TXT_WHITELIST_FILE = "TXT_WHITELIST_FILE"
ENV_DEBUG_UNPARSEABLE = "DEBUG_UNPARSEABLE"

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

# Строгие паттерны для легитимного K8s DNS (убирает FN из ndots expansion).
# Только <service>.<namespace>.svc.cluster.local, не exfil.attack.test.svc.cluster.local.
_K8S_SVC_RE = re.compile(r"^[a-z0-9\-]+\.[a-z0-9\-]+\.svc\.cluster\.local$")
_K8S_POD_RE = re.compile(r"^[a-z0-9\-]+\.[a-z0-9\-]+\.pod\.cluster\.local$")
_K8S_CLUSTER_RE = re.compile(r"^[a-z0-9\-]+\.cluster\.local$")


def is_legitimate_cluster_dns(domain):
    """
    True только для легитимных K8s service/pod имён, не для атакующих доменов
    с приписанным суффиксом (ndots expansion: exfil.attack.test.svc.cluster.local).
    """
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.lower().strip()
    if _K8S_SVC_RE.match(domain):
        return True
    if _K8S_POD_RE.match(domain):
        return True
    if _K8S_CLUSTER_RE.match(domain):
        return True
    return False

# Диагностика <unparseable>: при 1 в stderr пишется ip_version и hex первых 12 байт payload.
DEBUG_UNPARSEABLE = os.environ.get(ENV_DEBUG_UNPARSEABLE, "").strip().lower() in ("1", "true", "yes")

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
