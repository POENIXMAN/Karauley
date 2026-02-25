"""Config: CGROUP_PATH, METRICS_PORT, BPF path, colors."""
import os

_here = os.path.dirname(os.path.abspath(__file__))
BPF_SOURCE_FILE = os.path.join(_here, "bpf", "dns_cgroup.bpf.c")

ENV_CGROUP_PATH = "CGROUP_PATH"
ENV_METRICS_PORT = "METRICS_PORT"
ENV_DEVMODE = "DEVMODE"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
