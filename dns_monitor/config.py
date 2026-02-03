"""Constants and env-based config. BPF path, colors, env keys."""
import os

# BPF source: next to package root (parent of dns_monitor/)
_here = os.path.dirname(os.path.abspath(__file__))
_pkg_root = os.path.dirname(_here)
BPF_SOURCE_FILE = os.path.join(_pkg_root, "dns_ebpf_improved.bpf.c")

# Terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Env keys (for reference / central place)
ENV_HOST_PROC = "HOST_PROC"
ENV_METRICS_PORT = "METRICS_PORT"
ENV_DEVMODE = "DEVMODE"
