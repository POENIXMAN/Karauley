"""Devmode: when enabled, log debug info to stderr. Set DEVMODE=1 or DEV_MODE=1."""
import os
import sys

# DEVMODE or legacy DEBUG_POD_RESOLUTION / DEV_MODE
devmode = (
    os.environ.get("DEVMODE", "").lower() in ("1", "true", "yes")
    or os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes")
    or os.environ.get("DEBUG_POD_RESOLUTION", "").lower() in ("1", "true", "yes")
)

# Per-category caps (optional)
_MAX_LOGS = 80
_EVENT_SAMPLE_MAX = 20
_counts = {}

def dev_log(category: str, message: str) -> None:
    """Log to stderr only when devmode is on. Category can be 'pod', 'event', 'bpf', 'metrics', etc."""
    if not devmode:
        return
    key = category
    _counts[key] = _counts.get(key, 0) + 1
    if category == "event" and _counts[key] > _EVENT_SAMPLE_MAX:
        return
    if _counts[key] > _MAX_LOGS:
        if _counts[key] == _MAX_LOGS + 1:
            print(f"[DEV] [{category}] (log capped)", file=sys.stderr, flush=True)
        return
    print(f"[DEV] [{category}] {message}", file=sys.stderr, flush=True)
