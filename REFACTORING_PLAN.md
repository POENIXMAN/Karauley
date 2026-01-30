# Refactoring plan: split dns_analyzer_improved.py into modules

## Goals

1. Split the single ~900-line file into logical modules for easier maintenance.
2. Introduce **devmode** (rename from `debugPodResolution`): when enabled, log useful debug info everywhere (pod resolution, event samples, BPF load steps, etc.).
3. Keep behavior unchanged: same entrypoint, same CLI, same metrics, same detection logic.
4. No breaking changes to Dockerfile, Helm, or tests after refactor (only path/import updates if we move the entrypoint).

---

## 1. Devmode / logging

- **Rename:** `DEBUG_POD_RESOLUTION` → **`DEVMODE`** (env: `DEVMODE=1` or `DEV_MODE=1`).
- **Helm:** `daemonset.debugPodResolution` → **`daemonset.devmode`** (values + template).
- **New module:** `devmode.py` (or `log.py`)
  - Reads `os.environ.get("DEVMODE", "").lower() in ("1", "true", "yes")` (and optionally `DEV_MODE`).
  - Exposes:
    - `devmode: bool`
    - `dev_log(category, message)` — prints to stderr only when devmode is on; `category` e.g. `"pod"`, `"event"`, `"bpf"`, `"metrics"`.
  - Optional: rate-limit or cap lines per category so logs don’t flood (e.g. first N per category, then "… (devmode log capped)").
- **Usage:** Replace all current `[POD_DEBUG]` and ad-hoc debug prints with `dev_log("pod", ...)`, `dev_log("event", ...)`, etc. Use dev_log in:
  - Pod resolution (cgroup path, exists, parsed pod_uid, event sample pid/comm/pod_str).
  - BPF loading (step 1/2/3, errors).
  - Event handler (optional: sample of first N events with pid/comm/pod).
  - Anywhere else we want debug visibility later.

---

## 2. Proposed file layout

All new Python files live under a package so imports stay clear. Two options:

**Option A – Flat package `dns_monitor/` (recommended)**

```
prototype_improved/
  dns_analyzer_improved.py   → becomes thin entrypoint: imports from dns_monitor, calls main()
  dns_monitor/
    __init__.py             → re-exports main, version, and what’s needed for tests
    config.py               → constants: BPF_SOURCE_FILE, colors (RED,GREEN,...), DEVMODE env
    devmode.py              → devmode flag + dev_log()
    event_struct.py         → DNSEvent (ctypes.Structure)
    pod_resolver.py         → PodResolver (uses config, devmode)
    dns_parsing.py          → parse_dns_name, parse_dns_type, get_dns_type_name, calculate_entropy
    detectors/
      __init__.py           → TunnelDetector, tunnel_detector singleton, re-export C2/Exfil/IPOverDNS
      c2.py                 → C2Detector
      exfil.py              → ExfiltrationDetector
      ip_over_dns.py        → IPOverDNSDetector
      tunnel.py             → TunnelDetector (orchestrator)
    metrics.py              → Flask app, Prometheus counters/gauges, start_http_server (optional Flask)
    loader.py               → load_bpf(): read file, BPF(text=...), open_perf_buffer; returns bpf instance
    event_handler.py        → stats dict, pod_resolver, tunnel_detector, handle_event(), print_stats()
    main.py                 → main(): banner, RLIMIT_MEMLOCK log, load_bpf(), start HTTP, signal, poll loop
  dns_ebpf_improved.bpf.c   → unchanged
  Dockerfile                → CMD/ENTRYPOINT: python -m dns_monitor or python dns_analyzer_improved.py (if entrypoint stays)
```

**Option B – Same structure but keep single-file entrypoint**

- Keep `dns_analyzer_improved.py` as the only script that gets run; it imports from `dns_monitor.*`. No new top-level `main.py`; `main()` stays in `dns_analyzer_improved.py` or moves to `dns_monitor.main` and the script does `from dns_monitor.main import main; main()`.

Recommendation: **Option A** with entrypoint script `dns_analyzer_improved.py` that does:

```python
from dns_monitor.main import main
if __name__ == "__main__":
    main()
```

So the executable file remains `dns_analyzer_improved.py` (Dockerfile and docs don’t need to change).

---

## 3. Module responsibilities and dependencies

| Module | Responsibility | Depends on |
|--------|----------------|------------|
| **config** | BPF path, colors, env names (e.g. HOST_PROC, METRICS_PORT) | — |
| **devmode** | DEVMODE flag, dev_log() | — |
| **event_struct** | DNSEvent ctypes layout | ctypes |
| **pod_resolver** | PodResolver, cgroup v1/v2 parsing, K8s API resolution | config, devmode, os, sys |
| **dns_parsing** | parse_dns_name, parse_dns_type, get_dns_type_name, calculate_entropy | math, re |
| **detectors/c2** | C2Detector | collections.defaultdict, dns_parsing (none?), re (none) |
| **detectors/exfil** | ExfiltrationDetector | defaultdict, re, dns_parsing.calculate_entropy |
| **detectors/ip_over_dns** | IPOverDNSDetector | defaultdict |
| **detectors/tunnel** | TunnelDetector | c2, exfil, ip_over_dns |
| **metrics** | Flask app, Prometheus metrics, start_http_server | config (port), optional Flask |
| **loader** | load_bpf() → bpf, open_perf_buffer | bcc, event_struct, config, devmode |
| **event_handler** | stats, handle_event(), print_stats() | event_struct, pod_resolver, dns_parsing, detectors, metrics, config, devmode |
| **main** | main(): RLIMIT_MEMLOCK, load_bpf, HTTP thread, signal, poll loop | loader, event_handler, metrics, config, devmode |

Circular imports: event_handler will need tunnel_detector and metrics; loader needs nothing from event_handler. So dependency order is: config, devmode → event_struct, dns_parsing → pod_resolver, detectors → metrics → loader, event_handler → main.

---

## 4. What moves where (concise)

- **config.py:** `BPF_SOURCE_FILE`, `RED`, `GREEN`, etc., any env keys we centralize.
- **devmode.py:** `DEVMODE`, `dev_log()`, and capped counters per category if we want.
- **event_struct.py:** `DNSEvent` only.
- **pod_resolver.py:** `PodResolver` + `_resolve_from_cgroup` (all cgroup parsing). Remove `DEBUG_POD_RESOLUTION` / `_debug_pod` from current file; use `dev_log("pod", ...)`.
- **dns_parsing.py:** `parse_dns_name`, `parse_dns_type`, `get_dns_type_name`, `calculate_entropy`.
- **detectors/c2.py:** `C2Detector` class.
- **detectors/exfil.py:** `ExfiltrationDetector` class.
- **detectors/ip_over_dns.py:** `IPOverDNSDetector` class.
- **detectors/tunnel.py:** `TunnelDetector` class.
- **detectors/__init__.py:** Instantiate and export `tunnel_detector`, and re-export detector classes if useful.
- **metrics.py:** All Prometheus counters/gauges, Flask app, `/healthz`, `/ready`, `/metrics`, `start_http_server`. Guard with `try/except ImportError` for Flask/prometheus_client as today.
- **loader.py:** Read BPF source from `config.BPF_SOURCE_FILE`, `BPF(text=...)`, then `bpf["events"].open_perf_buffer(handle_event)`. `handle_event` is passed in (from event_handler) to avoid circular import. So loader exports `load_bpf(handle_event_cb)`.
- **event_handler.py:** `stats`, `pod_resolver` instance, `tunnel_detector` (from detectors), `handle_event(cpu, data, size)`, `print_stats()`. Uses config (colors), devmode (dev_log), metrics (inc/set), dns_parsing, event_struct.
- **main.py:** `main()`: print banner, RLIMIT_MEMLOCK (dev_log if we want), call `load_bpf(handle_event)` from loader, start HTTP thread (metrics), register signal, run `bpf.perf_buffer_poll()` loop, then `print_stats()`. `signal_handler` can live here and call `print_stats` + `sys.exit(0)`.

---

## 5. Backward compatibility

- **Entrypoint:** Keep `python dns_analyzer_improved.py` (or `python -m dns_monitor` if we prefer). Dockerfile and Helm `command` stay the same if we keep `dns_analyzer_improved.py` as the runner.
- **Tests:** `test_improved_version.py` (or similar) should import from `dns_monitor` (e.g. `from dns_monitor.dns_parsing import parse_dns_name`) and/or run the same entrypoint. We’ll adjust paths/imports in tests after refactor.
- **Helm:** Replace `debugPodResolution` with `devmode` in values and daemonset template; set env `DEVMODE=1` when `devmode: true`.

---

## 6. Order of implementation (to avoid breakage)

1. Add **config.py** and **devmode.py** (no behavior change, only new modules).
2. Add **event_struct.py**; move `DNSEvent` from current file and import it in the current file. Run tests / manual run to confirm.
3. Add **dns_parsing.py**; move parsing + entropy; current file imports from it. Confirm.
4. Add **pod_resolver.py**; move PodResolver and cgroup logic; switch to dev_log. Current file imports pod_resolver. Confirm.
5. Add **detectors/** (c2, exfil, ip_over_dns, tunnel, __init__); current file imports tunnel_detector from detectors. Confirm.
6. Add **metrics.py**; move Flask + Prometheus; current file imports metrics (and FLASK_AVAILABLE, start_http_server, counters). Confirm.
7. Add **loader.py**; move BPF load logic; current file calls loader.load_bpf(handle_event). Confirm.
8. Add **event_handler.py**; move stats, handle_event, print_stats; current file imports handle_event and print_stats from event_handler. Confirm.
9. Add **main.py**; move main() and signal_handler; current file becomes 5-line entrypoint. Confirm.
10. Rename **debugPodResolution → devmode** in Helm and in devmode.py (already using DEVMODE).
11. Final pass: add **dev_log()** in more places (BPF steps, event sample, etc.) and cap log volume if needed.
12. Run full test suite and a quick end-to-end (container + Helm) to ensure nothing is broken.

---

## 7. Summary for your approval

- **Devmode:** One place (`devmode.py`), env `DEVMODE=1`, `dev_log(category, msg)` used everywhere we want debug; Helm `daemonset.devmode`.
- **Split:** config, devmode, event_struct, pod_resolver, dns_parsing, detectors (c2, exfil, ip_over_dns, tunnel), metrics, loader, event_handler, main.
- **Entrypoint:** Keep `dns_analyzer_improved.py` as the script that calls `main()` from `dns_monitor.main`.
- **No behavior change** except logging controlled by devmode and renaming debugPodResolution → devmode.

If you approve this plan, next step is implementing in the order above and keeping the single file working after each step until the final cutover.
