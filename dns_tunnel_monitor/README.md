# Karauley (DNS Tunnel Monitor, cgroup_skb)

![Karauley logo](../docs/logo.png)

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](#requirements)
[![Linux](https://img.shields.io/badge/OS-Linux-FCC624?logo=linux&logoColor=black)](#requirements)
[![eBPF](https://img.shields.io/badge/eBPF-cgroup__skb-0A0A0A)](#architecture)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Helm%20Chart-326CE5?logo=kubernetes&logoColor=white)](#quick-start)
[![Prometheus](https://img.shields.io/badge/metrics-Prometheus-E6522C?logo=prometheus&logoColor=white)](#metrics)

Lightweight eBPF-based DNS monitor for Kubernetes. It captures DNS traffic at the cgroup layer, flags suspicious behavior (C2, exfiltration, tunneling), and exports metrics for Prometheus/Grafana.

The project is designed for quick Helm-based deployment and practical production troubleshooting.

## Key Features

- DNS interception without `tc`/`kprobe`, using `cgroup_skb`.
- Traffic source context: `client_pod` (`namespace/podname` when Kubernetes API resolution is available) and `process` (best-effort).
- Heuristic detection:
  - C2 beaconing (regular intervals),
  - suspicious TXT requests,
  - exfiltration indicators (entropy, long subdomains, subdomain churn),
  - IP-over-DNS indicators (high request rate, NULL records, many answers).
- Built-in endpoints: `/metrics`, `/healthz`, `/ready`.
- DaemonSet deployment model (one pod per node).

## Quick Start

### 1) Local run (Linux host)

```bash
cd /path/to/prototype_improved
sudo CGROUP_PATH=/sys/fs/cgroup python3 -m dns_tunnel_monitor
```

Sanity check:
- generate DNS traffic (`nslookup google.com`);
- open `http://localhost:9999/metrics`.

### 2) Kubernetes run (recommended)

Build image from the `prototype_improved` root:

```bash
docker build -f dns_tunnel_monitor/Dockerfile -t dns-tunnel-monitor:v1 .
```

Make sure the image is available to your cluster (registry push or local runtime import), then:

```bash
helm install dns-tunnel-monitor ./dns_tunnel_monitor/helm -n default
```

Chart configuration: `dns_tunnel_monitor/helm/values.yaml`.

## Architecture

1. `bpf/dns_cgroup.bpf.c`
   - attaches to cgroup egress/ingress;
   - filters UDP:53;
   - sends `cgroup_id`, direction, IP version, and DNS payload sample to ring buffer.
2. `loader.py`
   - compiles and attaches BPF programs;
   - reads ring buffer events;
   - parses DNS fields (`domain`, `dns_type`, `flags`, `answers`);
   - resolves `cgroup_id` to `client_pod` and `process`.
3. `event_handler.py`
   - updates runtime stats and Prometheus metrics;
   - runs detectors and prints event/suspicion logs.
4. `detectors/`
   - `c2.py`, `exfil.py`, `ip_over_dns.py`, plus aggregator `tunnel.py`.
5. `metrics.py`
   - serves metrics and probe endpoints.

## Requirements

- Linux with cgroup v2.
- Privileges required to load/attach eBPF (in Kubernetes typically `privileged: true`).
- BCC (`python3-bpfcc`, `bpfcc-tools`) and compatible kernel.
- Python 3.11+ (container runtime baseline; local environment may vary).

## Required Privileges

This monitor needs elevated privileges because it loads and attaches eBPF programs to cgroups.

- **Local host run**
  - use `sudo` (or equivalent capabilities),
  - access to cgroup v2 filesystem (`CGROUP_PATH`),
  - kernel support for BPF and cgroup hooks.
- **Kubernetes run**
  - DaemonSet runs as `privileged: true`,
  - host cgroup mount (`/sys/fs/cgroup` -> `/host-cgroup`),
  - host networking is enabled in chart defaults (`hostNetwork: true`),
  - RBAC is required only for resolving `cgroup_id` to `namespace/podname` (`list/get pods`).

Without these privileges, loading BPF or resolving pod metadata may fail.

## Security Considerations

Because this component is privileged and node-wide, treat it as a sensitive workload.

- **High trust requirement**: compromise of the monitor container may impact the node.
- **Node visibility**: it can observe DNS traffic context for workloads on the node.
- **Potential sensitive data in logs**: queried domains can contain internal naming information.
- **Image supply chain risk**: dependencies include BCC/kernel tooling.

Recommended hardening steps:

- Use a dedicated namespace and restrict who can deploy/upgrade the chart.
- Pin image tags/digests and use image scanning/signing in CI.
- Keep RBAC minimal (`list/get pods` only if pod-name resolution is needed).
- Restrict egress from the monitor pod to only required endpoints.
- Keep debug flags off in production (`DEBUG_POD_RESOLVER`, `DEBUG_UNPARSEABLE`).
- Ship logs/metrics to controlled backends with retention and access controls.

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `CGROUP_PATH` | cgroup path to attach to | `/sys/fs/cgroup` |
| `METRICS_PORT` | HTTP port for `/metrics`, `/healthz`, `/ready` | `9999` |
| `TXT_WHITELIST_FILE` | Path to TXT whitelist file | not set |
| `POD_RESOLVER_CACHE_TTL` | cgroup->pod resolver cache TTL (sec) | `300` |
| `DEBUG_POD_RESOLVER` | verbose logs for pod resolution failures | not set |
| `DEBUG_UNPARSEABLE` | logs events with unparseable DNS payload | not set |

## Metrics

Main metric series:

- `dns_queries_total{protocol}`
- `dns_responses_total{protocol}`
- `dns_suspicious_total{threat_type}`
- `dns_events_by_pod{client_pod,direction}`
- `dns_events_by_process{process,client_pod,direction}`
- `dns_domains_unique`

`process` is best-effort (read from `cgroup.procs`/`/proc/<pid>/comm`) and is not guaranteed to be the exact packet-originating process.

## Screenshots

This section is prepared for visual project assets.

| Asset | Path |
|---|---|
| Project logo | `../docs/logo.png` |
| Architecture diagram | `docs/images/architecture.png` |
| Grafana dashboard | `docs/images/grafana-dashboard.png` |
| Prometheus metrics view | `docs/images/prometheus-metrics.png` |

After adding files, images can be rendered in the README like this:

```md
![Architecture](docs/images/architecture.png)
![Grafana dashboard](docs/images/grafana-dashboard.png)
![Prometheus metrics](docs/images/prometheus-metrics.png)
```

## TXT Whitelist (No Image Rebuild)

You can extend legitimate TXT patterns via an external UTF-8 file with sections:
- `[domains]` - suffixes,
- `[prefixes]` - prefixes,
- `[roots]` - exact domains.

Example file: `dns_tunnel_monitor/helm/txt_whitelist.example.txt`.

In Helm, you can either:
- enable built-in ConfigMap via `txtWhitelist.enabled: true` + `txtWhitelist.content`;
- or mount your own ConfigMap via `txtWhitelist.configMapName`.

## Current Limitations

- BPF filter currently supports UDP and IPv4 only (no TCP DNS, no IPv6 path in monitor logic).
- Detection is heuristic by design (false positives/false negatives are possible).
- Analysis uses a DNS payload sample (up to 256 bytes).
- One monitor instance attaches to one `CGROUP_PATH`.
- `namespace/podname` resolution depends on cgroup format and Kubernetes API access (RBAC, token, network).

## Troubleshooting

### `client_pod=cgroup_id=...` in metrics

Check:
- `rbac.enabled: true` in `values.yaml`;
- ServiceAccount can `list/get pods`;
- cgroup path on the node follows expected `kubepods` layout.

For resolver diagnostics:

```yaml
env:
  DEBUG_POD_RESOLVER: "1"
```

### Metrics are missing in Grafana

- ensure Prometheus is scraping `/metrics` on port `9999`;
- if using Prometheus Operator, verify `prometheus.serviceMonitor.labels.release` matches your Prometheus release label;
- run `dns_queries_total` or `{__name__=~"dns_.*"}` directly in Prometheus.

## Repository Layout

| Path | Purpose |
|---|---|
| `dns_tunnel_monitor/main.py` | application entry point |
| `dns_tunnel_monitor/loader.py` | BPF load/attach + event intake |
| `dns_tunnel_monitor/event_handler.py` | event processing, logging, metrics |
| `dns_tunnel_monitor/pod_resolver.py` | cgroup -> pod/process resolution |
| `dns_tunnel_monitor/detectors/` | C2/exfiltration/tunneling detectors |
| `dns_tunnel_monitor/bpf/dns_cgroup.bpf.c` | eBPF program |
| `dns_tunnel_monitor/helm/` | Kubernetes Helm chart |
| `dns_tunnel_monitor/tests/` | heuristic tests |

## Roadmap

- IPv6 and TCP DNS support.
- Better process attribution accuracy.
- Detector tuning and coverage expansion.
- `libbpf`/CO-RE migration for improved portability.
# Karauley (DNS Tunnel Monitor, cgroup_skb)

![Karauley logo](../docs/logo.png)

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](#requirements)
[![Linux](https://img.shields.io/badge/OS-Linux-FCC624?logo=linux&logoColor=black)](#requirements)
[![eBPF](https://img.shields.io/badge/eBPF-cgroup__skb-0A0A0A)](#architecture)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Helm%20Chart-326CE5?logo=kubernetes&logoColor=white)](#quick-start)
[![Prometheus](https://img.shields.io/badge/metrics-Prometheus-E6522C?logo=prometheus&logoColor=white)](#metrics)

Lightweight eBPF-based DNS monitor for Kubernetes. It captures DNS traffic at the cgroup layer, flags suspicious behavior (C2, exfiltration, tunneling), and exports metrics for Prometheus/Grafana.

The project is designed for quick Helm-based deployment and practical production troubleshooting.

## Key Features

- DNS interception without `tc`/`kprobe`, using `cgroup_skb`.
- Traffic source context: `client_pod` (`namespace/podname` when Kubernetes API resolution is available) and `process` (best-effort).
- Heuristic detection:
  - C2 beaconing (regular intervals),
  - suspicious TXT requests,
  - exfiltration indicators (entropy, long subdomains, subdomain churn),
  - IP-over-DNS indicators (high request rate, NULL records, many answers).
- Built-in endpoints: `/metrics`, `/healthz`, `/ready`.
- DaemonSet deployment model (one pod per node).

## Quick Start

### 1) Local run (Linux host)

```bash
cd /path/to/prototype_improved
sudo CGROUP_PATH=/sys/fs/cgroup python3 -m dns_tunnel_monitor
```

Sanity check:
- generate DNS traffic (`nslookup google.com`);
- open `http://localhost:9999/metrics`.

### 2) Kubernetes run (recommended)

Build image from the `prototype_improved` root:

```bash
docker build -f dns_tunnel_monitor/Dockerfile -t dns-tunnel-monitor:v1 .
```

Make sure the image is available to your cluster (registry push or local runtime import), then:

```bash
helm install dns-tunnel-monitor ./dns_tunnel_monitor/helm -n default
```

Chart configuration: `dns_tunnel_monitor/helm/values.yaml`.

## Architecture

1. `bpf/dns_cgroup.bpf.c`
   - attaches to cgroup egress/ingress;
   - filters UDP:53;
   - sends `cgroup_id`, direction, IP version, and DNS payload sample to ring buffer.
2. `loader.py`
   - compiles and attaches BPF programs;
   - reads ring buffer events;
   - parses DNS fields (`domain`, `dns_type`, `flags`, `answers`);
   - resolves `cgroup_id` to `client_pod` and `process`.
3. `event_handler.py`
   - updates runtime stats and Prometheus metrics;
   - runs detectors and prints event/suspicion logs.
4. `detectors/`
   - `c2.py`, `exfil.py`, `ip_over_dns.py`, plus aggregator `tunnel.py`.
5. `metrics.py`
   - serves metrics and probe endpoints.

## Requirements

- Linux with cgroup v2.
- Privileges required to load/attach eBPF (in Kubernetes typically `privileged: true`).
- BCC (`python3-bpfcc`, `bpfcc-tools`) and compatible kernel.
- Python 3.11+ (container runtime baseline; local environment may vary).

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `CGROUP_PATH` | cgroup path to attach to | `/sys/fs/cgroup` |
| `METRICS_PORT` | HTTP port for `/metrics`, `/healthz`, `/ready` | `9999` |
| `TXT_WHITELIST_FILE` | Path to TXT whitelist file | not set |
| `POD_RESOLVER_CACHE_TTL` | cgroup->pod resolver cache TTL (sec) | `300` |
| `DEBUG_POD_RESOLVER` | verbose logs for pod resolution failures | not set |
| `DEBUG_UNPARSEABLE` | logs events with unparseable DNS payload | not set |

## Metrics

Main metric series:

- `dns_queries_total{protocol}`
- `dns_responses_total{protocol}`
- `dns_suspicious_total{threat_type}`
- `dns_events_by_pod{client_pod,direction}`
- `dns_events_by_process{process,client_pod,direction}`
- `dns_domains_unique`

`process` is best-effort (read from `cgroup.procs`/`/proc/<pid>/comm`) and is not guaranteed to be the exact packet-originating process.

## TXT Whitelist (No Image Rebuild)

You can extend legitimate TXT patterns via an external UTF-8 file with sections:
- `[domains]` - suffixes,
- `[prefixes]` - prefixes,
- `[roots]` - exact domains.

Example file: `dns_tunnel_monitor/helm/txt_whitelist.example.txt`.

In Helm, you can either:
- enable built-in ConfigMap via `txtWhitelist.enabled: true` + `txtWhitelist.content`;
- or mount your own ConfigMap via `txtWhitelist.configMapName`.

## Current Limitations

- BPF filter currently supports UDP and IPv4 only (no TCP DNS, no IPv6 path in monitor logic).
- Detection is heuristic by design (false positives/false negatives are possible).
- Analysis uses a DNS payload sample (up to 256 bytes).
- One monitor instance attaches to one `CGROUP_PATH`.
- `namespace/podname` resolution depends on cgroup format and Kubernetes API access (RBAC, token, network).

## Troubleshooting

### `client_pod=cgroup_id=...` in metrics

Check:
- `rbac.enabled: true` in `values.yaml`;
- ServiceAccount can `list/get pods`;
- cgroup path on the node follows expected `kubepods` layout.

For resolver diagnostics:

```yaml
env:
  DEBUG_POD_RESOLVER: "1"
```

### Metrics are missing in Grafana

- ensure Prometheus is scraping `/metrics` on port `9999`;
- if using Prometheus Operator, verify `prometheus.serviceMonitor.labels.release` matches your Prometheus release label;
- run `dns_queries_total` or `{__name__=~"dns_.*"}` directly in Prometheus.

## Repository Layout

| Path | Purpose |
|---|---|
| `dns_tunnel_monitor/main.py` | application entry point |
| `dns_tunnel_monitor/loader.py` | BPF load/attach + event intake |
| `dns_tunnel_monitor/event_handler.py` | event processing, logging, metrics |
| `dns_tunnel_monitor/pod_resolver.py` | cgroup -> pod/process resolution |
| `dns_tunnel_monitor/detectors/` | C2/exfiltration/tunneling detectors |
| `dns_tunnel_monitor/bpf/dns_cgroup.bpf.c` | eBPF program |
| `dns_tunnel_monitor/helm/` | Kubernetes Helm chart |
| `dns_tunnel_monitor/tests/` | heuristic tests |

## Roadmap

- IPv6 and TCP DNS support.
- Better process attribution accuracy.
- Detector tuning and coverage expansion.
- `libbpf`/CO-RE migration for improved portability.
- Adding Ml