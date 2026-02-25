# dns-tunnel-monitor Helm Chart

DaemonSet: DNS tunnel detector (cgroup_skb) on every node. Metrics on port 9999 for Prometheus/Grafana.

## Install

```bash
# From repo root
helm install dns-tunnel-monitor ./dns_tunnel_monitor/helm -n default
```

## Values

| Key | Description | Default |
|-----|-------------|---------|
| image.repository | Image name | dns-tunnel-monitor |
| image.tag | Image tag | v1 |
| env.CGROUP_PATH | Host cgroup mount path in container | /host-cgroup |
| env.METRICS_PORT | HTTP port for /metrics | 9999 |
| prometheus.enabled | Add Prometheus scrape annotations | true |

## Build image

From repo root:

```bash
docker build -f dns_tunnel_monitor/Dockerfile -t dns-tunnel-monitor:v1 .
```

For K3s without registry: `docker save`, copy to node, `k3s ctr images import`.
