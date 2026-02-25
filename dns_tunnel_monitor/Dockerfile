# Build from repo root: docker build -f dns_tunnel_monitor/Dockerfile -t dns-tunnel-monitor:v1 .
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-generic \
    procps \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONPATH=/usr/lib/python3/dist-packages:/app

WORKDIR /app
COPY dns_tunnel_monitor ./dns_tunnel_monitor

ENV CGROUP_PATH=/host-cgroup
ENV METRICS_PORT=9999

ENTRYPOINT ["python3", "-m", "dns_tunnel_monitor"]
