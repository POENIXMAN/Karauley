# DNS monitor via cgroup_skb (working.py + dns_cgroup_working.bpf.c).
# Build from repo root: docker build -f cgroup_skb_test/Dockerfile -t dns-cgroup-monitor:latest .
# Or from this dir: docker build -f Dockerfile -t dns-cgroup-monitor:latest ..
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-generic \
    procps \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONPATH=/usr/lib/python3/dist-packages

WORKDIR /app
# Build from repo root:  docker build -f cgroup_skb_test/Dockerfile -t dns-cgroup-monitor:v1 .
# Build from this dir:  docker build -t dns-cgroup-monitor:v1 .  (copies local files)
COPY cgroup_skb_test/working.py cgroup_skb_test/dns_cgroup_working.bpf.c ./

ENV CGROUP_PATH=/host-cgroup

ENTRYPOINT ["python3", "working.py"]
