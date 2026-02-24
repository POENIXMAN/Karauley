# Minimal image for CGROUP_SKB test in cluster
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-generic \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY dns_cgroup_minimal.bpf.c .
COPY test_cgroup_skb.py .

# CGROUP_PATH will be set by deployment (mount host cgroup here)
ENV CGROUP_PATH=/host-cgroup

ENTRYPOINT ["python3", "test_cgroup_skb.py"]
