# Minimal image for CGROUP_SKB test in cluster.
# Same pattern as main Dockerfile: python:3.11-slim + apt BCC + PYTHONPATH so bcc is found.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-generic \
    procps \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONPATH=/usr/lib/python3/dist-packages

WORKDIR /app
COPY dns_cgroup_minimal.bpf.c .
COPY test_cgroup_skb.py .

ENV CGROUP_PATH=/host-cgroup

ENTRYPOINT ["python3", "test_cgroup_skb.py"]
