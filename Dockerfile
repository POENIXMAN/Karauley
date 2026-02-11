FROM python:3.11-slim AS base


LABEL maintainer="ВКР DNS Tunnel Detection"
LABEL description="eBPF-based DNS tunnel detector for Kubernetes"



FROM base AS builder



RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*



COPY requirements.txt .
RUN pip3 install --no-cache-dir --target=/opt/packages -r requirements.txt



FROM base AS runtime


RUN apt-get update && apt-get install -y --no-install-recommends \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-generic \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*



COPY --from=builder /opt/packages /opt/packages


RUN python3 -c "import sys; print('Python version:', sys.version); print('Python paths:', sys.path)" \
    && python3 -c "import bcc; print('BCC imported successfully from:', bcc.file)" \
    || (echo "BCC import failed, checking installation..." \
        && dpkg -L python3-bpfcc | grep -E "(bcc|\.py)" | head -5 \
        && find /usr -name "*bcc*" -type f 2>/dev/null | head -10)



ENV PYTHONPATH=/opt/packages:/usr/lib/python3/dist-packages

WORKDIR /app

COPY dns_ebpf_improved.bpf.c dns_ebpf_common.h dns_ebpf_udp.inc dns_ebpf_tcp.inc .
COPY dns_analyzer.py .
COPY dns_monitor ./dns_monitor

EXPOSE 9999

ENTRYPOINT ["python3", "dns_analyzer.py"]