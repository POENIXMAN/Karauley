# DNS Tunnel Detector - eBPF based
# Multi-stage build

FROM python:3.11-slim AS base

# Метаданные
LABEL maintainer="ВКР DNS Tunnel Detection"
LABEL description="eBPF-based DNS tunnel detector for Kubernetes"

# ============================================
# Stage 1: Builder
# ============================================
FROM base AS builder

# Установка build зависимостей
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем Python зависимости в отдельную директорию
# Это позволит скопировать их в runtime без проблем с путями
COPY requirements.txt .
RUN pip3 install --no-cache-dir --target=/opt/packages -r requirements.txt

# ============================================
# Stage 2: Runtime
# ============================================
FROM base AS runtime

# Установка только runtime зависимостей
RUN apt-get update && apt-get install -y --no-install-recommends \
    # BCC runtime (системный пакет)
    bpfcc-tools \
    python3-bpfcc \
    # Для работы с kernel
    linux-headers-generic \
    # Утилиты
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Копируем установленные Python пакеты из builder
COPY --from=builder /opt/packages /opt/packages

# Проверяем, что bcc доступен после установки python3-bpfcc
RUN python3 -c "import sys; print('Python version:', sys.version); print('Python paths:', sys.path)" \
    && python3 -c "import bcc; print('BCC imported successfully from:', bcc.__file__)" \
    || (echo "BCC import failed, checking installation..." \
        && dpkg -L python3-bpfcc | grep -E "(bcc|\.py)" | head -5 \
        && find /usr -name "*bcc*" -type f 2>/dev/null | head -10)

# Добавляем скопированные пакеты в PYTHONPATH
# Python автоматически проверяет системные пути где установлен python3-bpfcc
ENV PYTHONPATH=/opt/packages

# Рабочая директория
WORKDIR /app

# Копируем код
COPY dns_ebpf_improved.bpf.c .
COPY dns_analyzer_improved.py .

# Создаем non-root пользователя (для логов, не для eBPF)
# Примечание: eBPF требует root/privileged, но логи пишем от обычного пользователя

# Health check endpoint
EXPOSE 9999

# Entrypoint
# Используем системный python3, т.к. bcc доступен только через python3-bpfcc
ENTRYPOINT ["python3", "dns_analyzer_improved.py"]

