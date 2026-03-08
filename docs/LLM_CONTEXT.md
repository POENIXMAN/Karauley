# DNS Tunnel Monitor — Полный контекст проекта (v3)

Этот документ — self-contained контекст для LLM. Обновлён 2026-03 после Phase C (direct access BPF), фикса whitelist и analyze.py --gt-by-domain.

---

## 1. Цель проекта

Магистерская ВКР: **CNI-agnostic модуль** для обнаружения DNS-туннелирования в Kubernetes.

- **eBPF cgroup_skb** — перехват DNS на уровне ядра без зависимости от CNI
- **cgroup_id → pod attribution** — определяет исходный pod
- **Только UDP/IPv4 DNS** (порт 53), payload 64 байта (~45 символов домена)
- DaemonSet с Prometheus-метриками

**Готовность: ~85%.** Pipeline работает. Валидация Phase C (direct access BPF): **Recall 0.856, F1 0.613** (threshold=2); Real FPR ≈ 0.017%. Добавлены: строгий whitelist cluster DNS (убирает ~400 FN из ndots), analyze.py `--gt-by-domain` (Precision → ~0.99 при разметке по домену). Подробности: VALIDATION_FINDINGS.md, HONEST_ASSESSMENT.md.

---

## 2. Архитектура

```
Pod DNS traffic (UDP/53)
  → BPF cgroup_skb (kernel, 64B payload capture)
  → perf buffer
  → Python: parse DNS + resolve pod (cgroup_id → ns/name)
  → 3 detectors (C2, Exfil, IP-over-DNS)
  → scoring aggregator (weighted sum, threshold=2)
  → Prometheus metrics (:9999/metrics)
  → Grafana
```

---

## 3. Файловая структура

```
dns_tunnel_monitor/
├── bpf/dns_cgroup.bpf.c     # BPF: cgroup_skb, direct access (data/data_end), 64B+ip_version
├── event_struct.py            # ctypes struct (81 bytes: +ip_version)
├── loader.py                  # load BPF, attach, perf callback; unparseable → payload_sample_hex
├── dns_parsing.py             # parse_dns_name, parse_dns_type, calculate_entropy
├── config.py                  # env, is_legitimate_cluster_dns() (strict regex), TTL, colors
├── pod_resolver.py            # cgroup_id → ns/pod via BPF fd / cgroup walk / K8s API
├── event_handler.py           # stats + detectors + metrics + JSON stderr; DEBUG_UNPARSEABLE
├── detectors/
│   ├── tunnel.py              # scoring + strict cluster DNS whitelist (not endswith)
│   ├── c2.py                  # beacon CV + TXT heuristic (LRU 10K keys)
│   ├── exfil.py               # entropy/digit/hex/base64/subdomains (capped 50)
│   └── ip_over_dns.py         # _key_data OrderedDict LRU, per-key rate + NULL + answers
├── metrics.py                 # Flask + Prometheus
├── main.py                    # entry point, signal handling
├── helm/                      # Helm chart (DaemonSet, RBAC, ServiceMonitor)
├── Dockerfile                 # python:3.11-slim + bpfcc-tools
└── requirements.txt          # prometheus_client, flask

k8s/tests/
├── analyze.py                 # confusion matrix; --gt-by-domain, --attack-domain, --threshold
├── collect.sh                 # сбор JSONL из DaemonSet
docs/
├── VALIDATION_FINDINGS.md     # Phase A/B/C результаты, интерпретация FP/FN
├── UNPARSEABLE_DIAGNOSTICS.md # ip_version, payload_sample_hex, DEBUG_UNPARSEABLE=1
```

---

## 4. Исходный код — ключевые модули

### 4.1 BPF — `bpf/dns_cgroup.bpf.c`

- **Доступ к пакету:** прямой (ctx->data / data_end), одна проверка `data + 92 <= data_end`. Без bpf_skb_load_bytes — меньше unparseable (Phase C: 399 вместо ~1719).
- **Структура события:** direction, cgroup_id, payload[64], **ip_version** (верхние 4 бита первого байта пакета — для диагностики unparseable).
- **Фильтр:** UDP, порт 53; payload с offset 28 (IPv4). IPv6 не поддерживается → оставшиеся unparseable.

Ограничения: UDP only, 64B payload, IPv4 only (offset 28). IPv6 даёт мусор с 28 → `<unparseable>`. Диагностика: DEBUG_UNPARSEABLE=1 и поля ip_version, payload_sample_hex в событии (см. UNPARSEABLE_DIAGNOSTICS.md).

### 4.2 Loader — `loader.py`

```python
# In perf callback: ev.ip_version, ev.payload → domain, dns_id, dns_flags, ...
# If domain == "<unparseable>": normalized["payload_sample_hex"] = payload[:12].hex()
# Normalized dict: domain, direction, protocol, client_pod, process, cgroup_id,
#   dns_id, dns_flags, dns_answers, dns_type, timestamp_ns, ip_version
```

### 4.3 Detectors

#### C2 — `detectors/c2.py`

```python
class C2Detector:
    query_history = OrderedDict()  # LRU, max 10K keys, max 20 timestamps per key
    # Beacon: CV of query intervals < 0.15 and avg > 5s → C2_BEACON (weight 3)
    # TXT: type 16 + not in 27-domain whitelist + not ACME → C2_TXT_REQUEST (weight 1)
```

#### Exfiltration — `detectors/exfil.py`

```python
class ExfiltrationDetector:
    subdomain_counts = defaultdict(list)  # max 50 subdomains per base_domain
    # Shannon entropy > 4.0 → HIGH_ENTROPY (weight 2)
    # len(domain) > 60 → LONG_DOMAIN (weight 1) — NOT WORKING (64B payload limit)
    # digit_ratio > 0.3 → HIGH_DIGIT_RATIO (weight 1)
    # first_subdomain > 20 chars:
    #   hex match first → HEX_SUBDOMAIN (weight 2)
    #   else base64 match → BASE64_SUBDOMAIN (weight 2)
    # unique subdomains > 20 → MANY_SUBDOMAINS (weight 2)
```

#### IP-over-DNS — `detectors/ip_over_dns.py`

```python
class IPOverDNSDetector:
    _key_data = OrderedDict()  # key -> (request_count, first_seen_ns), LRU 10K keys
    # Per-key 10s window, rate > RATE_THRESHOLD → HIGH_RATE (weight 3)
    # dns_type == 10 → NULL_RECORD (weight 2), dns_answers > 15 → MANY_ANSWERS (weight 2)
```

#### Aggregator — `detectors/tunnel.py`

```python
# 1. Skip only legitimate K8s DNS: config.is_legitimate_cluster_dns(domain)
#    Strict regex: ^<svc>.<ns>.svc.cluster.local$ (не exfil.attack.test.svc...)
# 2. Run all 3 detectors
# 3. Score = sum of weights; suspicious if score >= 2
```

### 4.4 Pod Resolver — `pod_resolver.py`

3-level resolution: BPF fd syscall → cgroup fs walk (50K dirs) → K8s API (list pods, limit=500).  
Cache: TTL 300s (configurable via `POD_RESOLVER_CACHE_TTL` env).

### 4.5 Metrics — `metrics.py`

Flask on :9999. Endpoints: `/healthz`, `/ready`, `/metrics`.  
Counters: dns_queries_total, dns_responses_total, dns_suspicious_total, dns_events_by_pod, dns_events_by_process.  
Gauge: dns_domains_unique.

### 4.6 Deployment

Helm chart: DaemonSet (privileged, hostNetwork, hostPID).  
Mounts: `/sys/fs/cgroup` → `/host-cgroup`, `/sys`, `/lib/modules`, `/usr/src`.  
RBAC: ServiceAccount + ClusterRole (list/get pods).  
ServiceMonitor for Prometheus Operator.

---

## 5. Нормализованное событие и JSON-лог

**Нормализованное событие (в callback):**
```python
{
    "domain": "example.com",        # или "<unparseable>"
    "direction": "query",           # по QR-биту DNS
    "protocol": "UDP",
    "client_pod": "default/nginx",
    "process": "nginx",
    "cgroup_id": 12345,
    "dns_id": 0x1234, "dns_flags": 0x0100,
    "dns_answers": 0, "dns_type": 1,
    "timestamp_ns": ...,
    "ip_version": 4,               # для диагностики unparseable
    "payload_sample_hex": "...",    # только при domain == "<unparseable>"
}
```

**Строка в stderr (JSON):** ts, domain, direction, dns_type, pod, process, suspicious, score, threat_type, reasons, ip_version; при unparseable — payload_sample_hex. Используется analyze.py и collect.sh.

---

## 8. Следующие шаги

1. **Сделано:** strict cluster DNS whitelist (is_legitimate_cluster_dns); analyze.py `--gt-by-domain` и `--attack-domain` для разметки по домену (Precision Phase C → ~0.99).
2. **Валидация:** Phase C с direct access — Recall 0.856, F1 0.613; Real FPR ≈ 0.017%. Повтор Phase B (iodine/dnscat2/exfil изолированно) после правок — по желанию.
3. **eBPF:** поддержка IPv6 (offset 48) — устранит ~399 оставшихся unparseable.
4. Сравнение с Tetragon/Falco/Zeek для ВКР.
5. (Опционально) ROC по threshold, повторные прогоны (mean ± std), ML scorer.

---

## 9. Анализ логов (k8s/tests/analyze.py)

- **По умолчанию:** ground truth по namespace пода (attack → attack, kube-system → legit). CoreDNS transit считается FP.
- **`--gt-by-domain`:** ground truth по домену: `*.attack.test` и варианты → attack. Убирает артефакт CoreDNS, Precision → ~0.99.
- **`--attack-domain SUFFIX`:** суффикс атакующего домена (default: attack.test).
- **`--threshold N`:** пересчёт метрик с порогом score >= N.

Пример: `python3 analyze.py results/phase_C.jsonl --gt-by-domain`

---

## 10. Технологический стек

| Компонент | Технология |
|-----------|------------|
| Kernel hook | eBPF cgroup_skb (BCC) |
| BPF language | C (BCC runtime compile) |
| Userspace | Python 3.11 |
| Metrics | prometheus_client + Flask |
| Deployment | Helm → DaemonSet (privileged) |
| Container | python:3.11-slim + bpfcc-tools |
| K8s | ServiceAccount RBAC, ServiceMonitor |
| Target | Kubernetes (any CNI), cgroup v2, UDP/IPv4 |
