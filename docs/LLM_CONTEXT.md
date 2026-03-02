# DNS Tunnel Monitor — Полный контекст проекта (v2)

Этот документ — self-contained контекст для LLM. Обновлён 2026-03-01 после исправлений.

---

## 1. Цель проекта

Магистерская ВКР: **CNI-agnostic модуль** для обнаружения DNS-туннелирования в Kubernetes.

- **eBPF cgroup_skb** — перехват DNS на уровне ядра без зависимости от CNI
- **cgroup_id → pod attribution** — определяет исходный pod
- **Только UDP/IPv4 DNS** (порт 53), payload 64 байта (~45 символов домена)
- DaemonSet с Prometheus-метриками

**Готовность: ~75%.** Сквозной pipeline работает. 10 из 11 детекторных проверок работают. Следующий шаг — валидация TP/FP.

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
├── bpf/dns_cgroup.bpf.c     # BPF: cgroup_skb hooks, capture direction+cgroup_id+64B
├── event_struct.py            # ctypes struct (80 bytes)
├── loader.py                  # load BPF, attach, perf callback, normalize event
├── dns_parsing.py             # parse_dns_name, parse_dns_type, calculate_entropy
├── config.py                  # env vars, cluster DNS suffixes, cache TTL, colors
├── pod_resolver.py            # cgroup_id → ns/pod via BPF fd / cgroup walk / K8s API
├── event_handler.py           # stats + detectors + metrics + console log
├── detectors/
│   ├── tunnel.py              # scoring aggregator + cluster DNS whitelist
│   ├── c2.py                  # beacon CV + TXT heuristic (LRU 10K keys)
│   ├── exfil.py               # entropy/digit/hex/base64/subdomains (capped 50)
│   └── ip_over_dns.py         # per-key rate + NULL + answers
├── metrics.py                 # Flask + Prometheus counters/gauges
├── main.py                    # entry point, signal handling
├── helm/                      # Helm chart (DaemonSet, RBAC, ServiceMonitor)
├── Dockerfile                 # python:3.11-slim + bpfcc-tools
└── requirements.txt           # prometheus_client, flask
```

---

## 4. Исходный код — ключевые модули

### 4.1 BPF — `bpf/dns_cgroup.bpf.c`

```c
#define DNS_PORT 53
#define PAYLOAD_SAMPLE 64

struct event_t {
    uint8_t  direction;       // 1=egress, 2=ingress
    uint8_t  _pad[7];
    uint64_t cgroup_id;
    uint8_t  payload[PAYLOAD_SAMPLE];
};

static __always_inline int monitor_dns(struct __sk_buff *ctx, uint8_t dir) {
    // filter: UDP only, port 53
    // capture: direction + cgroup_id + first 64 bytes of DNS payload (offset 28 = IP(20)+UDP(8))
    // send via perf_submit
}
int egress_hook(struct __sk_buff *ctx)  { return monitor_dns(ctx, 1); }
int ingress_hook(struct __sk_buff *ctx) { return monitor_dns(ctx, 2); }
```

Ограничения: hardcoded IP header 20 bytes (no IP options), UDP only, 64B payload.

### 4.2 Loader — `loader.py`

```python
# In perf callback:
is_response = (dns_flags & 0x8000) != 0          # QR bit (BUG-03 fixed)
direction = "response" if is_response else "query"
# Normalizes into dict with: domain, direction, protocol, client_pod, process,
#   cgroup_id, dns_id, dns_flags, dns_answers, dns_type, timestamp_ns
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
    request_counts = defaultdict(int)   # per (cgroup_id, base_domain)
    first_seen_ns = {}                  # per-key window start
    # Per-key 10s window, rate > 50/sec → HIGH_RATE (weight 3)
    # dns_type == 10 → NULL_RECORD (weight 2)
    # dns_answers > 5 → MANY_ANSWERS (weight 2)
```

#### Aggregator — `detectors/tunnel.py`

```python
# 1. Skip cluster-internal DNS (.svc.cluster.local etc.) — configurable
# 2. Run all 3 detectors
# 3. Score = sum of weights for triggered reasons
# 4. Suspicious if score >= 2
# Single C2_TXT_REQUEST (weight 1) → NOT suspicious
# HIGH_ENTROPY alone (weight 2) → suspicious
# C2_BEACON alone (weight 3) → suspicious
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

## 5. Нормализованное событие

```python
{
    "domain": "example.com",        # parsed (max ~45 chars due to 64B)
    "direction": "query",           # by QR bit of DNS flags
    "protocol": "UDP",
    "client_pod": "default/nginx",  # resolved via cgroup_id
    "process": "nginx",             # from /proc/pid/comm
    "cgroup_id": 12345,
    "dns_id": 0x1234, "dns_flags": 0x0100,
    "dns_answers": 0, "dns_type": 1,
    "timestamp_ns": 1709312345000000000,
}
```

---

## 6. Баги — текущий статус

### Исправлено (11 fixes)

| ID | Описание |
|----|----------|
| BUG-03 | direction по QR-биту вместо egress/ingress |
| BUG-11 | query_history: OrderedDict LRU (10K keys) |
| BUG-14 | hex regex перед base64 (оба работают) |
| BUG-16 | subdomain_counts: list с cap 50 |
| BUG-18 | Per-key window вместо global tumbling |
| BUG-19 | Rate от per-key first_seen |
| BUG-26 | PodResolver: TTL cache (300s) |
| ISSUE-12 | TXT whitelist: 27 доменов + ACME |
| ISSUE-22 | Scoring (weighted sum, threshold=2) |
| K8S | Cluster DNS whitelist (configurable) |
| NEW-01 | ip_over_dns: _key_data OrderedDict LRU (10K keys) |

### Принятые ограничения

| ID | Описание |
|----|----------|
| BUG-02 | PAYLOAD_SAMPLE=64 (увеличение ломает парсинг) |
| BUG-17 | LONG_DOMAIN(60) не работает (следствие 64B) |
| BUG-01 | IP header 20B hardcoded (IP options не учитываются) |

### Открытые issues

| ID | Severity | Описание |
|----|----------|----------|
| BUG-10 | Medium | base_domain = last 2 labels (неверно для .co.uk) |
| BUG-15 | Medium | Энтропия по полному домену, не по поддомену |
| BUG-23 | Medium | stats["domains"] set растёт бесконечно |
| BUG-27 | Medium | K8s API limit=500, нет пагинации |
| BUG-30 | Medium | Prometheus label cardinality (process × pod × direction) |
| BUG-07 | Low | parse_dns_type: нет bounds check в while |
| BUG-20 | Low | NULL_RECORD/MANY_ANSWERS double fire (query+response) |
| BUG-32 | Low | Double print_stats при Ctrl+C |
| ISSUE-33 | Medium | Нет мониторинга потерь perf buffer |

---

## 7. Детекция — что работает при 64B payload

| Проверка | Вес | Работает? |
|----------|:---:|:---------:|
| C2_BEACON (CV интервалов) | 3 | Да |
| C2_TXT_REQUEST | 1 | Да |
| HIGH_ENTROPY | 2 | Да |
| HIGH_DIGIT_RATIO | 1 | Да |
| HEX_SUBDOMAIN | 2 | Да |
| BASE64_SUBDOMAIN | 2 | Да |
| MANY_SUBDOMAINS | 2 | Да |
| HIGH_RATE | 3 | Да |
| NULL_RECORD | 2 | Да |
| MANY_ANSWERS | 2 | Да |
| LONG_DOMAIN | 1 | **Нет** |

**10 из 11 работают. Scoring threshold = 2.**

---

## 8. Следующие шаги

1. **Валидация TP/FP** — тестовый стенд с iodine/dnscat2/dns2tcp, confusion matrix, Precision/Recall/F1 (основа экспериментальной части ВКР)
2. Сравнение с Tetragon/Falco/Zeek
3. (Опционально) ML scorer как отдельный Deployment

---

## 9. Технологический стек

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
