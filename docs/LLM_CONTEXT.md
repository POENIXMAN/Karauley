# DNS Tunnel Monitor — контекст проекта

Источник истины: код в `dns_tunnel_monitor/` и `k8s/tests/`. Обновлено после Phase C (2026-03).

---

## 1. Цель

Магистерская ВКР: **CNI-agnostic модуль** обнаружения DNS-туннелирования в Kubernetes.

- eBPF **cgroup_skb** — перехват DNS в ядре без зависимости от CNI
- **cgroup_id → pod** — атрибуция до пода (K8s API или cgroup fs)
- Только **UDP/IPv4** DNS (порт 53), payload до 128 байт (в парсере используется ~64 байта для домена)
- DaemonSet, метрики Prometheus на порту METRICS_PORT (по умолчанию 9999)

---

## 2. Архитектура (по коду)

```
Pod DNS (UDP/53) → BPF cgroup_skb → ring buffer
  → loader: parse payload → domain, dns_id, flags, answers, type
  → pod_resolver: cgroup_id → (client_pod, process)
  → event_handler: stats, tunnel_detector.analyze(), JSON в stderr, метрики
  → detectors: C2 (beacon, TXT), Exfil (entropy, subdomains, hex/base64), IP-over-DNS (rate, NULL, many answers)
  → weighted score, threshold=2 → suspicious/clean
```

---

## 3. Файловая структура (код)

```
dns_tunnel_monitor/
  bpf/dns_cgroup.bpf.c   # BPF: egress/ingress hook, event_t (direction, cgroup_id, payload[128], ip_version)
  event_struct.py        # CgroupDNSEvent (ctypes): layout должен совпадать с struct event_t в bpf/dns_cgroup.bpf.c; PAYLOAD_SAMPLE=128
  loader.py              # load_bpf(), _parse_payload(), ringbuf_cb → event_callback(normalized)
  dns_parsing.py         # parse_dns_name (compression), parse_dns_type, get_dns_type_name, calculate_entropy
  config.py              # BPF path, CGROUP_PATH, CLUSTER_DNS_SUFFIXES, CLUSTER_BASE_DOMAINS, is_legitimate_cluster_dns(), DEBUG_UNPARSEABLE
  pod_resolver.py        # PodResolver: cgroup_id → (client_pod, process), TTL cache, bpf_cgroup_get_fd / cgroup fs walk / K8s API
  event_handler.py       # handle_event(), print_stats(); JSON stderr для analyze.py
  detectors/
    tunnel.py            # TunnelDetector: C2 + Exfil + IPOverDNS, REASON_WEIGHTS, SCORE_THRESHOLD=2
    c2.py                # C2Detector: beacon regularity (query timestamps), TXT (type 16) + whitelist
    exfil.py             # ExfiltrationDetector: entropy, long domain, digit ratio, hex/base64 subdomain (≥16 chars), MANY_SUBDOMAINS (excl. CLUSTER_BASE_DOMAINS)
    ip_over_dns.py       # IPOverDNSDetector: per-key rate (WINDOW_NS, RATE_THRESHOLD), NULL (type 10), MANY_ANSWERS
  whitelist_loader.py    # load_txt_whitelist(): [domains], [prefixes], [roots] + built-in
  metrics.py             # Flask: /healthz, /ready, /metrics; prometheus_client
  main.py                # load_bpf, metrics thread, ring_buffer_poll, SIGINT/SIGTERM

k8s/tests/
  analyze.py             # JSONL → confusion matrix. Usage: analyze.py <file.jsonl> [--threshold N] [--gt-by-domain] [--attack-domain SUFFIX] [--summary] [--save]
  collect.sh             # kubectl logs по подам DaemonSet, grep '^{', merge → results/<label>.jsonl. Usage: collect.sh <label> <duration> [namespace] [daemonset-name]
  attack/deploy.sh       # ns | iodine | dnscat2 | exfil | stop | status
  baseline/deploy.sh    # apply | stop | status — baseline traffic
```

---

## 4. Конфигурация (env)

| Переменная | Назначение |
|------------|------------|
| CGROUP_PATH | Корень cgroup v2 (default /sys/fs/cgroup) |
| METRICS_PORT | Порт HTTP метрик (default 9999) |
| CLUSTER_DNS_SUFFIXES | Суффиксы cluster DNS (default .svc.cluster.local,.cluster.local,.pod.cluster.local) |
| POD_RESOLVER_CACHE_TTL | TTL кэша pod resolver в секундах (default 300) |
| TXT_WHITELIST_FILE | Путь к файлу whitelist для TXT-запросов |
| DEBUG_UNPARSEABLE | 1/true/yes — в stderr ip_version и payload_sample_hex для domain=<unparseable> |
| DEBUG_POD_RESOLVER | 1/true/yes — логи разрешения cgroup_id |

---

## 5. Нормализованное событие и JSON-лог

**В callback (loader):** domain, direction (query/response), protocol, client_pod, process, cgroup_id, dns_id, dns_flags, dns_answers, dns_type, timestamp_ns, ip_version; при domain=="<unparseable>" — payload_sample_hex.

**Строка в stderr (JSON):** ts, domain, direction, dns_type, pod, process, suspicious, score, threat_type, reasons, ip_version; при unparseable — payload_sample_hex. Используется `analyze.py` и `collect.sh`.

---

## 6. Детекторы и веса (tunnel.py)

REASON_WEIGHTS: C2_BEACON 3, C2_TXT_REQUEST 1, HIGH_ENTROPY 2, LONG_DOMAIN 1, HIGH_DIGIT_RATIO 1, HEX_SUBDOMAIN 2, BASE64_SUBDOMAIN 2, MANY_SUBDOMAINS 2, HIGH_RATE 3, NULL_RECORD 2, MANY_ANSWERS 2.  
SCORE_THRESHOLD = 2. Домены, для которых `is_legitimate_cluster_dns(domain)` True, не детектируются.

---

## 7. Технологический стек

| Компонент | Технология |
|-----------|------------|
| Kernel hook | eBPF cgroup_skb (BCC) |
| Userspace | Python 3.11 |
| Метрики | prometheus_client, Flask |
| Deployment | Helm → DaemonSet (privileged) |
| Цель | Kubernetes, cgroup v2, UDP/IPv4 DNS |

Основная новая документация проекта:

- `DETECTION_ALGORITHMS.md` — алгоритмы детекции, признаки, ограничения.
- `TESTING_AND_VALIDATION.md` — методология ground truth, результаты фаз A/B/C, интерпретация и ограничения обобщаемости.
- `ROADMAP_AND_NEXT_STEPS.md` — что ещё нужно для сильной версии ВКР и дальнейшего развития системы.
