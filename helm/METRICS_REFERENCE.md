# Метрики DNS Monitor (Prometheus)

Все метрики отдаются на `GET /metrics` (порт по умолчанию 9999). Имена в Prometheus могут иметь суффикс `_total` или `_created` у счётчиков (так экспортирует `prometheus_client`).

---

## Метрики приложения

| Метрика (в /metrics) | Тип | Метки | Описание |
|----------------------|-----|-------|----------|
| **dns_queries_total** | Counter | `protocol` (UDP/TCP), `direction` (query) | Всего DNS-запросов (исходящих). |
| **dns_responses_total** | Counter | `protocol` (UDP/TCP) | Всего DNS-ответов (входящих). |
| **dns_suspicious_total** | Counter | `threat_type` (C2, EXFIL, TUNNEL или комбинация, напр. C2+EXFIL) | Запросы, помеченные как подозрительные детекторами туннелей. Серия появляется только после первого такого события. |
| **dns_domains_unique** | Gauge | — | Текущее число уникальных доменов (по всем обработанным событиям). |
| **dns_events_by_process_total** | Counter | `process` (имя процесса, напр. nslookup, python3) | Событий DNS по процессу. |
| **dns_events_by_pod_total** | Counter | `pod` (pod:uid или container:id или host) | Событий DNS по поду/контейнеру/хосту. |

---

## Вспомогательные метрики (prometheus_client)

Для каждого Counter библиотека добавляет:

- **\<name>_created** — Gauge, Unix-время создания счётчика (для расчёта времени жизни).

Примеры: `dns_queries_created`, `dns_events_by_process_created`, `dns_events_by_pod_created`.

---

## Системные метрики (process_*, python_*)

- **process_virtual_memory_bytes**, **process_resident_memory_bytes** — память процесса.
- **process_cpu_seconds_total** — CPU время процесса.
- **process_open_fds**, **process_max_fds** — открытые и макс. файловые дескрипторы.
- **process_start_time_seconds** — время старта процесса.
- **python_info** — версия Python.
- **python_gc_*** — сборка мусора (objects collected/uncollectable, collections).

---

## Примеры PromQL для Grafana

| Что показать | Запрос |
|--------------|--------|
| RPS запросов по протоколу | `sum(rate(dns_queries_total[5m])) by (protocol, direction)` |
| RPS ответов по протоколу | `sum(rate(dns_responses_total[5m])) by (protocol)` |
| RPS подозрительных по типу угрозы | `sum(rate(dns_suspicious_total[5m])) by (threat_type)` |
| Уникальные домены (агрегат по инстансам) | `sum(dns_domains_unique)` |
| RPS по процессам | `sum(rate(dns_events_by_process_total[5m])) by (process)` |
| RPS по подам | `sum(rate(dns_events_by_pod_total[5m])) by (pod)` |

---

## Типы угроз (threat_type для dns_suspicious_total)

- **C2** — Command & Control: регулярные биконы, TXT-запросы к не-whitelist доменам.
- **EXFIL** — Data exfiltration: высокая энтропия, длинный домен, base64/hex subdomain, много цифр, много уникальных subdomain’ов.
- **TUNNEL** — IP-Over-DNS (iodine и т.п.): NULL-запросы, очень высокая частота запросов, много ответов.

Один запрос может дать комбинацию, например `C2+EXFIL` или `C2+TUNNEL`.
