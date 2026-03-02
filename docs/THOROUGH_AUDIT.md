# Полный аудит кодовой базы DNS Tunnel Monitor (v2)

Дата первого аудита: 2026-03-01  
Дата обновления: 2026-03-01 (после исправлений, NEW-01 исправлен)

---

## Сводка изменений после первого аудита

| ID | Описание | Статус |
|----|----------|--------|
| BUG-03 | direction по QR-биту вместо egress/ingress | **ИСПРАВЛЕНО** |
| BUG-11 | query_history keys ∞ → OrderedDict + LRU (10K keys) | **ИСПРАВЛЕНО** |
| BUG-14 | HEX_SUBDOMAIN мёртв → hex проверяется первым | **ИСПРАВЛЕНО** |
| BUG-16 | subdomain_counts ∞ → list с cap 50 | **ИСПРАВЛЕНО** |
| BUG-18 | Tumbling window → per-key window | **ИСПРАВЛЕНО** |
| BUG-19 | Rate от window_start → per-key first_seen | **ИСПРАВЛЕНО** |
| BUG-26 | PodResolver cache stale → TTL 300s (configurable) | **ИСПРАВЛЕНО** |
| ISSUE-12 | TXT whitelist 3 домена → 27 доменов + ACME | **ИСПРАВЛЕНО** |
| ISSUE-22 | Бинарный OR → weighted scoring (threshold=2) | **ИСПРАВЛЕНО** |
| K8S | Нет cluster DNS whitelist → configurable suffix list | **ИСПРАВЛЕНО** |
| BUG-02 | PAYLOAD_SAMPLE=64 | **Принято как ограничение** (увеличение ломает парсинг) |
| BUG-17 | LONG_DOMAIN мёртвый код | **Принято как ограничение** (следствие 64B) |
| NEW-01 | ip_over_dns: first_seen_ns/request_counts ∞ keys → OrderedDict LRU (10K) | **ИСПРАВЛЕНО** |

---

## 1. Исправленные баги — проверка корректности

### BUG-03: ИСПРАВЛЕНО — direction по QR-биту

```python
# loader.py:65-66
is_response = (dns_flags & 0x8000) != 0
direction = "response" if is_response else "query"
```

Теперь query/response определяется по QR-биту DNS-заголовка (бит 15 flags). Корректно работает и для подов-клиентов, и для CoreDNS.

### BUG-11: ИСПРАВЛЕНО — LRU eviction для query_history

```python
# c2.py
self.query_history = OrderedDict()
MAX_QUERY_HISTORY_KEYS = 10_000
# при добавлении: popitem(last=False) если keys >= MAX
```

Ключей не больше 10K. Старые ключи вытесняются. Значения по-прежнему ограничены 20 timestamps.

### BUG-14: ИСПРАВЛЕНО — hex перед base64

```python
# exfil.py:41-44
if re.match(r'^[0-9a-fA-F]+$', first_subdomain):
    reasons.append("HEX_SUBDOMAIN")
elif re.match(r'^[A-Za-z0-9+/=]+$', first_subdomain):
    reasons.append("BASE64_SUBDOMAIN")
```

Hex проверяется первым. Обе ветки теперь достижимы.

### BUG-16: ИСПРАВЛЕНО — subdomain_counts capped

```python
# exfil.py
self.subdomain_counts = defaultdict(list)
MAX_SUBDOMAINS_STORED = 50
# при добавлении: lst.pop(0) если len > 50
```

Значения ограничены 50 записями. Однако **число ключей** (base_domain) по-прежнему не ограничено (см. оставшиеся issues).

### BUG-18 + BUG-19: ИСПРАВЛЕНО — per-key window и rate

```python
# ip_over_dns.py
self.first_seen_ns = {}  # per-key
# при проверке: elapsed = timestamp - self.first_seen_ns[key]
# при сбросе: only this key is reset
```

Rate теперь считается от первого события **конкретного ключа**, а не от начала глобального окна. Каждый ключ сбрасывается независимо.

### BUG-26: ИСПРАВЛЕНО — TTL-кэш PodResolver

```python
# pod_resolver.py
self._ttl_ns = config.POD_RESOLVER_CACHE_TTL_SEC * 10**9  # default 300s
# в _resolve_entry: if now_ns - cached["ts_ns"] < self._ttl_ns: return cached
```

Кэш инвалидируется через 5 минут. Configurable через `POD_RESOLVER_CACHE_TTL`.

### ISSUE-12: ИСПРАВЛЕНО — расширенный TXT whitelist

27 доменов: google, googleapis, microsoft, cloudflare, amazonaws, github, atlassian, fastly, apple, yandex, akamai, facebook, meta, twitter, linkedin, zoom, slack, dropbox, box, stripe, paypal, spotify, twitch, redhat, openshift, kubernetes.io, k8s.io.

Плюс пропуск `_acme-challenge.*` (Let's Encrypt / cert-manager).

### ISSUE-22: ИСПРАВЛЕНО — weighted scoring

```python
REASON_WEIGHTS = {
    "C2_BEACON": 3, "C2_TXT_REQUEST": 1, "HIGH_ENTROPY": 2,
    "LONG_DOMAIN": 1, "HIGH_DIGIT_RATIO": 1, "HEX_SUBDOMAIN": 2,
    "BASE64_SUBDOMAIN": 2, "MANY_SUBDOMAINS": 2, "HIGH_RATE": 3,
    "NULL_RECORD": 2, "MANY_ANSWERS": 2,
}
SCORE_THRESHOLD = 2
```

Один C2_TXT_REQUEST (вес 1) больше не даёт алерт. Нужен score >= 2.

### K8S: ИСПРАВЛЕНО — cluster DNS whitelist

```python
# tunnel.py:43-45
if domain and any(domain.endswith(s) for s in config.CLUSTER_DNS_SUFFIXES):
    return False, None, []
```

По умолчанию: `.svc.cluster.local`, `.cluster.local`, `.pod.cluster.local`. Configurable через `CLUSTER_DNS_SUFFIXES` env.

---

## 2. NEW-01: ИСПРАВЛЕНО — LRU для ip_over_dns

**Файл:** `detectors/ip_over_dns.py`

Вместо двух словарей (`request_counts`, `first_seen_ns`) используется один `OrderedDict`: ключ → `(request_count, first_seen_ns)`. При добавлении нового ключа при `len >= MAX_KEYS` (10_000) вытесняется старейший: `popitem(last=False)`. При обновлении ключа — `pop(key)` и повторная вставка (перемещение в конец LRU). Рост памяти ограничен.

---

## 3. Оставшиеся issues (не исправлены)

### Принятые ограничения (не баги)

| ID | Описание | Решение |
|----|----------|---------|
| BUG-02 | PAYLOAD_SAMPLE=64 → max ~45 символов домена | Принято: увеличение ломает парсинг. Описать в ВКР как ограничение |
| BUG-17 | LONG_DOMAIN(60) — мёртвый код | Следствие BUG-02. Оставить проверку (для будущего), описать в ВКР |
| BUG-01 | IP header = 20 байт hardcoded | Принято: IP options в кластере крайне редки. Описать как ограничение |

### Остающиеся баги — Low/Medium

| ID | Файл | Описание | Severity |
|----|------|----------|----------|
| BUG-05 | loader.py | size check 72 vs 80 | Low |
| BUG-07 | dns_parsing.py | parse_dns_type нет bounds check в while | Low-Medium |
| BUG-10 | все детекторы | base_domain = last 2 labels (неверно для .co.uk) | Medium |
| BUG-15 | exfil.py | Энтропия по полному домену, не по поддомену | Medium |
| BUG-20 | ip_over_dns.py | NULL_RECORD/MANY_ANSWERS double fire (query+response) | Low |
| BUG-23 | event_handler.py | stats["domains"] set ∞ | Medium |
| BUG-24 | event_handler.py | stats["by_pod"] dict ∞ | Medium |
| BUG-27 | pod_resolver.py | K8s API limit=500, нет пагинации | Medium |
| BUG-30 | metrics.py | Prometheus label cardinality (process × pod × direction) | Medium-High |
| BUG-32 | main.py | Double print_stats при Ctrl+C | Low |
| ISSUE-08 | loader.py | Dead code: dns_questions | Cosmetic |
| ISSUE-09 | loader.py | Unused import: get_dns_type_name | Cosmetic |
| ISSUE-25 | event_handler.py | Двойной расчёт энтропии (detector + handler) | Low |
| ISSUE-33 | main.py / loader.py | Нет мониторинга потерь perf buffer | Medium |

### Мелкие замечания по новому коду

**exfil.py — subdomain_counts ключи растут:** Значения ограничены 50, но число ключей (base_domain) нет. Для PoC/MVP допустимо, при долгой работе может расти.

**exfil.py — `if subdomain not in lst`:** O(n) поиск в list, n ≤ 50. Приемлемо для PoC. Для оптимизации можно использовать set + deque.

**c2.py — ACME check:** `if '_acme-challenge.' in domain_full` проверяет подстроку в любом месте домена. Строго говоря, `_acme-challenge.` должен быть первым label. Маловероятно что кто-то вставит `_acme-challenge.` в mid-domain, но технически false negative на необычный malicious домен вроде `data._acme-challenge_.evil.com`.

---

## 4. Что работает с 64-байтовым payload

С учётом ограничения ~45 символов домена из BPF:

| Проверка | Зависит от payload? | Работает? | Комментарий |
|----------|:-------------------:|:---------:|-------------|
| C2_BEACON (CV интервалов) | Нет (только timestamps) | **Полностью** | Не зависит от длины домена |
| C2_TXT_REQUEST | dns_type (парсится из 64B) | **Полностью** | |
| HIGH_ENTROPY | domain (до ~45 символов) | **Работает** | Энтропия значима для 20-45 символов; туннели обычно > 30 |
| HIGH_DIGIT_RATIO | domain (до ~45 символов) | **Работает** | |
| HEX_SUBDOMAIN | first_subdomain > 20 chars | **Работает** | Base domain ~15 chars → first sub до ~30 chars, > 20 порог |
| BASE64_SUBDOMAIN | first_subdomain > 20 chars | **Работает** | Аналогично |
| MANY_SUBDOMAINS | count, не длина | **Полностью** | |
| HIGH_RATE | count/time, не payload | **Полностью** | |
| NULL_RECORD | dns_type (парсится из 64B) | **Полностью** | |
| MANY_ANSWERS | dns header bytes 6-7 | **Полностью** | |
| LONG_DOMAIN | len(domain) > 60 | **Не работает** | Max ~45 символов из BPF. Мёртвый код |

**Итого: 10 из 11 проверок работают.** Только LONG_DOMAIN мёртв. Это хороший набор для MVP.

---

## 5. Приоритеты дальнейшей работы

| Приоритет | Задача | Зачем |
|-----------|--------|-------|
| **High** | Фаза 3: Валидация TP/FP (iodine/dnscat2/dns2tcp) | Основа экспериментальной части ВКР |
| **Medium** | BUG-15: энтропия по поддомену | Повышение чувствительности exfil |
| **Medium** | BUG-10: multi-part TLD (публичный suffix list) | Корректность base_domain |
| **Low** | BUG-30: label cardinality (namespace вместо pod) | Production stability |
| **Low** | Остальные Low issues | Nice-to-have |

---

## Приложение: карта по severity (обновлённая)

### High
| ID | Описание | Статус |
|----|----------|--------|
| ~~BUG-02~~ | ~~64-byte payload~~ | Принято как ограничение |
| ~~BUG-14~~ | ~~HEX_SUBDOMAIN мёртв~~ | ИСПРАВЛЕНО |
| ~~BUG-17~~ | ~~LONG_DOMAIN мёртвый код~~ | Принято как ограничение |
| ~~BUG-18~~ | ~~Tumbling window~~ | ИСПРАВЛЕНО |
| ~~BUG-19~~ | ~~Rate занижается~~ | ИСПРАВЛЕНО |
| ~~BUG-11~~ | ~~query_history keys ∞~~ | ИСПРАВЛЕНО |
| ~~BUG-16~~ | ~~subdomain_counts ∞~~ | ИСПРАВЛЕНО |
| ~~BUG-26~~ | ~~PodResolver cache stale~~ | ИСПРАВЛЕНО |
| ~~ISSUE-12~~ | ~~TXT whitelist 3 домена~~ | ИСПРАВЛЕНО |
| ~~ISSUE-22~~ | ~~Бинарный OR~~ | ИСПРАВЛЕНО |
| ~~NEW-01~~ | ~~ip_over_dns: first_seen_ns/request_counts ∞~~ | ИСПРАВЛЕНО |

### Medium (не исправлены)
| ID | Описание |
|----|----------|
| BUG-10 | Multi-part TLD → неверный base_domain |
| BUG-15 | Энтропия по полному домену, не по поддомену |
| BUG-23 | stats["domains"] → рост |
| BUG-27 | K8s API — limit=500, нет пагинации |
| BUG-30 | Prometheus label cardinality explosion |
| ISSUE-33 | Нет мониторинга потерь perf buffer |

### Low (не исправлены)
| ID | Описание |
|----|----------|
| BUG-05 | size check 72 vs 80 |
| BUG-07 | parse_dns_type bounds |
| BUG-20 | NULL_RECORD double fire |
| BUG-32 | Double print_stats |
| ISSUE-08 | Dead code: dns_questions |
| ISSUE-09 | Unused import |
| ISSUE-25 | Двойной расчёт энтропии |
