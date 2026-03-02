# Алгоритмы детекции DNS-туннелей (v2)

Обновлено: 2026-03-01. Соответствует текущему коду после исправлений.

В мониторе используются три детектора: **C2 (Command & Control)**, **экфильтрация данных (Exfil)** и **IP-over-DNS**. Итоговое решение принимается **scoring-агрегатором** (взвешенная сумма, порог 2 балла).

**Ограничение:** BPF захватывает 64 байта DNS payload → максимум ~45 символов доменного имени. Проверка LONG_DOMAIN (> 60 символов) фактически не срабатывает. Все остальные 10 проверок работают.

---

## 1. Предварительная фильтрация

### Cluster-internal DNS whitelist

Перед вызовом детекторов агрегатор проверяет, не является ли домен cluster-internal:

```python
if domain.endswith(suffix) for suffix in CLUSTER_DNS_SUFFIXES:
    return not suspicious  # пропускаем
```

По умолчанию: `.svc.cluster.local`, `.cluster.local`, `.pod.cluster.local`.  
Configurable через env `CLUSTER_DNS_SUFFIXES`.

Это убирает ложные срабатывания на Kubernetes service discovery, headless services, ndots:5 и т.д.

---

## 2. C2 (Command & Control)

**Файл:** `detectors/c2.py`

### 2.1 Алгоритм 1: Beacon (регулярность интервалов)

**Идея:** C2-клиент периодически опрашивает подконтрольный домен. Интервалы стабильны.

**Структуры данных:**
- `query_history: OrderedDict[(cgroup_id, base_domain)] → [timestamp_ns, ...]` — LRU, max 10K ключей, max 20 timestamps на ключ.

**Параметры:**
- `MAX_QUERY_HISTORY_KEYS = 10_000`
- `MAX_HISTORY = 20`
- `MIN_SAMPLES = 5`
- `REGULARITY_THRESHOLD = 0.15` (CV)
- Минимальный средний интервал: 5 секунд

**Шаги:**
1. Из домена извлечь `base_domain` = последние 2 компонента. Ключ: `(cgroup_id, base_domain)`.
2. Если событие — **query** (direction по QR-биту): добавить timestamp в историю, обрезать до 20, переместить ключ в конец OrderedDict. Если ключей > 10K, вытеснить старейший (LRU).
3. Если в истории ≥ 5 timestamps:
   - Вычислить интервалы: `intervals[i] = (ts[i+1] - ts[i]) / 1e9`
   - Среднее: `avg_interval = mean(intervals)`
   - CV: `std_dev / avg_interval`
4. Если `CV < 0.15` и `avg_interval > 5` → `C2_BEACON` (вес 3)

**Формула:**
```
intervals[i] = (timestamps[i+1] - timestamps[i]) / 1e9
avg = mean(intervals)
variance = mean((x - avg)^2 for x in intervals)
cv = sqrt(variance) / avg
```

### 2.2 Алгоритм 2: TXT-запросы к недоверенным доменам

**Правило:** Если `dns_type == 16` (TXT) и домен **не** в расширенном whitelist (27 доменов + ACME challenge) → `C2_TXT_REQUEST` (вес 1).

**Whitelist:** google.com, googleapis.com, microsoft.com, cloudflare.com, amazonaws.com, github.com, githubusercontent.com, atlassian.com, fastly.com, apple.com, googledomains.com, yandex.ru, yandex.net, cloudflare.net, akamai.net, facebook.com, meta.com, twitter.com, linkedin.com, zoom.us, slack.com, dropbox.com, box.com, stripe.com, paypal.com, spotify.com, twitch.tv, redhat.com, openshift.com, kubernetes.io, k8s.io.

**Исключение:** `_acme-challenge.*` (Let's Encrypt DNS-01, cert-manager) пропускается.

---

## 3. Exfiltration (экфильтрация данных)

**Файл:** `detectors/exfil.py`

### 3.1 Энтропия домена

**Формула (Шеннон):**
```
H = -Σ p(c) × log2(p(c))
```
где `p(c)` — частота символа в `domain.replace('.', '')`.

**Порог:** `ENTROPY_THRESHOLD = 4.0` → `HIGH_ENTROPY` (вес 2).

**Известное ограничение:** энтропия считается по всему домену включая base_domain, а не только по поддомену. Это снижает чувствительность.

### 3.2 Длина домена

**Порог:** `LENGTH_THRESHOLD = 60`.

**Статус:** **Фактически не работает** при 64-байтном payload (домен ≤ ~45 символов). Оставлено на случай будущего увеличения payload. Вес 1.

### 3.3 Доля цифр

`digit_ratio = (число цифр) / len(domain без точек)`.  
**Порог:** `DIGIT_RATIO_THRESHOLD = 0.3` → `HIGH_DIGIT_RATIO` (вес 1).

### 3.4 Кодирование в первом поддомене

Если домен имеет > 2 частей и первый поддомен > 20 символов:

1. **Hex** (проверяется первым): `^[0-9a-fA-F]+$` → `HEX_SUBDOMAIN` (вес 2)
2. **Base64** (если не hex): `^[A-Za-z0-9+/=]+$` → `BASE64_SUBDOMAIN` (вес 2)

Порядок важен: hex — подмножество base64, поэтому hex проверяется первым.

### 3.5 Много уникальных поддоменов

**Структура данных:** `subdomain_counts: defaultdict(list)` — для каждого base_domain хранит до 50 уникальных поддоменов (FIFO eviction).

**Порог:** `SUBDOMAIN_COUNT_THRESHOLD = 20` → `MANY_SUBDOMAINS` (вес 2).

**Параметры (сводка):**
- `ENTROPY_THRESHOLD = 4.0`
- `LENGTH_THRESHOLD = 60` (не работает при 64B payload)
- `DIGIT_RATIO_THRESHOLD = 0.3`
- `SUBDOMAIN_COUNT_THRESHOLD = 20`
- `MAX_SUBDOMAINS_STORED = 50`

---

## 4. IP-over-DNS

**Файл:** `detectors/ip_over_dns.py`

### 4.1 Per-key окно и rate

**Структуры данных:**
- `request_counts: defaultdict(int)` — счётчик запросов per key
- `first_seen_ns: dict` — timestamp первого события per key в текущем окне

**Параметры:**
- `WINDOW_NS = 10 × 1e9` (10 секунд)
- `RATE_THRESHOLD = 50` запросов/сек

**Алгоритм:**
1. Ключ: `(cgroup_id, base_domain)`.
2. Если ключ уже имеет `first_seen_ns` и прошло > 10 секунд → сброс **только этого ключа**: `first_seen_ns[key] = timestamp`, `request_counts[key] = 0`.
3. Если ключ новый → `first_seen_ns[key] = timestamp`.
4. `request_counts[key] += 1`.
5. `elapsed_sec = (timestamp - first_seen_ns[key]) / 1e9`.
6. Если `elapsed_sec > 1`: `rate = request_counts[key] / elapsed_sec`.
7. Если `rate > 50` → `HIGH_RATE` (вес 3).

### 4.2 NULL-запись (тип 10)

Если `dns_type == 10` → `NULL_RECORD(iodine)` (вес 2).

### 4.3 Много записей в ответе

Если `dns_answers > 5` → `MANY_ANSWERS` (вес 2).

**Параметры (сводка):**
- `WINDOW_NS = 10e9` (10 с), per-key
- `RATE_THRESHOLD = 50` запросов/с
- Порог ответов: 5 записей

---

## 5. Scoring-агрегатор

**Файл:** `detectors/tunnel.py`

### 5.1 Веса причин

| Причина | Вес | Обоснование |
|---------|:---:|-------------|
| C2_BEACON | 3 | Сильный сигнал: регулярные интервалы |
| HIGH_RATE | 3 | Сильный сигнал: аномальная частота |
| HIGH_ENTROPY | 2 | Типично для зашифрованных/сжатых данных |
| HEX_SUBDOMAIN | 2 | Явное кодирование |
| BASE64_SUBDOMAIN | 2 | Явное кодирование |
| MANY_SUBDOMAINS | 2 | Множество уникальных поддоменов = data channel |
| NULL_RECORD | 2 | Типично для iodine |
| MANY_ANSWERS | 2 | Типично для IP-over-DNS |
| C2_TXT_REQUEST | 1 | Слабый сигнал: TXT легитимен для SPF/DKIM |
| LONG_DOMAIN | 1 | Слабый сигнал (и не работает при 64B) |
| HIGH_DIGIT_RATIO | 1 | Слабый сигнал: много цифр |

### 5.2 Алгоритм

```python
score = sum(weight for reason in reasons if reason.startswith(prefix))
is_suspicious = (score >= SCORE_THRESHOLD)  # SCORE_THRESHOLD = 2
```

**Следствия:**
- Один `C2_TXT_REQUEST` (вес 1) → **не** suspicious (score 1 < 2)
- Один `HIGH_DIGIT_RATIO` (вес 1) → **не** suspicious
- `HIGH_ENTROPY` (вес 2) → suspicious (score 2 ≥ 2)
- `C2_BEACON` (вес 3) → suspicious
- `C2_TXT_REQUEST` + `HIGH_DIGIT_RATIO` (1 + 1 = 2) → suspicious (комбинация слабых сигналов)

### 5.3 Объединение threat_type

`threat_type = '+'.join(["C2", "EXFIL", "TUNNEL"])` — для каждого сработавшего детектора.

---

## 6. Сводная таблица порогов

| Детектор | Параметр | Значение | Configurable |
|----------|----------|----------|:------------:|
| C2 | MAX_QUERY_HISTORY_KEYS | 10,000 | Нет (код) |
| C2 | MAX_HISTORY | 20 | Нет |
| C2 | MIN_SAMPLES | 5 | Нет |
| C2 | REGULARITY_THRESHOLD | 0.15 | Нет |
| C2 | min avg_interval | 5 с | Нет |
| C2 | TXT whitelist | 27 доменов + ACME | Нет (код) |
| Exfil | ENTROPY_THRESHOLD | 4.0 | Нет |
| Exfil | LENGTH_THRESHOLD | 60 (не работает) | Нет |
| Exfil | DIGIT_RATIO_THRESHOLD | 0.3 | Нет |
| Exfil | SUBDOMAIN_COUNT_THRESHOLD | 20 | Нет |
| Exfil | MAX_SUBDOMAINS_STORED | 50 | Нет |
| IP-over-DNS | WINDOW_NS | 10e9 (10 с) | Нет |
| IP-over-DNS | RATE_THRESHOLD | 50 req/s | Нет |
| IP-over-DNS | dns_answers threshold | 5 | Нет |
| Aggregator | SCORE_THRESHOLD | 2 | Нет |
| Cluster DNS | CLUSTER_DNS_SUFFIXES | .svc.cluster.local, ... | **Да** (env) |
| Pod resolver | CACHE_TTL | 300 с | **Да** (env) |

---

## 7. Что работает / не работает при 64B payload

| Проверка | Работает? | Комментарий |
|----------|:---------:|-------------|
| C2_BEACON | Да | Зависит от timestamps, не от payload |
| C2_TXT_REQUEST | Да | Зависит от dns_type |
| HIGH_ENTROPY | Да | На усечённом домене (до ~45 символов); менее чувствителен |
| HIGH_DIGIT_RATIO | Да | На усечённом домене |
| HEX_SUBDOMAIN | Да | first_subdomain до ~30 символов (base ~15) |
| BASE64_SUBDOMAIN | Да | Аналогично |
| MANY_SUBDOMAINS | Да | Зависит от count, не от длины |
| HIGH_RATE | Да | Зависит от count/time |
| NULL_RECORD | Да | Зависит от dns_type |
| MANY_ANSWERS | Да | Из DNS header (bytes 6-7) |
| **LONG_DOMAIN** | **Нет** | Домен max ~45 символов, порог 60 |

**10 из 11 проверок работают.**
