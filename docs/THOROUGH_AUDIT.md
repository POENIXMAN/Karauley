# Полный аудит кодовой базы DNS Tunnel Monitor

Дата: 2026-03-01  
Область: все модули — BPF, парсинг, детекторы, event pipeline, pod resolution, метрики, main loop.

### Исправлено после аудита (актуализация)

- **timestamp_ns:** в loader при формировании события добавлено `timestamp_ns = time.time_ns()`; в event_handler в `event_data` для детекторов передаются `timestamp_ns` и `direction`. C2 beacon и IP-over-DNS rate/окно работают при наличии трафика (см. WORK_PLAN, раздел 0).
- **C2 beacon:** в детекторе C2 в историю для расчёта интервалов попадают только события с `direction == 'query'` (ответы не смешиваются).

Остальные пункты аудита ниже в силе; приоритеты и план исправлений — в WORK_PLAN.md.

---

## Содержание

1. [BPF-уровень (dns_cgroup.bpf.c)](#1-bpf-уровень)
2. [Структура события (event_struct.py)](#2-структура-события)
3. [Парсинг DNS (dns_parsing.py)](#3-парсинг-dns)
4. [Загрузчик (loader.py)](#4-загрузчик)
5. [Детекторы](#5-детекторы)
   - 5.1 [C2 (c2.py)](#51-c2)
   - 5.2 [Exfiltration (exfil.py)](#52-exfiltration)
   - 5.3 [IP-over-DNS (ip_over_dns.py)](#53-ip-over-dns)
   - 5.4 [Агрегатор (tunnel.py)](#54-агрегатор)
6. [Event handler (event_handler.py)](#6-event-handler)
7. [Pod resolver (pod_resolver.py)](#7-pod-resolver)
8. [Метрики (metrics.py)](#8-метрики)
9. [Main loop (main.py)](#9-main-loop)
10. [Память — сводка утечек](#10-память--сводка-утечек)
11. [Оценка для ВКР и рекомендации](#11-оценка-для-вкр-и-рекомендации)

---

## 1. BPF-уровень

**Файл:** `bpf/dns_cgroup.bpf.c`

### BUG-01: Жёстко заданное смещение IP-заголовка (IP options не учитываются)

```c
if (bpf_skb_load_bytes(ctx, 9, &proto, 1) < 0) return 1;  // protocol
// ...
if (bpf_skb_load_bytes(ctx, 20, &sport, 2) < 0) return 1;  // UDP src port
if (bpf_skb_load_bytes(ctx, 22, &dport, 2) < 0) return 1;  // UDP dst port
// ...
bpf_skb_load_bytes(ctx, 28, ev.payload, PAYLOAD_SAMPLE);    // DNS payload
```

Код предполагает IP-заголовок = 20 байт (IHL = 5). Если присутствуют IP options (IHL > 5), UDP-заголовок начинается не с offset 20, а дальше. В результате:
- `sport`/`dport` читаются из тела UDP, а не из заголовка
- `payload` начинается не с DNS, а с середины UDP-пакета
- Пакеты с IP options либо не распознаются как DNS, либо парсятся некорректно

**Severity:** Medium. IP options редки в кластерном трафике, но GKE/EKS могут добавлять Router Alert option.

**Fix:** Прочитать IHL из первого байта, вычислить длину заголовка:
```c
uint8_t ihl_byte;
bpf_skb_load_bytes(ctx, 0, &ihl_byte, 1);
uint32_t ip_hdr_len = (ihl_byte & 0x0F) * 4;
// Далее использовать ip_hdr_len вместо 20
```

### BUG-02: PAYLOAD_SAMPLE = 64 — усечение длинных доменов

DNS payload начинается после 12-байтного заголовка. Остаётся 52 байта на Question Section (доменное имя в wire format + QTYPE + QCLASS). С учётом length-prefix labels и 4 байт TYPE+CLASS, максимальная длина доменного имени в wire format ≈ 48 байт ≈ **~45 символов** после декодирования.

**Критическое последствие:** Exfil-детектор проверяет `len(domain) > 60` (LENGTH_THRESHOLD), но из BPF мы физически не получим домен длиннее ~45 символов. **Проверка LONG_DOMAIN — мёртвый код.**

Также: энтропия усечённых доменов занижена по сравнению с реальной.

**Severity:** High. Одна из основных эвристик exfil-детекции не работает.

**Fix:** Увеличить `PAYLOAD_SAMPLE` до 256 (или минимум 128). BPF stack limit — 512 байт, нужно убедиться что структура события помещается.

### BUG-03: Направление = egress/ingress ≠ query/response

```c
int egress_hook(struct __sk_buff *ctx)  { return monitor_dns(ctx, 1); }  // → "query"
int ingress_hook(struct __sk_buff *ctx) { return monitor_dns(ctx, 2); }  // → "response"
```

Loader интерпретирует: `direction = "query" if ev.direction == 1 else "response"`.

Проблема: egress из пода — это **исходящий** пакет. Если под является DNS-сервером (CoreDNS!), то egress = DNS ответ, а ingress = DNS запрос. Текущая логика инвертирует направление для DNS-серверов.

**Severity:** Medium. CoreDNS обычно в своей cgroup, но при мониторинге всего кластера (`/sys/fs/cgroup`) события CoreDNS будут неверно классифицированы.

**Fix:** Определять query/response по QR-биту DNS-заголовка (бит 15 поля flags), а не по направлению cgroup_skb:
```python
is_response = (dns_flags & 0x8000) != 0
direction = "response" if is_response else "query"
```

### ISSUE-04: Нет учёта потерянных событий perf buffer

BCC `open_perf_buffer` поддерживает `lost_cb` — callback при потере событий из-за переполнения буфера. Сейчас потерянные события молча теряются. В нагруженном кластере это может быть значительная доля трафика.

**Severity:** Low-Medium. Важно для production, не критично для PoC.

---

## 2. Структура события

**Файл:** `event_struct.py`

### BUG-05: Неверная проверка размера в loader

```python
# loader.py:60
if size < 8 + 64:  # = 72
    return
```

Реальный размер структуры: `direction(1) + _pad(7) + cgroup_id(8) + payload(64) = 80 байт`.

Проверка `size < 72` пропускает пакеты размером 72-79 байт, где `cgroup_id` не полностью заполнен. На практике perf buffer всегда передаёт полную структуру, но при сбое данные могут быть урезаны.

**Severity:** Low. Лучше: `size < ctypes.sizeof(CgroupDNSEvent)`.

---

## 3. Парсинг DNS

**Файл:** `dns_parsing.py`

### BUG-06: Compression pointer — только backward

```python
if pointer < i and pointer < len(data):
```

Код следует за compression pointers только если `pointer < i` (ссылка назад). RFC 1035 разрешает ссылки на любое предшествующее вхождение имени, но в wire format pointer может указывать на позицию >= текущей (forward reference). При 64-байтном payload это маловероятно, но при увеличении PAYLOAD_SAMPLE может проявиться.

**Severity:** Low.

### BUG-07: parse_dns_type — выход за границы при пустом/коротком payload

```python
def parse_dns_type(data):
    i = 12
    while i < len(data) and data[i] != 0:
        length = data[i]
        if (length & 0xC0) == 0xC0:
            i += 2
            break
        i += length + 1
    else:
        i += 1
```

Если `len(data) <= 12`, цикл не выполняется (i=12, `i < len(data)` false), `else` выполняется, `i = 13`. Затем `if i + 2 <= len(data)` → false при data < 15 байт, возвращает 1 (A). Не падает, но молча маскирует проблему.

Более серьёзно: если `length` (data[i]) = 0 при первой итерации, цикл завершается по условию `data[i] != 0`, else выполняется, i += 1. Это корректно (пропуск null terminator). Но если `i + length + 1 > len(data)`, мы выходим за границу массива при чтении `data[i]` на следующей итерации. Нет guard'а на `i + length + 1 <= len(data)` внутри цикла (есть в parse_dns_name, но не здесь).

**Severity:** Medium. При усечённых пакетах может читать мусор или упасть с IndexError.

---

## 4. Загрузчик

**Файл:** `loader.py`

### ISSUE-08: Неиспользуемая переменная dns_questions

```python
dns_questions = (data[4] << 8 | data[5]) if len(data) >= 6 else 0
```

Переменная вычисляется, но нигде не используется. Dead code.

**Severity:** Cosmetic.

### ISSUE-09: `get_dns_type_name` импортируется, но не используется

```python
from dns_tunnel_monitor.dns_parsing import parse_dns_name, parse_dns_type, get_dns_type_name
```

`get_dns_type_name` не вызывается в loader.py.

**Severity:** Cosmetic.

---

## 5. Детекторы

### 5.1 C2

**Файл:** `detectors/c2.py`

#### BUG-10: base_domain — неверное извлечение для multi-part TLD

```python
base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else event.get('domain', '')
```

Для доменов с составными TLD (`.co.uk`, `.com.au`, `.org.ru`, `.msk.ru`):
- `evil.co.uk` → base_domain = `co.uk` (вместо `evil.co.uk`)
- `data.evil.co.uk` → base_domain = `co.uk`
- Все домены под `.co.uk` группируются в один ключ

**Последствие для C2:** запросы к разным доменам `.co.uk` будут считаться beacon'ом одного домена.

**Severity:** Medium. Этот же баг присутствует во всех трёх детекторах и в exfil subdomain counting.

#### BUG-11: query_history — ключей бесконечно много

Значения ограничены до 20, но ключей `(cgroup_id, base_domain)` может быть `O(pods × domains)`. При 100 подах и 1000 доменах = 100K ключей × list overhead.

**Severity:** High для production. При долгой работе DaemonSet ведёт к OOM.

#### ISSUE-12: TXT whitelist — 3 домена, слишком узкий

Легитимные TXT-запросы: SPF/DKIM/DMARC (любые mail-домены), Let's Encrypt ACME DNS-01 challenge, service mesh discovery, cert-manager, external-dns. Все дадут false positive.

**Severity:** High для кластерной среды.

#### ISSUE-13: Пороги захардкожены

`MIN_SAMPLES=5`, `REGULARITY_THRESHOLD=0.15`, `avg_interval > 5` — нет конфигурации. Тюнинг требует правки кода.

**Severity:** Medium.

### 5.2 Exfiltration

**Файл:** `detectors/exfil.py`

#### BUG-14: HEX_SUBDOMAIN никогда не сработает

```python
if re.match(r'^[A-Za-z0-9+/=]+$', first_subdomain):
    reasons.append("BASE64_SUBDOMAIN")
elif re.match(r'^[0-9a-fA-F]+$', first_subdomain):
    reasons.append("HEX_SUBDOMAIN")
```

Hex-символы `[0-9a-fA-F]` являются подмножеством Base64-символов `[A-Za-z0-9+/=]`. **Любая** строка, которая матчит hex regex, также матчит base64 regex. Поскольку base64 проверяется первым (`if`), ветка `elif` для hex **никогда не выполнится**.

**Severity:** Bug. HEX_SUBDOMAIN — мёртвый код.

**Fix:** Поменять порядок проверок (сначала hex, потом base64) или проверять наличие не-hex символов для base64.

#### BUG-15: Энтропия считается по всему домену, включая base domain

```python
domain_clean = domain.replace('.', '')
entropy = calculate_entropy(domain_clean)
```

Для `encoded-data.example.com` → `encodeddataexamplecom`. Постоянная часть `examplecom` разбавляет энтропию. Детектор менее чувствителен к энтропии поддомена, чем должен быть.

**Severity:** Medium. Снижает чувствительность к коротким закодированным поддоменам.

**Fix:** Считать энтропию только от поддоменной части (всё кроме последних двух labels).

#### BUG-16: subdomain_counts — бесконечный рост

```python
self.subdomain_counts[base_domain].add(subdomain)
```

Множество `set()` на каждый base_domain. Никогда не очищается.

**Последствия:**
1. Память растёт линейно по числу уникальных (base_domain, subdomain) пар.
2. После превышения порога 20 — каждое новое событие для этого base_domain генерирует MANY_SUBDOMAINS. Алерт становится **постоянным и бесполезным** (alert fatigue).

**Severity:** High.

#### BUG-17: LONG_DOMAIN — мёртвый код из-за BPF payload limit

LENGTH_THRESHOLD = 60 символов. BPF захватывает 64 байта DNS payload = ~45 символов домена после декодирования (см. BUG-02). **Порог никогда не будет превышен.**

**Severity:** High. Ключевая эвристика exfil-детекции не работает.

### 5.3 IP-over-DNS

**Файл:** `detectors/ip_over_dns.py`

#### BUG-18: Tumbling window, не sliding — потеря событий на границах

```python
elif timestamp and timestamp - self.window_start > self.WINDOW_NS:
    self.request_counts.clear()
    self.window_start = timestamp
```

Глобальный сброс **всех** счётчиков при переходе к новому окну. Если cgroup A накопил 49 запросов за 9 секунд, и cgroup B триггерит смену окна — счётчик A обнуляется.

**Severity:** High. Rate detection может пропускать настоящие всплески.

#### BUG-19: Rate считается от начала окна, а не от первого события ключа

```python
elapsed_sec = (timestamp - self.window_start) / 1e9
rate = self.request_counts[key] / elapsed_sec
```

Если ключ начал генерировать события на 9-й секунде окна и сделал 50 запросов за 1 секунду: `rate = 50 / 9 = 5.5/sec`, а не `50/1 = 50/sec`. **Занижение rate в 9 раз.**

**Severity:** High. Пропуск реальных всплесков.

**Fix:** Хранить per-key first_seen_in_window и считать rate от него.

#### BUG-20: NULL_RECORD и MANY_ANSWERS срабатывают на query и response

NULL_RECORD (type 10) — фиксируется и для запроса, и для ответа. Каждый DNS exchange генерирует двойное срабатывание. Аналогично MANY_ANSWERS.

**Severity:** Low-Medium. Удвоение алертов.

#### BUG-21: dns_answers > 5 может ложно сработать на query

Для DNS-запросов ANCOUNT (поле ответов в заголовке) должен быть 0. Но из-за 64-байтного усечения payload и возможного мусора в данных, парсинг может вернуть ненулевое значение.

**Severity:** Low.

### 5.4 Агрегатор

**Файл:** `detectors/tunnel.py`

#### ISSUE-22: Бинарный OR вместо scoring

```python
is_suspicious = len(all_reasons) > 0
```

Одно любое срабатывание = подозрение. Нет весов, нет confidence score. Один TXT-запрос к незнакомому домену — сразу алерт. В кластерной среде это даёт шквал FP.

**Severity:** High для production. Приемлемо для PoC с оговоркой.

---

## 6. Event handler

**Файл:** `event_handler.py`

#### BUG-23: stats["domains"] — бесконечный рост

```python
stats["domains"].add(domain)
```

Set всех уникальных доменов за всё время работы. В кластере с тысячами подов и DNS service discovery это тысячи/десятки тысяч записей.

**Severity:** Medium.

#### BUG-24: stats["by_pod"] — бесконечный рост

```python
stats["by_pod"][client_pod] += 1
```

defaultdict(int) по podname. При частом пересоздании подов (deployments, jobs, cronjobs) — ключи от мёртвых подов накапливаются.

**Severity:** Medium.

#### ISSUE-25: Энтропия считается дважды

Exfil-детектор считает энтропию (`calculate_entropy`), и event_handler повторно считает её для вывода в лог:
```python
entropy = calculate_entropy(domain.replace(".", ""))
```

Двойная работа. Лучше передавать энтропию из детектора.

**Severity:** Low (performance).

---

## 7. Pod resolver

**Файл:** `pod_resolver.py`

#### BUG-26: _cache — бесконечный рост

```python
self._cache[cgroup_id] = out
```

Каждый уникальный cgroup_id кэшируется навсегда. Pods создаются и удаляются, cgroup_ids переиспользуются ядром. **Stale cache entries** могут вернуть имя удалённого пода для нового пода с тем же cgroup_id.

**Severity:** High.
- Утечка памяти (хотя и медленная — один dict entry per cgroup_id)
- Некорректная атрибуция DNS-трафика после пересоздания подов

**Fix:** TTL-кэш (например, 5 минут) или периодическая инвалидация.

#### BUG-27: K8s API — список всех подов для поиска одного UID

```python
url = f"https://{host}:{port}/api/v1/pods?limit=500"
```

Запрашивает до 500 подов и ищет линейно. Проблемы:
- O(n) по числу подов на каждый промах кэша
- limit=500 — если подов > 500, поды с UID за пределами первой страницы не будут найдены
- Нет пагинации (field `continue`)
- Нет field selector (`?fieldSelector=metadata.uid=...` — увы, K8s API не поддерживает фильтр по UID, но можно фильтровать другие поля или использовать Watch)

**Severity:** Medium. В кластере с > 500 подами часть подов не будет разрезолвлена.

#### BUG-28: _find_cgroup_path_by_id — обход до 50K директорий

```python
def _find_cgroup_path_by_id(cgroup_id, root=None, max_dirs=50000):
```

Вызывается при каждом промахе кэша, если BPF fd lookup не сработал. Обход 50K директорий в `/sys/fs/cgroup` — тяжёлая операция (десятки мс — секунды), выполняется **в perf callback** (блокирует обработку следующих событий).

**Severity:** High при частых промахах кэша.

#### ISSUE-29: pod_uid — усечение до 12 символов

```python
return uid_part[:12]
```

UUID = 36 символов (32 hex + 4 дефиса). Первые 12 символов = 12 hex = 48 бит. Вероятность коллизии при 1000 подов: ~10^-9. Практически безопасно, но нестандартно.

**Severity:** Low.

---

## 8. Метрики

**Файл:** `metrics.py`

#### BUG-30: Prometheus label cardinality explosion

```python
dns_events_by_process.labels(process=process, client_pod=client_pod, direction=direction_label).inc()
```

Каждая уникальная комбинация (process, client_pod, direction) создаёт отдельный time series в Prometheus. В кластере с 200 подами и 10 процессами на под = 4000 time series только для этой метрики. С pod churn (частое пересоздание) — time series растут без ограничений.

**Последствия:**
- Prometheus OOM или slow scrape
- Grafana dashboards тормозят
- prometheus_client в Python держит все series в памяти

**Severity:** High для production.

**Fix:** Использовать ограниченное число label values (namespace вместо pod name, или bucket по cgroup hierarchy).

#### ISSUE-31: Flask dev server

```python
app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
```

Flask development server не предназначен для production. Одно соединение, нет graceful shutdown, нет Keep-Alive management. Если Prometheus scrape зависнет — /metrics блокируется.

**Severity:** Low для PoC, Medium для production.

---

## 9. Main loop

**Файл:** `main.py`

#### BUG-32: Double print_stats и double close

```python
def on_exit(sig, frame):
    print_stats()              # первый вызов
    os.close(cgroup_fd)        # первый close
    sys.exit(0)

# ...
finally:
    print_stats()              # второй вызов
    os.close(cgroup_fd)        # второй close
```

При Ctrl+C:
1. `KeyboardInterrupt` ловится `except`, попадаем в `finally`
2. Но `signal.SIGINT` → `on_exit` тоже может сработать
3. Зависит от timing: либо только finally, либо signal handler + finally = **двойной вывод stats и двойной close fd**

Double close защищён `except OSError: pass`. Double print_stats — косметический баг (дважды печатает статистику).

**Severity:** Low.

#### ISSUE-33: perf_buffer_poll — нет мониторинга потерь

```python
bpf["events"].open_perf_buffer(_perf_cb)
```

Нет `lost_cb`. Потерянные события (при переполнении кольцевого буфера) не отслеживаются. Нет Prometheus-метрики `dns_events_lost_total`.

**Severity:** Medium. Без этого невозможно оценить полноту мониторинга.

---

## 10. Память — сводка утечек

| Структура | Файл | Тип роста | Ограничение | Оценка при 24ч в кластере |
|-----------|------|-----------|-------------|---------------------------|
| `subdomain_counts[base_domain]` | exfil.py | O(unique base_domains × unique subdomains) | Нет | 10K-100K записей |
| `query_history[(cg, domain)]` | c2.py | O(unique keys), values ≤ 20 | Keys нет | 10K-50K ключей |
| `request_counts[(cg, domain)]` | ip_over_dns.py | O(unique keys в одном окне) | Сброс per window (глобально) | Пик: тысячи ключей |
| `PodResolver._cache` | pod_resolver.py | O(unique cgroup_ids) | Нет | 1K-10K записей, stale |
| `stats["domains"]` | event_handler.py | O(unique domains) | Нет | 10K-100K строк |
| `stats["by_pod"]` | event_handler.py | O(unique pod names) | Нет | Сотни-тысячи |
| Prometheus time series | metrics.py | O(pods × processes × directions) | Нет | Тысячи series |

**Суммарно:** в нагруженном кластере (200+ подов, 24ч uptime) потребление памяти может вырасти на **сотни МБ** без возможности сборки мусора.

**Рекомендация:** ввести LRU-кэш или TTL для всех словарей. Минимальный вариант: периодический сброс (раз в N минут) через отдельный таймер-тред.

---

## 11. Оценка для ВКР и рекомендации

### Что критично исправить для демонстрации

1. **BUG-02 / BUG-17**: Увеличить PAYLOAD_SAMPLE в BPF, иначе LONG_DOMAIN не работает
2. **BUG-14**: Поменять порядок hex/base64 проверок
3. **BUG-18 + BUG-19**: IP-over-DNS rate detection выдаёт заниженные результаты
4. **BUG-03**: Определять query/response по QR-биту, а не по направлению cgroup_skb
5. Добавить whitelist cluster-internal DNS (`.svc.cluster.local`, `.cluster.local`) во все детекторы

### Что важно описать в тексте ВКР как ограничения

- Только UDP/IPv4 (no TCP DNS, no DoH/DoT)
- Payload truncation — влияние на качество парсинга
- Эвристические пороги — без обучения на реальных данных
- Бинарное решение (OR) vs scoring
- Без учёта multi-part TLD
- Память не ограничена при долгой работе

### Что усилит научную часть

- N-gram frequency analysis для exfil (сравнение с моделью легитимного DNS)
- Weighted scoring вместо бинарного OR
- Калибровка порогов на реальном трафике кластера (замер FP/FN rate)
- Сравнение с существующими инструментами (Falco, Tetragon) по coverage/performance

---

## Приложение: карта багов по severity

### High
| ID | Описание |
|----|----------|
| BUG-02 | 64-byte payload → LONG_DOMAIN мёртв |
| BUG-14 | HEX_SUBDOMAIN никогда не сработает |
| BUG-17 | LONG_DOMAIN — мёртвый код (следствие BUG-02) |
| BUG-18 | Tumbling window сбрасывает все ключи |
| BUG-19 | Rate занижается — elapsed от начала окна |
| BUG-11 | query_history keys → OOM |
| BUG-16 | subdomain_counts → OOM |
| BUG-26 | PodResolver cache → stale + OOM |
| BUG-30 | Prometheus cardinality explosion |
| ISSUE-12 | TXT whitelist — 3 домена → массовые FP |
| ISSUE-22 | Бинарный OR → FP flood |

### Medium
| ID | Описание |
|----|----------|
| BUG-01 | IP options не учитываются |
| BUG-03 | direction = egress/ingress ≠ query/response |
| BUG-07 | parse_dns_type — нет bounds check в цикле |
| BUG-10 | Multi-part TLD → неверный base_domain |
| BUG-15 | Энтропия по полному домену, не по поддомену |
| BUG-23 | stats["domains"] → рост |
| BUG-27 | K8s API — limit=500, нет пагинации |
| BUG-28 | cgroup fs walk 50K dirs в perf callback |
| ISSUE-13 | Пороги захардкожены |
| ISSUE-33 | Нет мониторинга потерь perf buffer |

### Low
| ID | Описание |
|----|----------|
| BUG-05 | Неверная проверка size (72 vs 80) |
| BUG-06 | Compression pointer — только backward |
| BUG-20 | NULL_RECORD double fire |
| BUG-21 | dns_answers > 5 на query |
| BUG-32 | Double print_stats |
| ISSUE-08 | Dead code: dns_questions |
| ISSUE-09 | Unused import: get_dns_type_name |
| ISSUE-25 | Двойной расчёт энтропии |
| ISSUE-29 | UID truncation 12 chars |
| ISSUE-31 | Flask dev server |
