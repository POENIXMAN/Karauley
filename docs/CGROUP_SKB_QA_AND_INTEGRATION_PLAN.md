# CGROUP_SKB: ответы на вопросы и план интеграции с метриками / Grafana

## 1. Ответы на вопросы

### 1.1. Сможем ли мы корректно сопоставлять поды (cgroup_id → pod)?

**Сейчас:** В логах видно `pod=cgroup_id=20570` — один и тот же `cgroup_id` на всех строках = один под (источник туннеля уже идентифицирован по id).

**Полное сопоставление (cgroup_id → namespace/name):**

- **Да, при условиях:** в `working.py` уже есть резолвер: `bpf(BPF_CGROUP_GET_FD_BY_ID)` → fd → попытка прочитать путь cgroup (readlink/fdinfo) → разбор пути (kubepods...pod&lt;uid&gt;.slice) → при наличии K8s API (serviceaccount в поде) запрос по UID даёт `namespace/name`. На части ядер/окружений fd не даёт путь — тогда остаётся только `cgroup_id`.
- **Практика:** для алертов и метрик достаточно **стабильного идентификатора источника**: один и тот же `cgroup_id` = один под. В метриках можно использовать лейбл `client_pod=cgroup_id=20570` или, при успешном резолве, `client_pod=default/suspicious-pod`. В Grafana группировка по этому лейблу даёт «какой под генерирует трафик».

**Итог:** для детекции туннеля и алертов сопоставление по поду уже есть (по cgroup_id); вывод человеко-читаемого имени пода — best-effort, при желании можно доработать резолвер (например, периодический обход cgroup на ноде).

---

### 1.2. Только трафик из подов на ноде или любой процесс (демоны и т.д.)?

**И то, и другое.** Хук привязан к **cgroup** (корень хоста `/sys/fs/cgroup`). В этот cgroup входят:

- все **поды** (kubepods.slice → …);
- **процессы самого хоста**, не попавшие в поды (systemd, node-agent, sshd и т.д.), — они в корне или в своих slice.

То есть мы видим **весь DNS с ноды**: и из подов, и с хоста. По `cgroup_id` можно отличить: один id для пода, другие — для хостовых задач. В метриках по `client_pod` будет и `host` (или отдельный id), и поды — в Grafana можно фильтровать «только поды» по лейблу (например, исключать `client_pod=host`).

---

### 1.3. Только UDP/IPv4? Хватает ли данных для разных подходов к DNS-детекции?

**Сейчас в коде:** да, только **UDP, IPv4**: в BPF проверяем `proto == IPPROTO_UDP`, порт 53, парсинг с offset 28 (IP 20 + UDP 8), без L2. Payload — первые 64 байта DNS.

**Достаточно ли для детекции туннелей:**

- **Да для типичных эвристик:** длинные/высокоэнтропийные метки, частота запросов, подозрительные домены (C2, exfil) — всё это можно считать по домену и направлению (query/response). Домен и направление у нас есть.
- **Ограничения:**  
  - **TCP DNS (порт 53):** не видим; для туннелей чаще используют UDP, но при желании можно добавить в BPF обработку TCP (сложнее из-за потока).  
  - **IPv6:** не видим; при необходимости — отдельный парсинг в BPF (next header, аналогично порту 53).  
  - **DoH/DoT (443):** не покрываются — это уже не «классический» DNS на 53, нужны другие подходы.

**Расширяемость:** текущий подход даёт «кто (cgroup_id/pod), что (домен), направление (query/response)». Этого хватает для подсчёта метрик (запросы/ответы по поду, подозрительные по типу угрозы) и для любых детекторов, работающих по домену и метаданным (entropy, длина меток, регулярность и т.д.). Добавление TCP/IPv6 — расширение BPF и парсера, без смены архитектуры.

---

## 2. Как сейчас устроены метрики и Grafana (dns_monitor)

- **Сбор метрик:** модуль поднимает HTTP-сервер (Flask) на порту `METRICS_PORT` (по умолчанию 9999), отдаёт Prometheus-формат на `/metrics`.
- **Метрики (Prometheus):**
  - `dns_queries_total{protocol}`, `dns_responses_total{protocol}` — запросы/ответы по протоколу (UDP/TCP).
  - `dns_suspicious_total{threat_type}` — подозрительные (C2, EXFIL, TUNNEL).
  - `dns_domains_unique` — число уникальных доменов.
  - `dns_events_by_process{process, client_pod, direction}`, `dns_events_by_pod{client_pod, direction}` — события по процессу/и по поду (источник трафика).
- **Grafana:** Prometheus скрейпит поды по аннотациям (`prometheus.io/scrape`, `prometheus.io/port`, `prometheus.io/path`); в Grafana дашборды строятся по этим метрикам. Лейбл **`client_pod`** — ключевой для «трафик по подам» (в т.ч. туннель по поду).

Код: `dns_monitor/metrics.py` (объявление метрик + Flask), `dns_monitor/event_handler.py` (вызов `metrics.*.inc()` / `.set()` при обработке события). Запуск HTTP в потоке — в `main.py`.

---

## 3. План работ: одна новая директория, только cgroup_skb

Kprobe **не используем** — от `dns_monitor` берём только нужное (метрики, детекторы, парсинг DNS, структуру кода). Всё собираем в **одну новую директорию** — один модуль, один образ, один способ деплоя.

---

### 3.1. Новая директория (единый модуль)

Предлагаемое имя: **`dns_tunnel_monitor/`** (в корне репо рядом с `dns_monitor`, `cgroup_skb_test`).

Всё живет там: BPF, Python, конфиг, точка входа. Старые `dns_monitor` и `cgroup_skb_test` остаются как референс; в продакшене используется только `dns_tunnel_monitor`.

---

### 3.2. Структура `dns_tunnel_monitor/`

```
dns_tunnel_monitor/
├── __init__.py
├── config.py              # CGROUP_PATH, METRICS_PORT, пути к BPF (из env)
├── main.py                # точка входа: загрузка BPF, HTTP метрик, perf_buffer_poll
├── bpf/
│   └── dns_cgroup.bpf.c   # копия cgroup_skb_test/dns_cgroup_working.bpf.c
├── loader.py              # загрузка BPF, attach к cgroup, open perf buffer
├── event_struct.py        # ctypes-структура события BPF (direction, cgroup_id, payload[64])
├── pod_resolver.py        # cgroup_id → ns/podname (bpf syscall, fd→path, K8s API)
├── dns_parsing.py         # из dns_monitor: parse_dns_name, parse_dns_type, entropy, get_dns_type_name
├── detectors/             # из dns_monitor/detectors (контракт: event dict, без обязательных pid/comm/timestamp_ns)
│   ├── __init__.py
│   ├── tunnel.py
│   ├── c2.py
│   ├── exfil.py
│   └── ip_over_dns.py
├── event_handler.py      # приём нормализованного события → stats, детекторы, метрики, лог
├── metrics.py             # из dns_monitor: Flask + Prometheus
├── devmode.py             # опционально
├── requirements.txt
├── Dockerfile
├── k8s/
│   └── daemonset.yaml     # при необходимости raw YAML (образ, volumes)
├── helm/                  # Helm chart по образцу prototype_improved/helm
│   ├── Chart.yaml
│   ├── values.yaml        # image, daemonset (securityContext, volumes, probes), service, prometheus
│   ├── templates/
│   │   ├── _helpers.tpl
│   │   ├── daemonset.yaml
│   │   ├── service.yaml
│   │   ├── servicemonitor.yaml  # опционально
│   │   ├── configmap.yaml      # если нужен конфиг детекторов
│   │   ├── rbac.yaml
│   │   └── namespace.yaml
│   └── README.md
└── README.md
```

Никакого kprobe, никаких backends — один источник событий: cgroup_skb.

---

### 3.3. Что брать из существующего кода

| Откуда | Что взять |
|--------|-----------|
| **cgroup_skb_test/** | `dns_cgroup_working.bpf.c` → в `dns_tunnel_monitor/bpf/dns_cgroup.bpf.c`; логика загрузки и attach из `working.py` → в `loader.py`; резолвер cgroup_id→pod из `working.py` → в `pod_resolver.py`. |
| **dns_monitor/** | `metrics.py` — целиком (Flask + Prometheus метрики). `event_handler.py` — логику обработки **нормализованного** события (stats, вызов детекторов, inc метрик, вывод в лог); сигнатуру заменить на один общий формат (dict/dataclass). `dns_parsing.py` — целиком. `detectors/` — целиком (c2, exfil, ip_over_dns, tunnel). `config.py` — только нужные константы и env (CGROUP_PATH, METRICS_PORT, цвета для лога). `devmode.py` — по желанию. |

Не тащим: kprobe, `dns_ebpf_improved.bpf.c`, loader/main из dns_monitor.

---

### 3.4. Нормализованный формат события

Один формат, который передаётся из loader в event_handler (и которого ждут детекторы). **Только поля, которые мы реально имеем или можем вычислить** — без pid, comm, timestamp_ns.

- **domain** (str) — распарсенный домен из payload (или `"<unparseable>"`).
- **direction** — `"query"` / `"response"` (egress → query, ingress → response).
- **protocol** — `"UDP"` (пока только UDP).
- **client_pod** (str) — **в приоритете красивый вид `namespace/podname`** (результат pod_resolver через K8s API по cgroup_id → path → pod UID → namespace/name). Если резолв не удался: `cgroup_id=<id>` или `host` для трафика с хоста.
- **cgroup_id** (int) — для логов и внутренней идентификации.
- **dns_id**, **dns_flags**, **dns_answers** — из первых 12 байт payload (для детекторов).
- **dns_type** — из парсера (A, AAAA, TXT, …).

**Не включаем:** timestamp_ns, pid, comm — в cgroup_skb их нет, для текущих детекторов не обязательны. Детекторы должны брать опциональные поля через `event.get('timestamp_ns', 0)` и т.д.; эвристики, завязанные на время/pid (например C2 по регулярности), без timestamp будут ослаблены или отключены.

Loader: из сырого события BPF (direction, cgroup_id, payload) парсит домен через `dns_parsing`, резолвит pod **в вид ns/podname**, собирает этот dict → вызывает `event_handler.handle_event(normalized_event)`.

---

### 3.5. Метрики и Grafana

- Те же имена и лейблы, что в dns_monitor: `dns_queries_total`, `dns_responses_total`, `dns_suspicious_total{threat_type}`, `dns_events_by_pod{client_pod, direction}`, `dns_domains_unique` и т.д.
- В event_handler при обработке нормализованного события — те же вызовы `metrics.*.inc()` / `.set()`. Grafana и Prometheus без изменений; только источник данных — новый модуль.

---

### 3.6. Пошаговый план работ (чеклист)

1. **Создать директорию и базовые файлы**
   - Создать `dns_tunnel_monitor/`, `dns_tunnel_monitor/bpf/`, `dns_tunnel_monitor/detectors/`, `dns_tunnel_monitor/k8s/`.
   - Скопировать `cgroup_skb_test/dns_cgroup_working.bpf.c` → `dns_tunnel_monitor/bpf/dns_cgroup.bpf.c`.
   - Добавить `config.py` (CGROUP_PATH, METRICS_PORT, путь к BPF), `__init__.py`.

2. **Перенести и упростить метрики и парсинг**
   - Скопировать `dns_monitor/metrics.py` в `dns_tunnel_monitor/metrics.py`.
   - Скопировать `dns_monitor/dns_parsing.py` в `dns_tunnel_monitor/dns_parsing.py`.

3. **Перенести детекторы**
   - Скопировать `dns_monitor/detectors/` в `dns_tunnel_monitor/detectors/` (c2, exfil, ip_over_dns, tunnel, __init__.py). Поправить импорты на `dns_tunnel_monitor.dns_parsing` и т.д.

4. **Резолвер пода и структура события**
   - Реализовать `pod_resolver.py`: cgroup_id → **ns/podname** в приоритете (bpf syscall → fd → path → pod UID → K8s API namespace/name). Fallback: `cgroup_id=<id>` или `host`.
   - Описать в `event_struct.py` ctypes-структуру события BPF (direction, _pad, cgroup_id, payload[64]).

5. **Loader (cgroup_skb)**
   - В `loader.py`: чтение `bpf/dns_cgroup.bpf.c`, компиляция BCC, open cgroup по CGROUP_PATH, attach egress/ingress, open perf buffer. В callback: распарсить payload (домен, dns_id, dns_flags, dns_answers, dns_type), вызвать pod_resolver, собрать нормализованный dict → передать в callback (event_handler.handle_event).

6. **Event handler**
   - Реализовать `event_handler.py`: приём одного аргумента — нормализованное событие (dict). Обновление stats, вызов `tunnel_detector.analyze(event_data)`, инкремент метрик (как в dns_monitor), вывод строки в лог и алерт при is_suspicious.

7. **main.py**
   - Читать config (CGROUP_PATH, METRICS_PORT). Запустить HTTP метрик в потоке (как в dns_monitor). Вызвать loader с callback=event_handler.handle_event. Цикл `bpf.perf_buffer_poll()`.

8. **Образ и K8s**
   - Написать `Dockerfile`: базовый образ с BCC, копирование `dns_tunnel_monitor/`, ENTRYPOINT `python3 -m dns_tunnel_monitor`. Обновить/скопировать `k8s/daemonset.yaml` (образ, CGROUP_PATH, метрики 9999, volumes). При необходимости Service с аннотациями для Prometheus.

9. **Helm chart**
   - Создать `dns_tunnel_monitor/helm/` по образцу `prototype_improved/helm`: Chart.yaml, values.yaml (image, daemonset с hostNetwork, hostPID, privileged, volumes: host-cgroup, sys, modules, usr-src; service port 9999; prometheus annotations; probes /healthz, /ready). Шаблоны: daemonset.yaml, service.yaml, _helpers.tpl, при необходимости servicemonitor.yaml, rbac.yaml, namespace.yaml. В values — CGROUP_PATH, METRICS_PORT, образ по умолчанию (например dns-tunnel-monitor:v1).

10. **Проверка**
   - Локально: `sudo python3 -m dns_tunnel_monitor` (cgroup v2), генерация DNS, проверка логов и алертов.
   - В кластере: деплой через Helm или `kubectl apply -f k8s/daemonset.yaml`, генерация подозрительного DNS из пода, проверка метрик на `/metrics` и в Grafana по `client_pod` (должен быть ns/podname где возможно) и `threat_type`.

11. **README**
    - Назначение модуля, требования (cgroup v2, root), сборка образа, деплой (kubectl и Helm), переменные окружения, метрики и Grafana.

После этого модуль готов: единая директория, только cgroup_skb, client_pod в виде ns/podname, без pid/comm/timestamp_ns в формате события, с Helm chart как в `prototype_improved/helm`.
