# DNS Tunnel Monitor (cgroup_skb)

Plug-and-play детекция DNS-туннелей в Kubernetes. Использует **cgroup_skb** . Один pod DaemonSet на узел; источник трафика определяется как `namespace/podname`; метрики Prometheus для Grafana.

## Требования

- Linux, cgroup v2 (например `/sys/fs/cgroup`)
- Root или CAP_BPF, CAP_NET_ADMIN
- BCC (python3-bpfcc / bpfcc-tools)

---

## Как это работает

### Компоненты

1. **BPF (ядро)** — программа в `bpf/dns_cgroup.bpf.c`: привязана к cgroup через **cgroup_skb**, срабатывает на каждый UDP-пакет с портом 53 (egress и ingress). В пользовательское пространство уходит событие: `direction`, `cgroup_id`, сэмпл payload (первые 64 байта DNS).
2. **Loader** (`loader.py`) — загружает BPF, вешает egress/ingress хуки на заданный cgroup, открывает perf buffer; для каждого события парсит DNS (домен, id, флаги, тип записи) и через **PodResolver** переводит `cgroup_id` в `namespace/podname` (или `cgroup_id=...` / host). Вызывает `event_callback` с нормализованным событием.
3. **Event handler** (`event_handler.py`) — обрабатывает каждое событие: обновляет счётчики, метрики Prometheus, передаёт событие в **TunnelDetector**; при подозрении — логирует и инкрементирует `dns_suspicious_total`.
4. **Detectors** (`detectors/`) — эвристики: C2 (подозрительные домены/паттерны), Exfil (высокая энтропия, длинные поддомены), IP-over-DNS (типы записей A/TXT и объём). Результат: флаг «подозрительно» и тип угрозы (C2, EXFIL, TUNNEL).
5. **Metrics** (`metrics.py`) — HTTP на порту 9999: `/healthz`, `/ready`, `/metrics` (Prometheus). Метрики: запросы/ответы, подозрительные по типу угрозы, события по `client_pod`, число уникальных доменов.
6. **PodResolver** (`pod_resolver.py`) — по `cgroup_id` получает fd cgroup, путь в fs, из пути извлекает UID пода (kubepods slice), при наличии доступа к API K8s — запрашивает namespace/name по UID. Иначе — fallback на `cgroup_id=...` или host.

### Где перехватывается трафик

- **Место привязки:** cgroup (путь задаётся через `CGROUP_PATH`; в кластере обычно монтируется host `/sys/fs/cgroup` в контейнер как `/host-cgroup`).
- **Что видно:** весь UDP-трафик на порт 53 (DNS), проходящий через процессы, принадлежащие этому cgroup. Не привязка к сетевому интерфейсу — привязка к **cgroup**. На каждом узле DaemonSet вешает программу на один и тот же cgroup (например корневой cgroup узла), поэтому видны все DNS-запросы/ответы, связанные с этим узлом в контексте этого cgroup.
- **Направления:** egress (исходящие запросы) и ingress (входящие ответы). В событии передаётся `direction`.

---

## Структура кода

| Путь | Назначение |
|------|------------|
| `main.py` / `__main__.py` | Точка входа: загрузка BPF, запуск HTTP метрик, цикл `perf_buffer_poll`, обработка сигналов. |
| `config.py` | Константы: путь к BPF-файлу, переменные окружения (CGROUP_PATH, METRICS_PORT), цвета вывода. |
| `loader.py` | Загрузка BPF из `bpf/dns_cgroup.bpf.c`, attach к cgroup (egress/ingress), парсинг DNS из payload, PodResolver, вызов `event_callback`. |
| `bpf/dns_cgroup.bpf.c` | Код BPF: фильтр UDP:53, чтение `bpf_skb_cgroup_id(ctx)`, сэмпл payload, `perf_submit`. |
| `event_struct.py` | Структура события для ctypes (совместимость с perf buffer). |
| `event_handler.py` | Обработка нормализованного события: статистика, метрики, вызов детекторов, вывод в консоль. |
| `pod_resolver.py` | Разрешение `cgroup_id` → путь cgroup → UID пода → (опционально) запрос K8s API → `namespace/podname`. |
| `dns_parsing.py` | Парсинг домена, типа записи, энтропии из сырых байт DNS. |
| `detectors/` | `tunnel.py` — агрегатор; `c2.py`, `exfil.py`, `ip_over_dns.py` — эвристики C2, exfil, IP-over-DNS. |
| `metrics.py` | Flask + prometheus_client: счётчики/гаужи, HTTP endpoints. |

---

## Что умеем

- Перехват DNS (UDP:53) по cgroup без TC/kprobe.
- Определение источника по cgroup и при возможности — **client_pod** (`namespace/podname`) для алертов в Grafana.
- Метрики Prometheus: запросы/ответы, подозрительные по типу (C2, EXFIL, TUNNEL), события по pod, число уникальных доменов.
- Эвристическая детекция: C2-подобные паттерны, exfil (энтропия, длинные поддомены), IP-over-DNS (типы записей и объём).
- Деплой одним Helm-чартом (DaemonSet на каждый узел, опционально аннотации под Prometheus).

---

## Что не умеем (ограничения и пол для будущей работы)

- **Только UDP, только IPv4** — TCP DNS (например зоны) и IPv6 не обрабатываются в BPF.
- **Нет привязки к процессу (pid/comm)** — только cgroup; для «какой процесс в поде» нужны дополнительные механизмы (например eBPF по pid или парсинг /proc в поде).
- **Разрешение pod зависит от cgroup и K8s** — если cgroup не в формате kubepods или нет доступа к API (токен, RBAC), остаётся только `cgroup_id=...` или host.
- **Детекторы — эвристики** — возможны ложные срабатывания и пропуски; нет ML, нет интеграции с threat intelligence; список «подозрительных» паттернов можно расширять.
- **Только первые 64 байта payload** — длинные ответы/запросы обрезаются; для глубокого анализа нужен больший сэмпл или буферизация (с ограничениями BPF).
- **Один cgroup на инстанс** — привязка к одному пути cgroup; для нескольких cgroup нужны несколько инстансов или доработка логики attach.
- **BCC и зависимости ядра** — требуется BCC (и совместимое ядро); для старых ядер или ограниченных окружений может понадобиться порт на libbpf/CO-RE.

Эти пункты задают нижнюю границу возможностей и направления для развития (TCP DNS, IPv6, pid/comm, более богатые детекторы, полный payload, несколько cgroup, libbpf).

---

## Запуск локально (хост)

```bash
cd /path/to/repo
sudo CGROUP_PATH=/sys/fs/cgroup python3 -m dns_tunnel_monitor
```

В другом терминале: `nslookup google.com` или генерация подозрительного DNS. Метрики: `http://localhost:9999/metrics`.

## Сборка образа

Из корня репозитория:

```bash
docker build -f dns_tunnel_monitor/Dockerfile -t dns-tunnel-monitor:v1 .
```

## Деплой в кластере (Helm)

Деплой только через Helm (без отдельных манифестов kubectl):

```bash
helm install dns-tunnel-monitor ./dns_tunnel_monitor/helm -n default
```

Образ должен быть доступен кластеру (push в registry или загрузка в kind/minikube). Параметры — в `helm/values.yaml` и в [helm/README.md](helm/README.md).

## Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| CGROUP_PATH | Путь к cgroup для attach (в кластере монтируют host `/sys/fs/cgroup` как `/host-cgroup`) | /sys/fs/cgroup |
| METRICS_PORT | HTTP-порт для /healthz, /ready, /metrics | 9999 |

## Метрики (Prometheus)

- `dns_queries_total{protocol}`, `dns_responses_total{protocol}`
- `dns_suspicious_total{threat_type}` — C2, EXFIL, TUNNEL
- `dns_events_by_pod{client_pod, direction}` — **client_pod** = ns/podname или cgroup_id=...
- `dns_domains_unique`

В Grafana по `client_pod` можно смотреть, какой pod генерирует DNS и алерты по туннелям.

### Метрики не видны в Grafana

Grafana показывает только то, что уже есть в Prometheus. Если метрик с префиксом `dns_` нет:

1. **Prometheus должен скрейпить поды.** На подах стоят аннотации `prometheus.io/scrape`, `prometheus.io/port`, `prometheus.io/path` — они работают только если Prometheus настроен на discovery подов с этими аннотациями.
2. **Если у вас Prometheus Operator** (kube-prometheus-stack, prometheus-operator) — он по умолчанию не смотрит на аннотации подов. Нужен **ServiceMonitor**. Включите его и переустановите чарт:
   ```bash
   helm upgrade dns-tunnel-monitor ./dns_tunnel_monitor/helm -n default --set prometheus.serviceMonitor.enabled=true
   ```
   Если ваш Prometheus выбирает ServiceMonitor по label (например `release: prometheus`), добавьте нужный label в `prometheus.serviceMonitor.labels` в values или через `--set`.
3. **Проверка в Prometheus:** UI → Status → Targets — должны быть цели для `dns-tunnel-monitor` (порт 9999, path `/metrics`). В разделе Graph/Explore запрос `dns_queries_total` или `{__name__=~"dns_.*"}` должен что-то вернуть.
4. **В Grafana:** Data source — ваш Prometheus. В Explore или в панели запрос, например: `sum(dns_queries_total) by (instance)` или `dns_suspicious_total`.
