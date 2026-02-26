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
6. **PodResolver** (`pod_resolver.py`) — по `cgroup_id` получает путь cgroup (через bpf fd или обход cgroup fs), из пути извлекает UID пода (kubepods slice), при доступе к API K8s — запрашивает `namespace/name` по UID; для метки **process** читает первый PID из `cgroup.procs` и имя из `/proc/<pid>/comm`. Иначе — fallback на `cgroup_id=...` и `process=unknown`.

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
- Определение источника по cgroup и при возможности — **client_pod** (`namespace/podname`) и **process** (имя из `cgroup.procs` + `/proc/pid/comm`, см. ограничения ниже) для алертов в Grafana.
- Метрики Prometheus: запросы/ответы, подозрительные по типу (C2, EXFIL, TUNNEL), события по pod и по process, число уникальных доменов.
- Эвристическая детекция: C2-подобные паттерны, exfil (энтропия, длинные поддомены), IP-over-DNS (типы записей и объём).
- Деплой одним Helm-чартом (DaemonSet на каждый узел, опционально аннотации под Prometheus).

---

## Что не умеем (ограничения и пол для будущей работы)

- **Только UDP, только IPv4** — TCP DNS (например зоны) и IPv6 не обрабатываются в BPF.
- **Process — только приблизительно** — BPF по cgroup_skb отдаёт только `cgroup_id`, без pid. Имя процесса берётся в userspace: первый PID из `cgroup.procs` и `/proc/<pid>/comm`. Это **не** «процесс, отправивший этот пакет», а один из процессов в cgroup (часто основной процесс контейнера). Для пода с одним процессом обычно совпадает; при нескольких процессах в поде может быть любой из них. Точное соответствие «пакет → процесс» потребовало бы pid в BPF (в cgroup_skb контексте это не всегда доступно).
- **Разрешение pod зависит от cgroup и K8s** — если cgroup не в формате kubepods или нет доступа к API (токен, RBAC), остаётся только `cgroup_id=...` или host. В контейнере часто недоступен `bpf_cgroup_get_fd_by_id` (cgroup namespace); используется обход по cgroup fs (CGROUP_PATH).
- **Детекторы — эвристики** — возможны ложные срабатывания и пропуски; нет ML, нет интеграции с threat intelligence; список «подозрительных» паттернов можно расширять.
- **Только первые 64 байта payload** — длинные ответы/запросы обрезаются; для глубокого анализа нужен больший сэмпл или буферизация (с ограничениями BPF).
- **Один cgroup на инстанс** — привязка к одному пути cgroup; для нескольких cgroup нужны несколько инстансов или доработка логики attach.
- **BCC и зависимости ядра** — требуется BCC (и совместимое ядро); для старых ядер или ограниченных окружений может понадобиться порт на libbpf/CO-RE.

Эти пункты задают нижнюю границу возможностей и направления для развития (TCP DNS, IPv6, точный pid в BPF, более богатые детекторы, полный payload, несколько cgroup, libbpf).

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
- `dns_events_by_process{process, client_pod, direction}` — **process** = имя из cgroup (best-effort: один из процессов в cgroup, не обязательно отправитель пакета), **client_pod** = ns/podname или cgroup_id=...
- `dns_domains_unique`

В Grafana по `client_pod` и `process` можно смотреть, какой pod и какой процесс генерируют DNS и алерты по туннелям. Учитывайте ограничение: **process** — это представительный процесс в cgroup (часто основной контейнер), а не гарантированно отправитель данного пакета (см. раздел «Что не умеем»).

### Как показывать namespace/pod вместо cgroup_id

Метрика `client_pod` может быть в виде **`namespace/podname`** (удобно в дашбордах) или **`cgroup_id=...`** (если разрешение по API недоступно). Чтобы получать имена подов:

1. **Включите RBAC в чарте** — в `helm/values.yaml` должно быть `rbac.enabled: true` (по умолчанию включено). Тогда создаётся ServiceAccount и права на `list/get pods` по API; под монитора получает токен и дергает Kubernetes API, чтобы по UID из cgroup найти `namespace/name` пода.
2. **После `helm upgrade`** поды перезапустятся с новым ServiceAccount. Новые события начнут приходить с `client_pod=default/nginx-xxx` вместо `cgroup_id=24346`. Старые метрики (по cgroup_id) останутся в истории; новые лейблы появятся по мере поступления трафика.
3. Если после включения RBAC по-прежнему видите только `cgroup_id` или `pod_uid:...`: проверьте, что на узле используется cgroup v2 и путь cgroup содержит `kubepods` (формат типа `kubepods-pod<uid>.slice`). В логах пода ошибок API быть не должно.

При необходимости отключить доступ к API (например, из соображений безопасности) задайте `rbac.enabled: false` — тогда будет использоваться только `cgroup_id=...` или `pod_uid:...`.

### Отладка: в метриках по-прежнему «cgroup_id» или «unknown @ cgroup_id=...»

Включите лог резолвера и посмотрите логи пода — там будет причина, по которой cgroup_id не превратился в `namespace/podname`:

1. В `helm/values.yaml` в секции `env` раскомментируйте и установите:
   ```yaml
   env:
     DEBUG_POD_RESOLVER: "1"
   ```
2. Обновите релиз и перезапустите поды: `helm upgrade dns-tunnel-monitor ./helm -n default`
3. Смотрите логи пода (по мере появления DNS-трафика будут строки `[pod_resolver] ...`):
   ```bash
   kubectl logs -n default -l app.kubernetes.io/name=dns-tunnel-monitor -f
   ```

Типичные сообщения и что делать:

| Сообщение | Причина | Действие |
|-----------|--------|----------|
| `KUBERNETES_SERVICE_HOST not set` | Под не в кластере или не видит API | Проверьте, что под запущен в K8s и не переопределяете env |
| `serviceaccount token not mounted` | Нет смонтированного токена | Включите `rbac.enabled: true`, задайте `serviceAccountName` в DaemonSet |
| `API HTTP error: 403` | Нет прав на list/get pods | Проверьте ClusterRole/ClusterRoleBinding и что под использует нужный ServiceAccount |
| `path has no 'kubepods'` | Cgroup не от Kubernetes (системный процесс или другой runtime) | Для таких процессов нормально показывать `cgroup_id=...` |
| `no pod UID in path (expected -pod<uid>.slice)` | Формат cgroup на узле другой (например, cgroup v1 или другой runtime) | Сравните путь в логе с реальной структурой под host: `ls /host-cgroup/` или `ls /sys/fs/cgroup/` на узле |
| `no pod with UID prefix '...' in API list` | UID из cgroup не найден среди подов (лимит 500, или под уже удалён) | Для больших кластеров может понадобиться увеличить limit или пагинацию в коде |

После отладки уберите `DEBUG_POD_RESOLVER` или поставьте пустое значение, чтобы не засорять логи.

### Метрики не видны в Grafana

Grafana показывает только то, что уже есть в Prometheus. Если метрик с префиксом `dns_` нет:

1. **Prometheus должен скрейпить поды.** На подах стоят аннотации `prometheus.io/scrape`, `prometheus.io/port`, `prometheus.io/path` — они работают только если Prometheus настроен на discovery подов с этими аннотациями.
2. **Если у вас Prometheus Operator** (kube-prometheus-stack, prometheus-operator) — включите ServiceMonitor и **обязательно укажите label, по которому ваш Prometheus выбирает ServiceMonitor** (иначе Operator проигнорирует наш). Обычно это `release: <имя релиза Prometheus>`:
   ```bash
   helm upgrade dns-tunnel-monitor ./dns_tunnel_monitor/helm -n default \
     --set prometheus.serviceMonitor.enabled=true \
     --set prometheus.serviceMonitor.labels.release=kube-prometheus-stack
   ```
   Имя релиза смотри в `helm list -A` (релиз со стеком Prometheus/Grafana). В values можно задать `prometheus.serviceMonitor.labels.release: kube-prometheus-stack`.
3. **Проверка в Prometheus:** UI → Status → Targets — должны быть цели для `dns-tunnel-monitor` (порт 9999, path `/metrics`). В разделе Graph/Explore запрос `dns_queries_total` или `{__name__=~"dns_.*"}` должен что-то вернуть.
4. **В Grafana:** Data source — ваш Prometheus. В Explore или в панели запрос, например: `sum(dns_queries_total) by (instance)` или `dns_suspicious_total`.

### Отладка по шагам (если в мониторинге пусто, а в логах пода видны UDP QUERY/RESPONSE)

Под уже получает события (в логах есть `UDP QUERY` / `UDP RESPONSE`), значит метрики в приложении обновляются. Нужно проверить, что Prometheus до них доходит.

1. **Проверить, что `/metrics` отдаёт данные из пода**
   ```bash
   # Взять любой под DaemonSet и запросить /metrics изнутри
   POD=$(kubectl get pods -l app.kubernetes.io/name=dns-tunnel-monitor -n default -o jsonpath='{.items[0].metadata.name}')
   kubectl exec -n default "$POD" -- curl -s http://127.0.0.1:9999/metrics | head -80
   ```
   Должны быть строки `dns_queries_total`, `dns_responses_total` и т.д. Если их нет — проблема в приложении (метрики не экспортируются). Если есть — идём дальше.

2. **Проверить, что ServiceMonitor подхватывается Prometheus**
   У Prometheus Operator есть `serviceMonitorSelector`: он выбирает только те ServiceMonitor, у которых есть нужные labels. Если у вас **kube-prometheus-stack**:
   ```bash
   helm upgrade dns-tunnel-monitor ./dns_tunnel_monitor/helm -n default \
     --set prometheus.serviceMonitor.labels.release=kube-prometheus-stack
   ```
   Имя релиза стека смотрите: `helm list -A | grep prometheus` (часто `kube-prometheus-stack` или `prometheus`). После апгрейда подождите 1–2 минуты и проверьте цели в Prometheus.

3. **Проверить цели в Prometheus**
   Prometheus UI → **Status → Targets**. Найти цели с именем/меткой `dns-tunnel-monitor` или job'ом для этого сервиса. Статус должен быть **UP**. Если целей нет — ServiceMonitor не выбран (вернуться к шагу 2). Если цель **Down** — проверить сеть/порт (под с `hostNetwork: true` слушает на порту узла).

4. **Проверить запрос в Prometheus**
   В Prometheus → **Graph** или **Explore** выполнить: `dns_queries_total` или `{__name__=~"dns_.*"}`. Должны появиться ряды. Если целей UP нет или выборка по времени пустая — метрики в Grafana не появятся.
