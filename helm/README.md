# DNS Monitor Helm Chart

Helm chart для развертывания DNS Tunnel Detector с использованием eBPF в Kubernetes.

## Описание

Этот Helm chart развертывает DaemonSet, который мониторит DNS трафик на всех нодах кластера Kubernetes для обнаружения DNS туннелей и подозрительной активности.

## Требования

- Kubernetes 1.19+
- Helm 3.0+
- Доступ к host network и privileged режим для eBPF
- Prometheus Operator (опционально, для ServiceMonitor)

## Установка

### Базовая установка

```bash
helm install dns-monitor ./helm
```

### Установка с кастомными значениями

```bash
helm install dns-monitor ./helm -f my-values.yaml
```

### Установка в конкретный namespace

```bash
helm install dns-monitor ./helm --namespace dns-monitor --create-namespace
```

## Обновление

```bash
helm upgrade dns-monitor ./helm
```

## Удаление

```bash
helm uninstall dns-monitor
```

## Конфигурация

### Основные параметры

| Параметр | Описание | Значение по умолчанию |
|----------|-----------|----------------------|
| `image.repository` | Docker образ | `localhost/ebpfmodule` |
| `image.tag` | Тег образа | `v1.0` |
| `image.pullPolicy` | Политика загрузки образа | `IfNotPresent` |
| `global.namespace` | Namespace для развертывания | `dns-monitor` |
| `serviceAccount.create` | Создать ServiceAccount | `true` |
| `rbac.create` | Создать RBAC ресурсы | `true` |

### Ресурсы

| Параметр | Описание | Значение по умолчанию |
|----------|-----------|----------------------|
| `daemonset.resources.limits.memory` | Лимит памяти | `512Mi` |
| `daemonset.resources.limits.cpu` | Лимит CPU | `500m` |
| `daemonset.resources.requests.memory` | Запрос памяти | `128Mi` |
| `daemonset.resources.requests.cpu` | Запрос CPU | `100m` |

### Prometheus

| Параметр | Описание | Значение по умолчанию |
|----------|-----------|----------------------|
| `prometheus.enabled` | Включить Prometheus метрики | `true` |
| `prometheus.port` | Порт для метрик | `9999` |
| `prometheus.path` | Путь для метрик | `/metrics` |
| `serviceMonitor.enabled` | Включить ServiceMonitor | `false` |

### Metrics, labels and PromQL

Exposed metrics (all under `/metrics`):

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `dns_queries_total` | Counter | `protocol` | Total DNS queries (UDP/TCP). |
| `dns_responses_total` | Counter | `protocol` | Total DNS responses. |
| `dns_suspicious_total` | Counter | `threat_type` | Suspicious DNS events by threat type. |
| `dns_domains_unique` | Gauge | — | Number of unique domains seen. |
| `dns_events_by_pod_total` | Counter | `client_pod`, `direction` | Events by traffic source pod and direction (query/response). |
| `dns_events_by_process_total` | Counter | `process`, `client_pod`, `direction` | Events by process name and client pod. |

**Labels we use (only what you need):**

- **`client_pod`** — Pod that generated the DNS event (traffic source), e.g. `default/my-app` or `kube-system/coredns-...`. Resolved from cgroup/Kubernetes; we avoid the name `pod` so Prometheus scrape target labels do not overwrite it.
- **`direction`** — `query` (client sent) or `response` (server sent). Use `direction="query"` in PromQL to see who made the request.
- **`protocol`**, **`threat_type`**, **`process`** — As in the table above.

The ServiceMonitor is configured with `metricRelabelings` to **drop** the labels `pod` and `exported_pod` from scraped metrics. So you only see `client_pod` for “which pod”; there is no duplicate or `exported_pod` from earlier conflicts.

**PromQL used in the dashboard:**

- `sum(rate(dns_queries_total[5m])) by (protocol)` — Query rate by protocol.
- `sum(rate(dns_responses_total[5m])) by (protocol)` — Response rate by protocol.
- `sum(rate(dns_suspicious_total[5m])) by (threat_type)` — Suspicious rate by threat type.
- `sum(dns_domains_unique)` — Unique domains (gauge, summed across instances).
- `sum(rate(dns_events_by_pod_total[5m])) by (client_pod)` — Event rate by client pod (all directions).
- `sum(rate(dns_events_by_pod_total{direction="query"}[5m])) by (client_pod)` — Only queries (who made the request).
- `sum(rate(dns_events_by_process_total[5m])) by (process, client_pod)` — Event rate by process and client pod.

### Конфигурация детекции

Все параметры детекции настраиваются в `config` секции:

```yaml
config:
  detection:
    entropy_threshold: 4.0
    max_domain_length: 60
    digit_ratio_threshold: 0.3
    suspicious_types:
      - TXT
      - NULL
      - CNAME
  whitelist:
    domains:
      - google.com
      - microsoft.com
```

## Примеры использования

### Установка с кастомным образом

```yaml
# custom-values.yaml
image:
  repository: my-registry.io/dns-monitor
  tag: v1.2.0
```

```bash
helm install dns-monitor ./helm -f custom-values.yaml
```

### Включение ServiceMonitor для Prometheus Operator

```yaml
# prometheus-values.yaml
serviceMonitor:
  enabled: true
  labels:
    release: prometheus
```

```bash
helm install dns-monitor ./helm -f prometheus-values.yaml
```

### Изменение ресурсов

```yaml
# resources-values.yaml
daemonset:
  resources:
    limits:
      memory: 1Gi
      cpu: 1000m
    requests:
      memory: 256Mi
      cpu: 200m
```

## Проверка установки

```bash
# Проверить статус подов
kubectl get pods -n dns-monitor

# Проверить логи
kubectl logs -n dns-monitor -l app.kubernetes.io/name=dns-monitor

# Проверить метрики
kubectl port-forward -n dns-monitor svc/dns-monitor 9999:9999
curl http://localhost:9999/metrics
```

## Troubleshooting

### Поды не запускаются

1. Проверьте, что у подов есть доступ к host network:
   ```bash
   kubectl describe pod -n dns-monitor
   ```

2. Убедитесь, что используется privileged режим или правильные capabilities

3. Проверьте логи:
   ```bash
   kubectl logs -n dns-monitor -l app.kubernetes.io/name=dns-monitor
   ```

### Master vs worker nodes and Grafana

eBPF sees the **local process** on each node. So:

- **On worker nodes** where your app pods run (e.g. `dns-suspicious-tunnel-rate`), the monitor correctly attributes traffic to those pods (`client_pod` = `default/dns-suspicious-*`).
- **On the master node**, DNS traffic is often handled by CoreDNS; the local process is `coredns`, so you see `client_pod` = `kube-system/coredns-...` (and possibly `default/dns-monitor-...`). This is expected: the actual client pods are visible only on the nodes where they run.

Metrics use the label **`client_pod`** (the pod that generated the DNS event), not `pod`, so Prometheus does not overwrite it with the scrape target’s pod name. In Grafana you should see all traffic sources: `default/dns-suspicious-*`, `kube-system/coredns-*`, `default/dns-monitor-*`, etc. Use the dashboard panel **"DNS queries by client pod only"** to see only client-originated requests (`direction=query`), which reduces CoreDNS in the view.

### Метрики не доступны

1. Проверьте, что Prometheus включен:
   ```yaml
   prometheus:
     enabled: true
   ```

2. Проверьте Service:
   ```bash
   kubectl get svc -n dns-monitor
   ```

## Лицензия

[Укажите лицензию]
