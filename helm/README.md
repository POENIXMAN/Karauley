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
| `prometheus.port` | Порт для метрик | `8080` |
| `prometheus.path` | Путь для метрик | `/metrics` |
| `serviceMonitor.enabled` | Включить ServiceMonitor | `false` |

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
kubectl port-forward -n dns-monitor svc/dns-monitor 8080:8080
curl http://localhost:8080/metrics
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
