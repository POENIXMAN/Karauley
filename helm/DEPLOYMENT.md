# Инструкция по развертыванию в k3s

## 1. Загрузка Docker образа в k3s

k3s использует containerd вместо Docker. Есть несколько способов загрузить образ:

### Способ 1: Использование ctr (containerd CLI)

```bash
# На VM с k3s, загрузите образ
sudo ctr -n k8s.io images import ebpfmodule-v1.0.tar

# Проверьте, что образ загружен
sudo ctr -n k8s.io images list | grep ebpfmodule
```

### Способ 2: Использование k3s crictl

```bash
# Загрузите образ
sudo k3s crictl load -i ebpfmodule-v1.0.tar

# Проверьте образы
sudo k3s crictl images | grep ebpfmodule
```

### Способ 3: Использование docker (если установлен)

```bash
# Загрузите образ
docker load -i ebpfmodule-v1.0.tar

# Переименуйте для k3s (если нужно)
docker tag localhost/ebpfmodule:v1.0 localhost/ebpfmodule:v1.0

# k3s может использовать образы из Docker
```

### Способ 4: Использование локального registry

Если образ уже скопирован на VM:

```bash
# На VM, загрузите образ
sudo ctr -n k8s.io images import ebpfmodule-v1.0.tar

# Или если используете docker
docker load -i ebpfmodule-v1.0.tar
```

## 2. Настройка Helm values для k3s

Создайте файл `k3s-values.yaml`:

```yaml
image:
  repository: localhost/ebpfmodule
  tag: v1.0
  pullPolicy: Never  # Важно! Используем локальный образ

global:
  namespace: dns-monitor

# Остальные настройки по умолчанию
```

## 3. Установка DNS Monitor через Helm

```bash
# Установите Helm chart
helm install dns-monitor ./helm -f k3s-values.yaml

# Или с inline параметрами
helm install dns-monitor ./helm \
  --set image.repository=localhost/ebpfmodule \
  --set image.tag=v1.0 \
  --set image.pullPolicy=Never
```

## 4. Установка Prometheus + Grafana Stack

### Вариант 1: kube-prometheus-stack (рекомендуется)

```bash
# Добавьте Helm repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Установите kube-prometheus-stack
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false

# Получите пароль Grafana
kubectl get secret --namespace monitoring prometheus-grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo

# Пробросьте порт для доступа к Grafana
kubectl port-forward --namespace monitoring svc/prometheus-grafana 3000:80
```

Затем откройте http://localhost:3000 (admin / пароль из команды выше)

### Вариант 2: Prometheus Operator отдельно

```bash
# Добавьте repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Установите Prometheus Operator
helm install prometheus-operator prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace
```

## 5. Включение ServiceMonitor для DNS Monitor

После установки Prometheus, обновите DNS Monitor с включенным ServiceMonitor:

```bash
# Обновите Helm release
helm upgrade dns-monitor ./helm \
  --set image.repository=localhost/ebpfmodule \
  --set image.tag=v1.0 \
  --set image.pullPolicy=Never \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.labels.release=prometheus
```

Или создайте `k3s-values.yaml`:

```yaml
image:
  repository: localhost/ebpfmodule
  tag: v1.0
  pullPolicy: Never

serviceMonitor:
  enabled: true
  labels:
    release: prometheus

global:
  namespace: dns-monitor
```

И установите:

```bash
helm install dns-monitor ./helm -f k3s-values.yaml
```

## 6. Проверка работы

```bash
# Проверьте поды DNS Monitor
kubectl get pods -n dns-monitor

# Проверьте логи
kubectl logs -n dns-monitor -l app.kubernetes.io/name=dns-monitor

# Проверьте метрики
kubectl port-forward -n dns-monitor svc/dns-monitor 8080:8080
curl http://localhost:8080/metrics

# Проверьте Prometheus targets
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090
# Откройте http://localhost:9090/targets
```

## 7. Доступ к Grafana

```bash
# Получите пароль
kubectl get secret --namespace monitoring prometheus-grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo

# Пробросьте порт
kubectl port-forward --namespace monitoring svc/prometheus-grafana 3000:80
```

Логин: `admin`
Пароль: (из команды выше)

## Troubleshooting

### Образ не находится

Если k3s не видит образ:

1. Проверьте, что образ загружен:
   ```bash
   sudo ctr -n k8s.io images list | grep ebpfmodule
   ```

2. Убедитесь, что используете `pullPolicy: Never` в values.yaml

3. Проверьте имя образа:
   ```bash
   # Должно совпадать с тем, что в values.yaml
   sudo ctr -n k8s.io images list
   ```

### Prometheus не видит метрики

1. Проверьте ServiceMonitor:
   ```bash
   kubectl get servicemonitor -n dns-monitor
   kubectl describe servicemonitor -n dns-monitor dns-monitor
   ```

2. Проверьте labels на Service:
   ```bash
   kubectl get svc -n dns-monitor --show-labels
   ```

3. Проверьте Prometheus targets в UI

### Доступ к k3s извне

Если нужно получить доступ к k3s API с другой машины:

```bash
# Скопируйте kubeconfig
sudo cat /etc/rancher/k3s/k3s.yaml

# Используйте на локальной машине
export KUBECONFIG=/path/to/k3s.yaml
```
