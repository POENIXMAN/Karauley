# Исправление проблем k3s в VMware NAT режиме

## Проблема

В NAT режиме VMware поды не могут подключиться к API серверу через service IP (10.43.0.1:443), что вызывает:
- CoreDNS CrashLoopBackOff
- Metrics-server CrashLoopBackOff
- Prometheus admission webhook проблемы

## Решение

### Шаг 1: Проверьте доступность API сервера

На каждой ноде выполните:

```bash
# Проверьте, доступен ли API сервер через service IP
curl -k https://10.43.0.1:443/api/v1/namespaces

# Проверьте доступность через master IP
curl -k https://192.168.136.133:6443/api/v1/namespaces

# Проверьте маршруты
ip route show
```

### Шаг 2: Настройте k3s для работы с NAT

На master ноде проверьте/настройте k3s:

```bash
# Проверьте текущую конфигурацию
sudo cat /etc/rancher/k3s/config.yaml

# Создайте/отредактируйте конфигурацию
sudo mkdir -p /etc/rancher/k3s
sudo tee /etc/rancher/k3s/config.yaml <<EOF
cluster-cidr: "10.42.0.0/16"
service-cidr: "10.43.0.0/16"
cluster-dns: "10.43.0.10"
# Используйте IP master ноды для API сервера
tls-san:
  - 192.168.136.133
  - k8s-master
EOF

# Перезапустите k3s
sudo systemctl restart k3s
```

### Шаг 3: Исправьте CoreDNS

CoreDNS не может подключиться к API серверу. Исправление:

```bash
# Проверьте текущий ConfigMap CoreDNS
kubectl get configmap coredns -n kube-system -o yaml

# Создайте патч для CoreDNS, чтобы использовать hostNetwork
kubectl patch deployment coredns -n kube-system --type='json' -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/hostNetwork",
    "value": true
  },
  {
    "op": "add",
    "path": "/spec/template/spec/dnsPolicy",
    "value": "ClusterFirstWithHostNet"
  }
]'

# Или пересоздайте с правильными настройками
kubectl delete deployment coredns -n kube-system
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: kube-dns
  template:
    metadata:
      labels:
        k8s-app: kube-dns
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
      - name: coredns
        image: registry.k8s.io/coredns/coredns:v1.11.1
        args:
        - -conf
        - /etc/coredns/Corefile
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 9153
          name: metrics
          protocol: TCP
      volumes:
      - name: config-volume
        configMap:
          name: coredns
          items:
          - key: Corefile
            path: Corefile
EOF
```

### Шаг 4: Исправьте Metrics-server

```bash
# Удалите текущий metrics-server
kubectl delete deployment metrics-server -n kube-system

# Создайте новый с hostNetwork
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metrics-server
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: metrics-server
  template:
    metadata:
      labels:
        k8s-app: metrics-server
    spec:
      hostNetwork: true
      serviceAccountName: metrics-server
      containers:
      - name: metrics-server
        image: registry.k8s.io/metrics-server/metrics-server:v0.7.1
        args:
        - --kubelet-insecure-tls
        - --kubelet-preferred-address-types=InternalIP
        - --cert-dir=/tmp
        - --secure-port=4443
        ports:
        - name: https
          containerPort: 4443
          protocol: TCP
        volumeMounts:
        - name: tmp-dir
          mountPath: /tmp
      volumes:
      - name: tmp-dir
        emptyDir: {}
EOF
```

### Шаг 5: Исправьте Prometheus admission webhook

```bash
# Отключите проблемные webhooks
helm upgrade kube-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --reuse-values \
  --set prometheusOperator.admissionWebhooks.enabled=false

# Или удалите проблемные jobs
kubectl delete job -n monitoring -l app.kubernetes.io/component=admission-webhook
```

### Шаг 6: Альтернативное решение - Используйте hostNetwork для всех системных подов

Если проблемы продолжаются, можно настроить k3s для использования hostNetwork по умолчанию для системных подов.

## Проверка

После исправлений проверьте:

```bash
# Проверьте статус подов
kubectl get pods -n kube-system

# Проверьте CoreDNS
kubectl logs -n kube-system -l k8s-app=kube-dns

# Проверьте Metrics-server
kubectl logs -n kube-system -l k8s-app=metrics-server

# Проверьте доступность API
kubectl get nodes
kubectl get pods --all-namespaces
```

## Альтернативное решение: Использование Bridge сети в VMware

Если проблемы продолжаются, рассмотрите переход на Bridge сеть в VMware:

1. В настройках VM измените сетевой адаптер с NAT на Bridge
2. Настройте статические IP адреса для всех нод
3. Перезапустите k3s кластер

Bridge режим обеспечит прямую связь между VM и хостом, что решит проблемы с маршрутизацией.
