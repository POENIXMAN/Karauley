#!/bin/bash

# Быстрое исправление CoreDNS и Metrics-server для k3s в NAT режиме

set -e

echo "🔧 Исправление CoreDNS и Metrics-server"
echo "========================================"

# Проверка доступа
if ! kubectl cluster-info &>/dev/null; then
    echo "❌ Не могу подключиться к кластеру"
    exit 1
fi

echo ""
echo "1️⃣ Исправление CoreDNS..."

# Удаляем старый
kubectl delete deployment coredns -n kube-system --ignore-not-found=true
sleep 3

# Получаем текущий ConfigMap CoreDNS
COREFILE=$(kubectl get configmap coredns -n kube-system -o jsonpath='{.data.Corefile}')

# Создаем новый с hostNetwork
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
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
      priorityClassName: system-cluster-critical
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      tolerations:
      - key: "CriticalAddonsOnly"
        operator: "Exists"
      - key: "node-role.kubernetes.io/control-plane"
        operator: "Exists"
        effect: "NoSchedule"
      containers:
      - name: coredns
        image: registry.k8s.io/coredns/coredns:v1.11.1
        imagePullPolicy: IfNotPresent
        resources:
          limits:
            memory: 170Mi
          requests:
            cpu: 100m
            memory: 70Mi
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
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            add:
            - NET_BIND_SERVICE
            drop:
            - all
          readOnlyRootFilesystem: true
      volumes:
      - name: config-volume
        configMap:
          name: coredns
          items:
          - key: Corefile
            path: Corefile
EOF

echo "✅ CoreDNS обновлен"

echo ""
echo "2️⃣ Исправление Metrics-server..."

# Удаляем старый
kubectl delete deployment metrics-server -n kube-system --ignore-not-found=true
sleep 3

# Создаем новый с hostNetwork
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metrics-server
  namespace: kube-system
  labels:
    k8s-app: metrics-server
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
      priorityClassName: system-cluster-critical
      hostNetwork: true
      serviceAccountName: metrics-server
      containers:
      - name: metrics-server
        image: registry.k8s.io/metrics-server/metrics-server:v0.7.1
        imagePullPolicy: IfNotPresent
        args:
        - --kubelet-insecure-tls
        - --kubelet-preferred-address-types=InternalIP,Hostname
        - --cert-dir=/tmp
        - --secure-port=4443
        ports:
        - name: https
          containerPort: 4443
          protocol: TCP
        resources:
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: tmp-dir
          mountPath: /tmp
        securityContext:
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
      volumes:
      - name: tmp-dir
        emptyDir: {}
      nodeSelector:
        kubernetes.io/os: linux
EOF

echo "✅ Metrics-server обновлен"

echo ""
echo "3️⃣ Исправление Prometheus webhook..."

# Отключаем webhooks
if helm list -n monitoring 2>/dev/null | grep -q kube-stack; then
    helm upgrade kube-stack prometheus-community/kube-prometheus-stack \
      --namespace monitoring \
      --reuse-values \
      --set prometheusOperator.admissionWebhooks.enabled=false \
      --wait=false 2>/dev/null || echo "⚠️  Webhooks уже отключены или не установлены"
fi

# Удаляем проблемные jobs
kubectl delete job -n monitoring -l app.kubernetes.io/component=admission-webhook --ignore-not-found=true 2>/dev/null || true

echo "✅ Prometheus webhook исправлен"

echo ""
echo "⏳ Ожидание запуска (30 секунд)..."
sleep 30

echo ""
echo "📊 Статус:"
kubectl get pods -n kube-system -l 'k8s-app in (kube-dns,metrics-server)'
echo ""
kubectl get pods -n monitoring 2>/dev/null | head -5 || echo "Monitoring namespace не найден"

echo ""
echo "✅ Готово! Проверьте статус через минуту:"
echo "   kubectl get pods -n kube-system"
echo "   kubectl get pods -n monitoring"
