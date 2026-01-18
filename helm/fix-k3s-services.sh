#!/bin/bash

# Скрипт для исправления проблем с CoreDNS и Metrics-server в k3s с NAT сетью

set -e

echo "🔧 Исправление проблем k3s в NAT режиме VMware"
echo "=============================================="

# Проверка доступа к кластеру
if ! kubectl cluster-info &>/dev/null; then
    echo "❌ Не могу подключиться к кластеру. Проверьте kubeconfig."
    exit 1
fi

echo ""
echo "📊 Текущий статус:"
kubectl get pods -n kube-system | grep -E "coredns|metrics-server" || true

echo ""
echo "🔧 Шаг 1: Исправление CoreDNS..."

# Удаляем текущий CoreDNS
kubectl delete deployment coredns -n kube-system --ignore-not-found=true
sleep 5

# Создаем CoreDNS с hostNetwork
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
spec:
  replicas: 1
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
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
echo "🔧 Шаг 2: Исправление Metrics-server..."

# Удаляем текущий metrics-server
kubectl delete deployment metrics-server -n kube-system --ignore-not-found=true
sleep 5

# Создаем Metrics-server с hostNetwork
kubectl apply -f - <<'EOF'
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
        - --kubelet-preferred-address-types=InternalIP,Hostname,InternalDNS,ExternalDNS,ExternalIP
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
echo "🔧 Шаг 3: Исправление Prometheus webhook..."

# Отключаем проблемные webhooks
if helm list -n monitoring | grep -q kube-stack; then
    echo "Обновляю Prometheus stack..."
    helm upgrade kube-stack prometheus-community/kube-prometheus-stack \
      --namespace monitoring \
      --reuse-values \
      --set prometheusOperator.admissionWebhooks.enabled=false \
      --wait=false || echo "⚠️  Не удалось обновить, возможно уже отключено"
fi

# Удаляем проблемные jobs
kubectl delete job -n monitoring -l app.kubernetes.io/component=admission-webhook --ignore-not-found=true

echo "✅ Prometheus webhook исправлен"

echo ""
echo "⏳ Ожидание запуска подов (30 секунд)..."
sleep 30

echo ""
echo "📊 Финальный статус:"
kubectl get pods -n kube-system | grep -E "coredns|metrics-server" || true

echo ""
echo "✅ Исправления применены!"
echo ""
echo "Проверьте статус через несколько минут:"
echo "  kubectl get pods -n kube-system"
echo "  kubectl get pods -n monitoring"
