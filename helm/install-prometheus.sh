#!/bin/bash

# Скрипт для установки Prometheus + Grafana stack в k3s
# Использование: ./install-prometheus.sh

set -e

NAMESPACE="monitoring"
RELEASE_NAME="prometheus"

echo "📊 Установка Prometheus + Grafana Stack"
echo "========================================"

# Проверка Helm
if ! command -v helm &> /dev/null; then
    echo "❌ Helm не установлен. Установите Helm: https://helm.sh/docs/intro/install/"
    exit 1
fi

# Добавление Helm repo
echo "📦 Добавление Helm репозитория..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Установка kube-prometheus-stack
echo "🚀 Установка kube-prometheus-stack..."
helm upgrade --install "$RELEASE_NAME" prometheus-community/kube-prometheus-stack \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --set grafana.adminPassword=admin \
  --wait \
  --timeout 10m

echo "⏳ Ожидание готовности компонентов..."
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=grafana \
  -n "$NAMESPACE" \
  --timeout=300s || echo "⚠️  Grafana еще не готова"

kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=prometheus \
  -n "$NAMESPACE" \
  --timeout=300s || echo "⚠️  Prometheus еще не готов"

echo ""
echo "✅ Prometheus + Grafana установлены!"
echo ""
echo "📊 Доступ к Grafana:"
echo "   Пароль: admin"
echo "   kubectl port-forward --namespace $NAMESPACE svc/${RELEASE_NAME}-grafana 3000:80"
echo "   Затем откройте http://localhost:3000"
echo ""
echo "📈 Доступ к Prometheus:"
echo "   kubectl port-forward --namespace $NAMESPACE svc/${RELEASE_NAME}-kube-prometheus-prometheus 9090:9090"
echo "   Затем откройте http://localhost:9090"
echo ""
echo "🔍 Проверка статуса:"
kubectl get pods -n "$NAMESPACE"
echo ""
echo "📋 После установки Prometheus, включите ServiceMonitor для DNS Monitor:"
echo "   helm upgrade dns-monitor ./helm \\"
echo "     --set image.repository=localhost/ebpfmodule \\"
echo "     --set image.tag=v1.0 \\"
echo "     --set image.pullPolicy=Never \\"
echo "     --set serviceMonitor.enabled=true \\"
echo "     --set serviceMonitor.labels.release=$RELEASE_NAME"
