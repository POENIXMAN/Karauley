#!/bin/bash

# Скрипт для развертывания DNS Monitor в k3s кластере
# Использование: ./deploy-k3s.sh [путь-к-образу.tar]

set -e

IMAGE_TAR="${1:-ebpfmodule-v1.0.tar}"
HELM_CHART_DIR="./helm"
NAMESPACE="dns-monitor"

echo "🚀 Развертывание DNS Monitor в k3s кластере"
echo "=========================================="

# Проверка наличия образа
if [ ! -f "$IMAGE_TAR" ]; then
    echo "❌ Файл образа не найден: $IMAGE_TAR"
    echo "Использование: $0 [путь-к-образу.tar]"
    exit 1
fi

echo "📦 Загрузка образа в k3s..."
# Попробуем разные способы загрузки
if command -v ctr &> /dev/null; then
    echo "Используем ctr..."
    sudo ctr -n k8s.io images import "$IMAGE_TAR" || {
        echo "⚠️  ctr не сработал, пробуем k3s crictl..."
        sudo k3s crictl load -i "$IMAGE_TAR"
    }
elif command -v k3s &> /dev/null; then
    echo "Используем k3s crictl..."
    sudo k3s crictl load -i "$IMAGE_TAR"
else
    echo "⚠️  Не найден ctr или k3s. Убедитесь, что образ загружен вручную."
fi

echo "✅ Образ загружен"

# Проверка Helm
if ! command -v helm &> /dev/null; then
    echo "❌ Helm не установлен. Установите Helm: https://helm.sh/docs/intro/install/"
    exit 1
fi

# Создание values для k3s
cat > /tmp/k3s-values.yaml <<EOF
image:
  repository: localhost/ebpfmodule
  tag: v1.0
  pullPolicy: Never

global:
  namespace: ${NAMESPACE}

serviceMonitor:
  enabled: false  # Включите после установки Prometheus
EOF

echo "📋 Установка DNS Monitor через Helm..."
helm upgrade --install dns-monitor "$HELM_CHART_DIR" \
  -f /tmp/k3s-values.yaml \
  --namespace "$NAMESPACE" \
  --create-namespace

echo "⏳ Ожидание запуска подов..."
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=dns-monitor \
  -n "$NAMESPACE" \
  --timeout=120s || echo "⚠️  Поды еще не готовы, проверьте: kubectl get pods -n $NAMESPACE"

echo ""
echo "✅ DNS Monitor установлен!"
echo ""
echo "Проверка статуса:"
kubectl get pods -n "$NAMESPACE"
echo ""
echo "Просмотр логов:"
echo "kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=dns-monitor"
echo ""
echo "Метрики:"
echo "kubectl port-forward -n $NAMESPACE svc/dns-monitor 8080:8080"
echo "curl http://localhost:8080/metrics"
