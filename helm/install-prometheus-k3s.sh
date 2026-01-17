#!/bin/bash

# Скрипт для установки Prometheus + Grafana stack в k3s
# Исправляет проблемы с webhook admission

set -e

NAMESPACE="monitoring"
RELEASE_NAME="prometheus"

echo "📊 Установка Prometheus + Grafana Stack для k3s"
echo "=============================================="

# Проверка Helm
if ! command -v helm &> /dev/null; then
    echo "❌ Helm не установлен. Установите Helm: https://helm.sh/docs/intro/install/"
    exit 1
fi

# Добавление Helm repo
echo "📦 Добавление Helm репозитория..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Проверка существующей установки
if helm list -n "$NAMESPACE" | grep -q "$RELEASE_NAME"; then
    echo "⚠️  Prometheus уже установлен. Удаляю старую установку..."
    helm uninstall "$RELEASE_NAME" -n "$NAMESPACE" || true
    # Ждем удаления
    sleep 10
fi

# Удаление проблемных ресурсов, если они остались
echo "🧹 Очистка проблемных ресурсов..."
kubectl delete validatingwebhookconfiguration prometheus-operator-admission 2>/dev/null || true
kubectl delete mutatingwebhookconfiguration prometheus-operator-admission 2>/dev/null || true
kubectl delete job -n "$NAMESPACE" -l app.kubernetes.io/name=kube-prometheus-stack,app.kubernetes.io/component=admission-webhook 2>/dev/null || true

# Установка с правильными настройками для k3s
echo "🚀 Установка kube-prometheus-stack с настройками для k3s..."
helm upgrade --install "$RELEASE_NAME" prometheus-community/kube-prometheus-stack \
  --namespace "$NAMESPACE" \
  --create-namespace \
  -f prometheus-k3s-values.yaml \
  --wait \
  --timeout 15m

echo "⏳ Ожидание готовности компонентов..."
sleep 30

# Проверка статуса
echo ""
echo "📊 Статус установки:"
kubectl get pods -n "$NAMESPACE"

echo ""
echo "⏳ Ожидание готовности подов (это может занять несколько минут)..."
kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=grafana \
  -n "$NAMESPACE" \
  --timeout=600s || echo "⚠️  Grafana еще не готова, проверьте: kubectl get pods -n $NAMESPACE"

kubectl wait --for=condition=ready pod \
  -l app.kubernetes.io/name=prometheus \
  -n "$NAMESPACE" \
  --timeout=600s || echo "⚠️  Prometheus еще не готов, проверьте: kubectl get pods -n $NAMESPACE"

echo ""
echo "✅ Prometheus + Grafana установлены!"
echo ""
echo "📊 Доступ к Grafana:"
echo "   Логин: admin"
echo "   Пароль: admin"
echo "   kubectl port-forward --namespace $NAMESPACE svc/${RELEASE_NAME}-grafana 3000:80"
echo "   Затем откройте http://localhost:3000"
echo ""
echo "📈 Доступ к Prometheus:"
echo "   kubectl port-forward --namespace $NAMESPACE svc/${RELEASE_NAME}-kube-prometheus-prometheus 9090:9090"
echo "   Затем откройте http://localhost:9090"
echo ""
echo "🔍 Проверка логов (если что-то не работает):"
echo "   kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=prometheus-operator"
echo "   kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp'"
