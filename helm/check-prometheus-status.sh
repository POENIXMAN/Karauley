#!/bin/bash

# Скрипт для проверки статуса Prometheus stack

NAMESPACE="monitoring"
RELEASE="kube-stack"

echo "🔍 Проверка статуса Prometheus Stack"
echo "====================================="

echo ""
echo "📊 Статус подов:"
kubectl get pods -n "$NAMESPACE" -l "release=$RELEASE"

echo ""
echo "🔍 Проверка проблемных webhooks:"
kubectl get validatingwebhookconfiguration | grep prometheus || echo "✅ Нет проблемных validating webhooks"
kubectl get mutatingwebhookconfiguration | grep prometheus || echo "✅ Нет проблемных mutating webhooks"

echo ""
echo "📋 События в namespace:"
kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -10

echo ""
echo "🔍 Проверка готовности подов:"
READY_PODS=$(kubectl get pods -n "$NAMESPACE" -l "release=$RELEASE" --no-headers | grep -c "Running\|Completed" || echo "0")
TOTAL_PODS=$(kubectl get pods -n "$NAMESPACE" -l "release=$RELEASE" --no-headers | wc -l)

echo "Готово: $READY_PODS из $TOTAL_PODS"

if [ "$READY_PODS" -eq "$TOTAL_PODS" ] && [ "$TOTAL_PODS" -gt 0 ]; then
    echo "✅ Все поды работают!"
else
    echo "⚠️  Некоторые поды еще не готовы. Проверьте логи:"
    echo "   kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=prometheus-operator"
fi

echo ""
echo "📊 Доступ к сервисам:"
echo ""
echo "Grafana:"
echo "  kubectl port-forward -n $NAMESPACE svc/${RELEASE}-grafana 3000:80"
echo ""
echo "Prometheus:"
echo "  kubectl port-forward -n $NAMESPACE svc/${RELEASE}-kube-prometheus-prometheus 9090:9090"
echo ""
echo "Пароль Grafana:"
echo "  kubectl get secret --namespace $NAMESPACE ${RELEASE}-grafana -o jsonpath='{.data.admin-password}' | base64 -d ; echo"
