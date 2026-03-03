#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="default"

ACTION="${1:-apply}"

case "$ACTION" in
  apply|start)
    echo "=== Deploying baseline traffic generators ==="
    echo "Namespace: ${NAMESPACE}"
    echo ""

    echo "[1/4] Creating ConfigMaps (domain lists)..."
    kubectl apply -f "${SCRIPT_DIR}/00-configmaps.yaml"

    echo "[2/4] Deploying dnsperf (3 replicas across nodes)..."
    kubectl apply -f "${SCRIPT_DIR}/01-dnsperf.yaml"

    echo "[3/4] Deploying curl-loop (3 replicas across nodes)..."
    kubectl apply -f "${SCRIPT_DIR}/02-curl-loop.yaml"

    echo "[4/4] Deploying k8s-discovery + txt-queries (3 replicas each)..."
    kubectl apply -f "${SCRIPT_DIR}/03-k8s-discovery.yaml"
    kubectl apply -f "${SCRIPT_DIR}/04-txt-queries.yaml"

    echo ""
    echo "=== Waiting for pods to be ready ==="
    kubectl wait --for=condition=available --timeout=120s \
      deployment/dnsperf-baseline \
      deployment/curl-baseline \
      deployment/k8s-discovery-baseline \
      deployment/txt-queries-baseline \
      -n "${NAMESPACE}" 2>/dev/null || true

    echo ""
    echo "=== Baseline pods status ==="
    kubectl get pods -n "${NAMESPACE}" -l app=baseline-traffic -o wide
    echo ""
    echo "=== Node distribution ==="
    kubectl get pods -n "${NAMESPACE}" -l app=baseline-traffic \
      -o custom-columns='NAME:.metadata.name,NODE:.spec.nodeName,STATUS:.status.phase' \
      --sort-by='.spec.nodeName'
    echo ""
    echo "Baseline traffic is running. Use '$0 stop' to clean up."
    ;;

  delete|stop)
    echo "=== Stopping baseline traffic generators ==="
    kubectl delete -f "${SCRIPT_DIR}/04-txt-queries.yaml" --ignore-not-found
    kubectl delete -f "${SCRIPT_DIR}/03-k8s-discovery.yaml" --ignore-not-found
    kubectl delete -f "${SCRIPT_DIR}/02-curl-loop.yaml" --ignore-not-found
    kubectl delete -f "${SCRIPT_DIR}/01-dnsperf.yaml" --ignore-not-found
    kubectl delete -f "${SCRIPT_DIR}/00-configmaps.yaml" --ignore-not-found
    echo ""
    echo "=== Baseline traffic stopped and cleaned up ==="
    ;;

  status)
    echo "=== Baseline pods status ==="
    kubectl get pods -n "${NAMESPACE}" -l app=baseline-traffic -o wide
    echo ""
    echo "=== Node distribution ==="
    kubectl get pods -n "${NAMESPACE}" -l app=baseline-traffic \
      -o custom-columns='NAME:.metadata.name,COMPONENT:.metadata.labels.component,NODE:.spec.nodeName,STATUS:.status.phase' \
      --sort-by='.spec.nodeName'
    ;;

  *)
    echo "Usage: $0 {apply|start|stop|delete|status}"
    echo ""
    echo "  apply/start  - Deploy all baseline traffic generators"
    echo "  delete/stop  - Remove all baseline traffic generators"
    echo "  status       - Show current pod status and node distribution"
    exit 1
    ;;
esac
