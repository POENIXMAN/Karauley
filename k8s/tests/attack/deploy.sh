#!/bin/bash
#
# Фаза B/C: деплой attack-инструментов в namespace attack.
# Запускается один инструмент за раз. Перед сбором логов — прогрев 2 мин.
#
# Использование:
#   ./deploy.sh ns              # создать namespace attack
#   ./deploy.sh iodine          # задеплоить iodine client
#   ./deploy.sh dnscat2         # задеплоить dnscat2 client
#   ./deploy.sh exfil           # задеплоить DNSExfiltrator client
#   ./deploy.sh stop [iodine|dnscat2|exfil]  # удалить один или все
#   ./deploy.sh status          # статус подов в attack
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="attack"

ensure_ns() {
  kubectl apply -f "${SCRIPT_DIR}/00-namespace.yaml"
}

deploy_iodine() {
  ensure_ns
  kubectl apply -f "${SCRIPT_DIR}/01-iodine-client.yaml"
  echo "Iodine client deployed. Set ATTACK_DOMAIN (edit 01-iodine-client.yaml or set env in deployment)."
  echo "Wait ~2 min warmup, then: bash collect.sh attack_iodine 10m"
}

deploy_dnscat2() {
  ensure_ns
  kubectl apply -f "${SCRIPT_DIR}/02-dnscat2-client.yaml"
  echo "dnscat2 client deployed. First start may take 1–2 min (gem install). Set ATTACK_DOMAIN."
  echo "Wait ~2 min warmup, then: bash collect.sh attack_dnscat2 10m"
}

deploy_exfil() {
  ensure_ns
  kubectl apply -f "${SCRIPT_DIR}/03-dnsexfiltrator-client.yaml"
  echo "DNSExfiltrator client deployed. Set EXFIL_DOMAIN."
  echo "Wait ~2 min warmup, then: bash collect.sh attack_exfil 10m"
}

stop_one() {
  local name="$1"
  case "$name" in
    iodine)
      kubectl delete -f "${SCRIPT_DIR}/01-iodine-client.yaml" --ignore-not-found
      ;;
    dnscat2)
      kubectl delete -f "${SCRIPT_DIR}/02-dnscat2-client.yaml" --ignore-not-found
      ;;
    exfil)
      kubectl delete -f "${SCRIPT_DIR}/03-dnsexfiltrator-client.yaml" --ignore-not-found
      kubectl delete configmap exfil-payload -n "$NS" --ignore-not-found
      ;;
    *)
      echo "Unknown tool: $name (iodine, dnscat2, exfil)"
      exit 1
      ;;
  esac
}

stop_all() {
  stop_one exfil
  stop_one dnscat2
  stop_one iodine
  echo "All attack workloads stopped."
}

status() {
  ensure_ns 2>/dev/null || true
  echo "=== Pods in namespace '$NS' ==="
  kubectl get pods -n "$NS" -o wide 2>/dev/null || true
  echo ""
  echo "=== Deployments ==="
  kubectl get deploy -n "$NS" 2>/dev/null || true
}

case "${1:-}" in
  ns)
    ensure_ns
    echo "Namespace $NS ready."
    ;;
  iodine)
    deploy_iodine
    ;;
  dnscat2)
    deploy_dnscat2
    ;;
  exfil)
    deploy_exfil
    ;;
  stop)
    if [ -n "${2:-}" ]; then
      stop_one "$2"
    else
      stop_all
    fi
    ;;
  status)
    status
    ;;
  *)
    echo "Usage: $0 {ns|iodine|dnscat2|exfil|stop [tool]|status}"
    echo ""
    echo "  ns       — create namespace attack"
    echo "  iodine   — deploy iodine client (set ATTACK_DOMAIN in manifest)"
    echo "  dnscat2  — deploy dnscat2 client (set ATTACK_DOMAIN)"
    echo "  exfil    — deploy DNSExfiltrator client (set EXFIL_DOMAIN)"
    echo "  stop     — remove all attack workloads (or: stop iodine|dnscat2|exfil)"
    echo "  status   — show pods and deployments in attack namespace"
    exit 1
    ;;
esac
