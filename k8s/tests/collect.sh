#!/bin/bash
#
# Сбор JSONL-логов из dns-tunnel-monitor DaemonSet.
#
# JSON идёт в stderr контейнера, но kubectl logs отдаёт оба потока.
# Фильтруем: оставляем только строки, начинающиеся с '{' (валидный JSON).
#
# Использование:
#   ./collect.sh baseline 10m            # Фаза A: собирать 10 минут → results/baseline.jsonl
#   ./collect.sh attack_iodine 10m       # Фаза B: собирать 10 минут → results/attack_iodine.jsonl
#   ./collect.sh mixed_iodine 10m        # Фаза C: собирать 10 минут → results/mixed_iodine.jsonl
#   ./collect.sh baseline 0             # Собирать бесконечно (Ctrl+C для остановки)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
mkdir -p "${RESULTS_DIR}"

LABEL="${1:?Usage: $0 <label> <duration> [namespace] [daemonset-name]}"
DURATION="${2:-10m}"
NAMESPACE="${3:-default}"
DS_NAME="${4:-dns-tunnel-monitor}"

OUTPUT="${RESULTS_DIR}/${LABEL}.jsonl"
TMPDIR_COLLECT="${RESULTS_DIR}/.collect_${LABEL}_$$"
mkdir -p "${TMPDIR_COLLECT}"

cleanup() {
    echo ""
    echo "=== Stopping collectors ==="
    kill $(jobs -p) 2>/dev/null || true
    wait 2>/dev/null || true

    echo "=== Merging logs from all pods ==="
    cat "${TMPDIR_COLLECT}"/*.jsonl 2>/dev/null | sort -t'"' -k4 -n > "${OUTPUT}" || true
    rm -rf "${TMPDIR_COLLECT}"

    TOTAL=$(wc -l < "${OUTPUT}" 2>/dev/null || echo 0)
    SUSPICIOUS=$(grep -c '"suspicious": true' "${OUTPUT}" 2>/dev/null || echo 0)
    CLEAN=$(grep -c '"suspicious": false' "${OUTPUT}" 2>/dev/null || echo 0)

    echo ""
    echo "=== Collection complete ==="
    echo "  Output:      ${OUTPUT}"
    echo "  Total events: ${TOTAL}"
    echo "  Suspicious:   ${SUSPICIOUS}"
    echo "  Clean:        ${CLEAN}"
    echo ""
}

trap cleanup EXIT INT TERM

PODS=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name="${DS_NAME}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)

if [ -z "$PODS" ]; then
    PODS=$(kubectl get pods -n "${NAMESPACE}" -l app="${DS_NAME}" \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
fi

if [ -z "$PODS" ]; then
    PODS=$(kubectl get pods -n "${NAMESPACE}" --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
        | grep "${DS_NAME}" || true)
fi

if [ -z "$PODS" ]; then
    echo "ERROR: No pods found for DaemonSet '${DS_NAME}' in namespace '${NAMESPACE}'"
    echo ""
    echo "Available pods:"
    kubectl get pods -n "${NAMESPACE}" -o wide 2>/dev/null || true
    echo ""
    echo "Hint: pass the correct namespace and DS name:"
    echo "  $0 ${LABEL} ${DURATION} <namespace> <daemonset-name>"
    exit 1
fi

POD_COUNT=$(echo "$PODS" | wc -l | tr -d ' ')
echo "=== DNS Tunnel Monitor Log Collector ==="
echo "  Label:       ${LABEL}"
echo "  Duration:    ${DURATION}"
echo "  Output:      ${OUTPUT}"
echo "  DaemonSet:   ${NAMESPACE}/${DS_NAME}"
echo "  Pods found:  ${POD_COUNT}"
echo ""

for pod in $PODS; do
    NODE=$(kubectl get pod "${pod}" -n "${NAMESPACE}" \
        -o jsonpath='{.spec.nodeName}' 2>/dev/null || echo "unknown")
    echo "  Collecting from ${pod} (node: ${NODE})..."

    POD_FILE="${TMPDIR_COLLECT}/${pod}.jsonl"

    kubectl logs -f "${pod}" -n "${NAMESPACE}" --since=1s 2>/dev/null \
        | grep --line-buffered '^{' \
        | python3 -c "
import sys, json
node = sys.argv[1]
for line in sys.stdin:
    line = line.rstrip()
    if not line or not line.startswith('{'): continue
    try:
        o = json.loads(line)
        o['node'] = node
        print(json.dumps(o, ensure_ascii=False))
    except Exception:
        pass
" "${NODE}" >> "${POD_FILE}" &

done

echo ""

if [ "${DURATION}" = "0" ] || [ "${DURATION}" = "0s" ] || [ "${DURATION}" = "0m" ]; then
    echo "=== Collecting indefinitely (Ctrl+C to stop) ==="
    wait
else
    SECONDS_TOTAL=0
    case "${DURATION}" in
        *m) SECONDS_TOTAL=$(( ${DURATION%m} * 60 )) ;;
        *h) SECONDS_TOTAL=$(( ${DURATION%h} * 3600 )) ;;
        *s) SECONDS_TOTAL=${DURATION%s} ;;
        *)  SECONDS_TOTAL=${DURATION} ;;
    esac

    echo "=== Collecting for ${SECONDS_TOTAL}s (${DURATION}) ==="
    echo ""

    ELAPSED=0
    INTERVAL=30
    while [ $ELAPSED -lt $SECONDS_TOTAL ]; do
        SLEEP_TIME=$INTERVAL
        REMAINING=$(( SECONDS_TOTAL - ELAPSED ))
        if [ $SLEEP_TIME -gt $REMAINING ]; then
            SLEEP_TIME=$REMAINING
        fi
        sleep $SLEEP_TIME
        ELAPSED=$(( ELAPSED + SLEEP_TIME ))

        CURRENT_TOTAL=0
        for f in "${TMPDIR_COLLECT}"/*.jsonl; do
            [ -f "$f" ] && CURRENT_TOTAL=$(( CURRENT_TOTAL + $(wc -l < "$f") ))
        done
        echo "  [${ELAPSED}/${SECONDS_TOTAL}s] Events collected: ${CURRENT_TOTAL}"
    done
fi
