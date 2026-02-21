# Plan to investigate userspace / user-namespace (unparseable domain)

Step-by-step commands to see why `bpf_probe_read_user` fails in the container and who is sending DNS.

---

## Prerequisites

- Cluster running, dns-monitor DaemonSet deployed (kprobe mode, not TC).
- `kubectl` and node SSH (or `kubectl exec` to a pod with host PID) for node checks.
- Devmode enabled so eBPF debug lines appear: `daemonset.devmode: true`.

---

## Step 1: Baseline — capture current eBPF debug

See what the pipeline is doing **before** any changes.

```bash
# Pick a dns-monitor pod on a node where you'll test
export NS=default   # or your namespace
export POD=$(kubectl get pods -n $NS -l app.kubernetes.io/name=dns-monitor -o jsonpath='{.items[0].metadata.name}')

# Stream logs; wait for the 30s debug line (steps + read: user_ok=, kernel_ok=)
kubectl logs -n $NS -f $POD -c dns-monitor 2>&1 | grep -E '\[eBPF debug\]|user_ok|kernel_ok'
```

Note:
- `read: user_ok=0, kernel_ok=N` → user read never succeeds, kernel fallback used (wrong data).
- `send_read_user_ok` / `recv_read_user_ok` in `steps:` → user read sometimes works.

Save one full `[eBPF debug]` line for later comparison.

---

## Step 2: Who is sending DNS (processes and namespaces)

Find which processes on the node hit port 53 and what user namespace they’re in.

**2a) From a pod with host PID (e.g. dns-monitor with hostPID):**

```bash
# Processes that have opened UDP port 53 (client side) — run inside dns-monitor pod
kubectl exec -n $NS $POD -c dns-monitor -- nsenter -t 1 -m -u -i -n -- \
  bash -c 'ss -ulnp 2>/dev/null | grep -E ":53|^State"; echo "---"; ss -ulnp 2>/dev/null'
```

Or use `lsof` if available:

```bash
kubectl exec -n $NS $POD -c dns-monitor -- nsenter -t 1 -m -u -i -n -- \
  lsof -i UDP:53 2>/dev/null || true
```

**2b) User namespace of a process (replace PID):**

On the **node** (SSH or `nsenter -t 1` from a privileged pod):

```bash
# Example: check PID 12345
PID=12345
ls -la /proc/$PID/ns/user
readlink /proc/$PID/ns/user
# If different from host's /proc/1/ns/user → process is in a different user namespace (e.g. container)
```

Compare with host init:

```bash
readlink /proc/1/ns/user
```

**2c) List user namespaces on the node:**

```bash
# Requires root on node
ls -la /proc/*/ns/user 2>/dev/null | sort -u
# Or
for p in /proc/[0-9]*; do
  u=$(readlink "$p/ns/user" 2>/dev/null)
  echo "$u ${p##*/}"
done | sort -u
```

If most PIDs share one `user` inode and only a few (e.g. container init) have another → those are in a different user namespace.

---

## Step 3: Test pod **without** user namespace (root, default)

If DNS from this pod parses, the issue is likely the **sender’s** user namespace.

**3a) Create test pod (no user namespace, root):**

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: dns-test-hostuser
  namespace: default
spec:
  securityContext:
    runAsUser: 0
    runAsGroup: 0
  containers:
  - name: dns
    image: busybox:1.36
    command: ["sleep", "3600"]
EOF
```

Wait until Running:

```bash
kubectl wait --for=condition=Ready pod/dns-test-hostuser -n default --timeout=60s
```

**3b) Generate DNS from this pod:**

```bash
kubectl exec -n default dns-test-hostuser -- nslookup google.com
kubectl exec -n default dns-test-hostuser -- nslookup example.com
```

**3c) Check dns-monitor logs (same node):**

Find the node where `dns-test-hostuser` ran:

```bash
kubectl get pod dns-test-hostuser -n default -o wide
```

Then on the dns-monitor pod on **that node**:

```bash
NODE=$(kubectl get pod dns-test-hostuser -n default -o jsonpath='{.spec.nodeName}')
POD=$(kubectl get pods -n $NS -l app.kubernetes.io/name=dns-monitor --field-selector spec.nodeName=$NODE -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n $NS $POD -c dns-monitor --tail=100 2>&1 | grep -E 'google|example|unparseable|QUERY|RESPONSE'
```

- If you see **parsed domains** (e.g. `google.com`, `example.com`) for these queries → user read works when the **sender** is root and not in a user namespace.
- If you still see `<unparseable>` only → problem may be elsewhere (e.g. our pod’s context or node config).

**3d) Optional: confirm user NS of test pod’s process**

```bash
# PID of the process inside dns-test-hostuser that ran nslookup (may need to run nslookup again and quickly check)
# From node (replace NODE_NAME):
kubectl get pod dns-test-hostuser -n default -o jsonpath='{.status.hostIP}'
# SSH to that IP, then:
CONTAINER_PID=$(crictl ps -o pid,id | grep <container-id> | awk '{print $1}')  # or docker/crictl inspect
readlink /proc/$CONTAINER_PID/ns/user
readlink /proc/1/ns/user
# Same inode → same user namespace as host.
```

**3e) Cleanup:**

```bash
kubectl delete pod dns-test-hostuser -n default
```

---

## Step 4: Test pod **with** user namespace (if your cluster supports it)

Only if the cluster has user namespaces for pods enabled (e.g. `hostUsers: false` or userns feature gate). Then create a pod that **uses** a user namespace and send DNS from it; expect unparseable if the hypothesis holds.

```bash
# Example (K8s 1.25+ with UserNamespacesSupport)
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: dns-test-userns
  namespace: default
spec:
  hostUsers: false
  containers:
  - name: dns
    image: busybox:1.36
    command: ["sleep", "3600"]
EOF
kubectl wait --for=condition=Ready pod/dns-test-userns -n default --timeout=60s
kubectl exec -n default dns-test-userns -- nslookup google.com
# Then check dns-monitor logs again — expect unparseable for this pod's traffic
kubectl delete pod dns-test-userns -n default
```

---

## Step 5: Node runtime — is user namespace remapping on?

If the container runtime remaps user namespaces for all containers, every container process will be in a non-init user namespace.

**containerd (node):**

```bash
# On the node
cat /etc/containerd/config.toml | grep -A5 userns
# or
containerd config dump 2>/dev/null | grep -i userns
```

**cri-o (node):**

```bash
cat /etc/crio/crio.conf | grep -i userns
```

**Docker (if used):**

```bash
grep -i userns /etc/docker/daemon.json
```

If userns remap is enabled for the runtime, all containers are in a separate user namespace; then `bpf_probe_read_user` to their memory is expected to fail and the only fix is a different data source (e.g. CoreDNS logs).

---

## Step 6: Compare eBPF debug before vs after tests

After Step 3, capture debug again:

```bash
kubectl logs -n $NS $POD -c dns-monitor --tail=500 2>&1 | grep '\[eBPF debug\]'
```

Compare:
- **Before:** e.g. `read: user_ok=0, kernel_ok=N`, no `send_read_user_ok`.
- **After (only root test pod traffic):** if you see `user_ok > 0` or `send_read_user_ok` / `recv_read_user_ok` when the only DNS was from the test pod → confirms that user read works when the **sender** is not in a user namespace.

---

## Step 7: Optional — 12-byte read test in eBPF

Add a diagnostic in the BPF code: try only **12 bytes** with `bpf_probe_read_user` before the full 256-byte read. If 12 bytes succeed but 256 fail → possible size/page issue; if 12 bytes also fail → user read not allowed for that process (e.g. user namespace).

(Implementation: in `read_dns_payload` or before it, call `bpf_probe_read_user(dst, 12, src)` and increment a new debug counter for success/fail; print that counter from Python. See TRY_READ_USER_FIX.md §2.4.)

---

## Summary checklist

| Step | What you learn |
|------|----------------|
| 1 | Baseline: user_ok vs kernel_ok, which steps pass. |
| 2 | Which processes send DNS and their user namespace (same as host or not). |
| 3 | If DNS from a root, no-userns pod parses → problem is sender’s user namespace. |
| 4 | If DNS from a userns pod stays unparseable → consistent with userns blocking user read. |
| 5 | Whether the node runtime forces user namespaces for all containers. |
| 6 | Before/after comparison of eBPF counters. |
| 7 | Whether even a 12-byte user read fails (solid proof of “no user read allowed”). |

After this you’ll know whether the issue is user namespace of the **sender**, runtime config on the node, or something else; and whether to keep trying runtime/securityContext tweaks or switch to CoreDNS as the source of domains.
