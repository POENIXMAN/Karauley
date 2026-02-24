# Minimal test: CGROUP_SKB for DNS payload

Standalone test to verify that **attaching to a cgroup** and **reading DNS payload from __sk_buff** works before refactoring the main project.

## Binding and payload (short)

- **Binding:** Python opens a cgroup path (e.g. `/sys/fs/cgroup`) → gets fd → calls `bpf.attach_cgroup("egress", cgroup_fd, BPF_CGROUP_INET_EGRESS)` and same for `"ingress"` with `BPF_CGROUP_INET_INGRESS`. The kernel then runs our BPF for every egress/ingress packet from that cgroup.
- **Payload:** In BPF, `ctx->data` / `ctx->data_end` point to the packet in **kernel memory**. We parse IP (protocol, header length), then UDP (port 53), then copy bytes after the UDP header into the event and submit to perf buffer. So we never touch user memory or iov_iter.

## Unlike TC: no interface, CNI-agnostic

- **TC** attaches to a **network interface** (e.g. `dev ens33`). Whoever owns that interface (e.g. Cilium) owns the qdisc → conflict, not CNI-agnostic.
- **CGROUP_SKB** attaches to a **cgroup** (a path in cgroupfs), not to any NIC. The hook runs when a packet is associated with a socket in that cgroup, regardless of which interface it uses. So no interface binding and **CNI-agnostic** — no conflict with Cilium, Calico, etc.

## What it does

1. **Binding:** Opens a cgroup path (e.g. `/sys/fs/cgroup`), attaches a BPF program to it for **egress** (and optionally ingress). Any UDP packet to/from port 53 from processes in that cgroup triggers the program.
2. **Payload:** In the BPF program, packet is in kernel memory (`ctx->data` / `data_end`). We parse IP + UDP, check port 53, copy first 64 bytes of payload to a perf buffer and pass to Python.
3. **Python:** Loads the BPF, attaches to cgroup, polls the perf buffer and prints received bytes (hex). If you see DNS-like bytes (e.g. transaction ID, then domain name), the approach works.

## Run locally (as root, on a node with cgroup v2)

```bash
cd prototype_improved/cgroup_skb_test
sudo python3 test_cgroup_skb.py
```

## Run in cluster (Docker + Kubernetes)

**Build image** (from repo root):

```bash
docker build -f cgroup_skb_test/Dockerfile -t cgroup-skb-test:latest .
# If using a registry: tag and push, then set image in k8s/deployment.yaml
```

**Deploy:**

```bash
kubectl apply -f cgroup_skb_test/k8s/deployment.yaml
```

**Logs** (payload lines):

```bash
kubectl logs -f deployment/cgroup-skb-test -n default
```

**Generate DNS** from another pod or from the node (so traffic is in the same cgroup tree):

```bash
kubectl run -it --rm dns-gen --image=busybox:1.36 --restart=Never -- nslookup google.com
```

The deployment mounts the host cgroup at `/host-cgroup` and sets `CGROUP_PATH=/host-cgroup`, so the test attaches to the node’s cgroup root and sees DNS from the node and from pods.

**Kind / Minikube:** load the image into the cluster, e.g. `kind load docker-image cgroup-skb-test:latest` or `minikube image load cgroup-skb-test:latest`.

---

## Expected output (local or cluster)

In another terminal, generate DNS traffic (e.g. `nslookup google.com` or `dig @8.8.8.8 google.com`). You should see lines like:

```
egress: 00 01 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 ...
```

(DNS header + start of query name.)

## Requirements

- Root (or CAP_BPF, CAP_NET_ADMIN for load and attach).
- cgroup v2 mounted (e.g. `/sys/fs/cgroup`). Check: `mount | grep cgroup2`.
- BCC and kernel that support CGROUP_SKB (4.10+; egress/ingress and __sk_buff fields depend on version).

## If it fails

- **Verifier error:** Packet parsing may need more explicit bounds checks for your kernel. On some kernels `ctx->data` may be L2 (Ethernet); then we’d need to skip 14 bytes before IP.
- **Attach error:** Check cgroup path; try `/sys/fs/cgroup` or `cat /proc/self/cgroup` to see your cgroup. BCC API may differ: some versions use `bpf.load_func("egress", BPF.CGROUP_SKB_EGRESS)` then attach that program; adjust per your BCC.
- **No events:** Ensure DNS traffic goes through a socket in the same cgroup (e.g. run `nslookup` in the same environment where the test runs). If the test runs in a container, attach to the host cgroup root to see host traffic, or to the container’s cgroup to see only that container.

## Layout

- `dns_cgroup_minimal.bpf.c` — BPF: egress (and ingress) hook, parse IP/UDP, copy 64 bytes payload to perf buffer.
- `test_cgroup_skb.py` — Python: load BPF, open cgroup, attach, poll and print.
- `Dockerfile` — image with BCC and the test files.
- `k8s/deployment.yaml` — Deployment (1 replica) with host cgroup mount and privileged; optional DaemonSet in comments.
