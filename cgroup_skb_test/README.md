# Minimal test: CGROUP_SKB for DNS payload

Standalone test to verify that **attaching to a cgroup** and **reading DNS payload from __sk_buff** works before refactoring the main project.

## Binding and payload (short)

- **Binding:** Python opens a cgroup path (e.g. `/sys/fs/cgroup`) → gets fd → calls `bpf.attach_cgroup("egress", cgroup_fd, BPF_CGROUP_INET_EGRESS)` and same for `"ingress"` with `BPF_CGROUP_INET_INGRESS`. The kernel then runs our BPF for every egress/ingress packet from that cgroup.
- **Payload:** In BPF, `ctx->data` / `ctx->data_end` point to the packet in **kernel memory**. We parse IP (protocol, header length), then UDP (port 53), then copy bytes after the UDP header into the event and submit to perf buffer. So we never touch user memory or iov_iter.

## Unlike TC: no interface, CNI-agnostic

- **TC** attaches to a **network interface** (e.g. `dev ens33`). Whoever owns that interface (e.g. Cilium) owns the qdisc → conflict, not CNI-agnostic.
- **CGROUP_SKB** attaches to a **cgroup** (a path in cgroupfs), not to any NIC. The hook runs when a packet is associated with a socket in that cgroup, regardless of which interface it uses. So no interface binding and **CNI-agnostic** — no conflict with Cilium, Calico, etc. You can run the same DaemonSet on **any cluster** (K3s, kubeadm, EKS) as long as cgroup v2 is mounted at `/sys/fs/cgroup` (or set `CGROUP_PATH`).

## What it does

1. **Binding:** Opens a cgroup path (e.g. `/sys/fs/cgroup`), attaches a BPF program to it for **egress** (and optionally ingress). Any UDP packet to/from port 53 from processes in that cgroup triggers the program.
2. **Payload:** In the BPF program, packet is in kernel memory (`ctx->data` / `data_end`). We parse IP + UDP, check port 53, copy first 64 bytes of payload to a perf buffer and pass to Python.
3. **Python:** Loads the BPF, attaches to cgroup, polls the perf buffer and prints received bytes (hex). If you see DNS-like bytes (e.g. transaction ID, then domain name), the approach works.

## Test on a host/VM first (recommended)

Testing on a plain Linux host (or VM) before the cluster is **very helpful**: no Kubernetes, no Cilium. You only verify that BPF loads, cgroup attach works, and events appear. If it works on the host, the same code is ready for the cluster; if not, you debug without cluster-specific noise. Use the "Run locally" steps below.

## Run locally (as root, on a node with cgroup v2)

On the host or VM, as root:

```bash
cd prototype_improved/cgroup_skb_test
sudo python3 test_cgroup_skb.py
```

In **another terminal** on the same host, generate DNS (e.g. `nslookup google.com` or `dig @8.8.8.8 google.com` to avoid loopback). You should see lines like `[dns] egress cgroup_id=...` in the first terminal. If nothing appears, try `DEBUG=1` or `DEBUG=2` (see "If it fails").

## Run in cluster (Docker + Kubernetes)

### Working solution (DaemonSet: monitor on every node)

Из корня репо:

```bash
docker build -f cgroup_skb_test/Dockerfile -t dns-cgroup-monitor:v1 .
```

Для K3s без registry: `docker save -o dns-cgroup-monitor.tar dns-cgroup-monitor:v1`, скопировать на узел, затем `sudo k3s ctr --namespace=k8s.io images import dns-cgroup-monitor.tar`. Для kind: `kind load docker-image dns-cgroup-monitor:v1`.

Применить DaemonSet:

```bash
kubectl apply -f cgroup_skb_test/k8s/daemonset.yaml
```

Логи (по одному поду на узел):

```bash
kubectl logs -f -l app=dns-cgroup-monitor -n default
```

В логах строки вида `[OUT] pod=cgroup_id=... | domain.name` и при длинных метках — алерт о туннелинге.

### Один под (Deployment, опционально)

Для теста на одном узле можно использовать тот же образ `dns-cgroup-monitor:v1` и манифест `k8s/deployment.yaml`, заменив в нём `image:` на `dns-cgroup-monitor:v1` и убрав `nodeName`, либо оставить старый образ `cgroup-skb-test` (собранный тем же Dockerfile с другим тегом).

**Deploy (with registry):** push image, set `image:` in deployment, then `kubectl apply -f cgroup_skb_test/k8s/deployment.yaml`.

**K3s (no registry):** Same pattern as the main helm chart (`localhost/ebpfmodule:v1.4`). Use a **versioned tag** so K3s doesn’t resolve to `docker.io/library/...` for `:latest`. Deployment uses `image: localhost/cgroup-skb-test:v1` and `imagePullPolicy: IfNotPresent`.

1. **Build and tag** (versioned tag like helm):
   ```bash
   docker build -f cgroup_skb_test/Dockerfile -t localhost/cgroup-skb-test:v1 .
   ```
2. **Save** (`-o` = output file, then image name):
   ```bash
   docker save -o cgroup-skb-test-v1.tar localhost/cgroup-skb-test:v1
   ```
3. Copy tar to node (e.g. `scp cgroup-skb-test-v1.tar user@k8s-master:~/`).
4. **Import** on node (use real path):
   ```bash
   sudo k3s ctr --namespace=k8s.io images import /home/db-user/cgroup-skb-test-v1.tar
   ```
5. **Apply** (delete deployment first if you had a wrong image ref, then apply):
   ```bash
   kubectl delete deployment cgroup-skb-test -n default
   kubectl apply -f cgroup_skb_test/k8s/deployment.yaml
   ```

**Logs** (payload lines):

```bash
kubectl logs -f deployment/cgroup-skb-test -n default
```

Чтобы включить отладку (любой UDP или любой IP), в `deployment.yaml` задайте `DEBUG: "1"` или `DEBUG: "2"` в `env` контейнера и перезапустите под.

**Если логов нет** — см. раздел «Нет событий / loopback» ниже.

**Generate DNS** from another pod or from the node (so traffic is in the same cgroup tree):

```bash
kubectl run -it --rm dns-gen --image=busybox:1.36 --restart=Never -- nslookup google.com
```

The deployment mounts the host cgroup at `/host-cgroup` and sets `CGROUP_PATH=/host-cgroup`, so the test attaches to the node’s cgroup root and sees DNS from the node and from **all pods** (pods live under `kubepods.slice` in the same hierarchy). Each event includes **cgroup_id** — same id = same pod, so you can identify the active or infected pod.

**Kind / Minikube:** load the image into the cluster, e.g. `kind load docker-image cgroup-skb-test:latest` or `minikube image load cgroup-skb-test:latest`.

---

## Expected output (local or cluster)

In another terminal, generate DNS traffic (e.g. `nslookup google.com` or `dig @8.8.8.8 google.com`). You should see lines like:

```
[dns] egress cgroup_id=12345: 00 01 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 ...
```

(DNS header + start of query name.) Each line includes `cgroup_id=<id>`: the same id corresponds to the same pod, so you can see which pod generated the DNS.

## Requirements

- Root (or CAP_BPF, CAP_NET_ADMIN for load and attach).
- cgroup v2 mounted (e.g. `/sys/fs/cgroup`). Check: `mount | grep cgroup2`.
- BCC and kernel that support CGROUP_SKB (4.10+; egress/ingress and __sk_buff fields depend on version).

## If it fails

- **Verifier error:** Packet parsing may need more explicit bounds checks for your kernel. On some kernels `ctx->data` may be L2 (Ethernet); then we’d need to skip 14 bytes before IP.
- **Attach error:** Check cgroup path; try `/sys/fs/cgroup` or `cat /proc/self/cgroup` to see your cgroup. BCC API may differ: some versions use `bpf.load_func("egress", BPF.CGROUP_SKB_EGRESS)` then attach that program; adjust per your BCC.
- **No events:** Ensure DNS traffic goes through a socket in the same cgroup (e.g. run `nslookup` in the same environment where the test runs). If the test runs in a container, attach to the host cgroup root to see host traffic, or to the container’s cgroup to see only that container.

## Нет событий / loopback (No events)

Если контейнер работает, но в логах нет строк с `egress:`/`ingress:`:

1. **Loopback:** На многих ядрах **cgroup_skb не вызывается для трафика через loopback (lo)** так же, как для внешнего. Если `nslookup` и CoreDNS крутятся на одном узле, запрос/ответ могут идти через `lo` и не попадать в хук.
   - **Что сделать:** генерировать DNS с **другого узла** (другой под с `nodeName` отличным от того, где CoreDNS), чтобы трафик шёл по сети, а не по loopback.
   - Либо временно поднять внешний DNS (например `dig @8.8.8.8 google.com`) с пода — трафик до 8.8.8.8 пойдёт через интерфейс, не loopback.

2. **Проверить, что хуки вообще срабатывают:** включите отладочный режим — тогда в лог пойдут **любой UDP** (не только порт 53) или **любой IP** пакет.
   - В поде задайте переменную окружения `DEBUG=1` (любой UDP) или `DEBUG=2` (любой IP), перезапустите под и снова генерируйте трафик (например `nslookup`, или `curl`, или пинг).
   - Если при `DEBUG=1` или `DEBUG=2` появятся строки вида `[udp] egress: ...` / `[ip] ingress: ...`, значит cgroup_skb вызывается, а фильтр по порту 53 или смещениям (L3/L4) можно подправить (например попробовать L2_OFFSET 14 в BPF, если в вашем ядре в skb приходит Ethernet).

3. **Cgroup:** мы цепляемся к корню хоста (`/sys/fs/cgroup`). Поды в K8s живут в поддереве (например `kubepods.slice`), они наследуют программу. Убедитесь, что в под смонтирован именно хостовой cgroup: в deployment уже есть `hostPath: /sys/fs/cgroup` → `/host-cgroup` и `CGROUP_PATH=/host-cgroup`.

4. **Сборка и образ:** после смены кода пересоберите образ и загрузите его в кластер заново (например для K3s: `docker build ...`, `docker save`, `k3s ctr images import`, затем `kubectl rollout restart deployment/cgroup-skb-test`).

**Приоритет — трафик из подов:** цепляемся к корню хоста `/sys/fs/cgroup`. Поды лежат в том же дереве (`kubepods.slice` → …). В событии есть **cgroup_id**: один и тот же id = один под (на egress задаётся, на ingress на части ядер может быть 0). По нему можно определить под-источник DNS.

## Layout (working solution: two files + Docker + DaemonSet)

- **`dns_cgroup_working.bpf.c`** — BPF: egress/ingress, DNS port 53, cgroup_id в событии (отдельный файл для working.py).
- **`working.py`** — Python: загружает BPF из файла (или inline), attach к cgroup, резолвер cgroup_id → pod, вывод и алерт по длинным меткам.
- `Dockerfile` — образ с BCC, `working.py` и `dns_cgroup_working.bpf.c`; ENTRYPOINT `python3 working.py`.
- `docker-compose.yml` — локальный запуск с монтом хостового cgroup (из корня репо: `docker compose -f cgroup_skb_test/docker-compose.yml up --build`).
- `k8s/daemonset.yaml` — **DaemonSet**: монитор на каждом узле, образ `dns-cgroup-monitor:v1`, примонтирован `/sys/fs/cgroup` → `/host-cgroup`.
- `k8s/deployment.yaml` — Deployment (один под, для теста); минимальный тест — `dns_cgroup_minimal.bpf.c` + `test_cgroup_skb.py`.
