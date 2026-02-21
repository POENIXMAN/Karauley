# Refactoring estimate: BPF_PROG_TYPE_CGROUP_SKB

How much work to switch from kprobe (udp_sendmsg/recvmsg + iov_iter) to CGROUP_SKB for reading DNS payload from kernel memory (skb).

---

## Where binding happens and how we get the payload

**Binding** = attaching the loaded BPF program to a **cgroup**. The kernel then runs our program for every packet (egress or ingress) from any socket that belongs to that cgroup or its descendants.

1. **Where:** In userspace we open a cgroup path (e.g. `/sys/fs/cgroup` for cgroup v2 unified root, or `/sys/fs/cgroup/kubepods.slice` to see only Kubernetes pods) and get an **fd**:
   - `cgroup_fd = os.open("/sys/fs/cgroup", os.O_RDONLY)` (or the chosen path).
2. **Attach:** We call the BPF attach API with that fd and the program fd:
   - Egress: attach program to `cgroup_fd` with type `BPF_CGROUP_INET_EGRESS` → our `egress(ctx)` runs on every **outgoing** packet from that cgroup.
   - Ingress: attach with `BPF_CGROUP_INET_INGRESS` → our `ingress(ctx)` runs on every **incoming** packet.
3. **Payload:** Inside the program, `ctx` is `struct __sk_buff *`. The packet bytes are in kernel memory:
   - `ctx->data` = pointer to start of (linear) packet; in cgroup skb this is typically the **L3 (IP) header**.
   - `ctx->data_end` = end of accessible data. We must bounds-check every read (verifier requirement).
   - We parse: IP header (min 20 bytes) → get `ihl`, `protocol`, saddr, daddr; skip to UDP (8 bytes) → get sport, dport; if port 53, then **payload** starts at `data + ip_hdr_len + 8`. We copy that into a small buffer and submit to a perf buffer (or map). So the payload is read from **kernel skb memory**, not from user space — no iov_iter, no probe_read_user.

So: **binding** = open cgroup → attach(prog_fd, cgroup_fd, EGRESS/INGRESS). **Payload** = parse L3/L4 from `ctx->data`/`data_end`, then copy the bytes after the UDP header.

---

## What changes

| Layer | Current (kprobe) | CGROUP_SKB |
|-------|------------------|------------|
| **Entry** | kprobe__udp_sendmsg, kretprobe__udp_recvmsg, + TCP | Two programs: cgroup_skb/egress, cgroup_skb/ingress |
| **Context** | pt_regs, sock, msghdr → iov_iter → user pointer | __sk_buff: data, data_end, (optional) local_ip4, remote_ip4, local_port, remote_port |
| **Payload** | Read from user VA (fails in container) | Read from skb (kernel memory) → reliable |
| **Metadata** | pid, comm, cgroup_id, netns from current/sock | cgroup_id from bpf_get_current_cgroup_id(); pid/comm not in __sk_buff (or via sk→owner if available) |
| **Attachment** | BCC attach_kprobe | BCC attach to cgroup path (e.g. /sys/fs/cgroup or kubepods) |

---

## 1. BPF (new program)

**Remove:** All iov_iter logic (~400 lines): get_data_ptr_from_iter, extract_data_ptr_from_iter_union, read_dns_payload, IOV_ITER_* offsets, recv_ctx_map, TCP send/recv context, and the kprobe/kretprobe hooks.

**Add:**
- Two entry points: `int ingress(struct __sk_buff *ctx)` and `int egress(struct __sk_buff *ctx)` (or one with direction from a map).
- Packet parsing (verifier-safe):
  - __sk_buff->data points to L3 (IP) in cgroup skb; bounds check `data + 20 <= data_end`, read IP header (protocol, saddr, daddr, ihl).
  - If protocol != IPPROTO_UDP, return 1 (pass).
  - Bounds check for UDP header (8 bytes); read sport, dport; if port != 53, return 1.
  - Payload at `data + ip_hdr_len + 8`, length = packet_len - ip_hdr_len - 8; copy min(256, payload_len) into event.dns_data.
- Fill event: saddr, daddr, sport, dport (from __sk_buff or from parsed IP/UDP), cgroup_id = bpf_get_current_cgroup_id(), direction = egress→query / ingress→response, protocol = 17 (UDP), pid/comm = 0 (or leave as-is if we later get from sk).
- Same struct dns_event, same BPF_PERF_OUTPUT(events), same parse_dns_header if you want dns_id/flags in kernel.
- Debug maps: can be simplified (no ptr_null/iter_type; maybe just “packets seen”, “payload copied”, “parse fail”).

**Rough size:** 250–400 lines of new C (replacing ~600+ lines of kprobe/iov_iter/TCP). First version UDP-only; TCP would require handling stream (multiple skbs or reassembly), so add another 100–200 lines if needed.

**Risks:** Non-linear skb (data in fragments) — then data_end - data might be less than full packet; need to handle or skip. Some kernels expose local_ip4/remote_ip4 etc. on __sk_buff, so you might avoid full IP parse; if not, parsing is mandatory and must be bounds-checked every step for verifier.

---

## 2. Python loader

**Current:** Load one BPF file, no attach (BCC auto-attaches kprobe by name).

**New:**
- Load BPF with the new C file (two programs: ingress + egress).
- Resolve cgroup path:
  - cgroup v2: e.g. `/sys/fs/cgroup` (unified) or `/sys/fs/cgroup/kubepods.slice` to see all pods; or discover pod cgroups for per-pod attach (more complex).
  - cgroup v1: e.g. `/sys/fs/cgroup/net_cls` or similar depending on setup.
- Open cgroup fd (open(path, O_RDONLY)) and call BCC attach: e.g. `bpf.attach_cgroup(prog_egress, cgroup_fd, BPF_CGROUP_INET_EGRESS)` and same for ingress. Exact API depends on BCC (might be `attach_raw_socket`-style or `attach_cgroup_program`).
- If BCC doesn’t expose cgroup attach cleanly, use libbpf or raw bpf() syscall (bpf_prog_attach with BPF_CGROUP_INET_EGRESS/INGRESS).

**Rough size:** 40–80 lines (path discovery + attach both programs). More if you support both cgroup v1 and v2 or per-pod attach.

---

## 3. Event structure and userspace

- **struct dns_event:** Keep as-is. pid/comm can be 0 for “cgroup-only” source; pod resolution still works via cgroup_id (you already resolve pod from cgroup_id/pid in Python).
- **event_handler.py:** No change or minimal (e.g. treat pid=0 as “from cgroup hook”).
- **Pod resolution:** Still by cgroup_id; cgroup path in Python can be read from /proc/self/cgroup or the same path you used for attach. No change to pod_resolver logic.

---

## 4. What stays the same

- Perf buffer and Python callback (handle_event).
- Event struct layout (so no change to event_struct.py or parsing).
- Detectors, metrics, CoreDNS fallback doc — unchanged.
- Helm/K8s: same DaemonSet; need to mount cgroup fs if not already (often already there) and possibly pass cgroup path via env.

---

## 5. Summary table

| Component | Effort | Notes |
|-----------|--------|--------|
| **New BPF (C)** | **Medium–High** | New file, ~250–400 lines; UDP parsing + event fill; no iov_iter; TCP optional and extra. |
| **Loader (Python)** | **Low–Medium** | 40–80 lines; cgroup path + attach two progs; BCC API may require a quick check. |
| **Event / handler** | **None–Minimal** | Same event; maybe pid=0 handling. |
| **Pod resolution** | **None** | Still cgroup_id → pod. |
| **Testing** | **Medium** | Different code path; test on same node (cgroup v1 vs v2, path). |

**Total:** One focused developer, roughly **2–5 days** for UDP-only CGROUP_SKB path and integration, plus tests and edge cases (non-linear skb, cgroup path on different distros). TCP adds another 1–2 days if you want parity.

---

## 6. Quick win vs full parity

- **Quick win:** New BPF file + loader attach to root cgroup (e.g. `/sys/fs/cgroup`), UDP only, direction from egress/ingress. Gets you correct DNS payload in Python for detection with minimal refactor and no kprobe/iov_iter.
- **Full parity:** Re-add TCP (stream handling in CGROUP_SKB is harder), optional pid/comm via sk if available, and/or per-pod cgroup attach for finer-grained control. That’s the extra 1–3 days.
