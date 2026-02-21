# Kprobe DNS monitor: unparseable domain — context for LLM

Use this as a prompt/context for an LLM when working on the **kprobe-based** DNS tunnel detector. Ignore TC (Traffic Control) mode; focus only on the **kprobe** path and the **&lt;unparseable&gt; domain** issue.

---

## 1. Project and stack

- **Goal**: DNS tunnel / C2 detection in Kubernetes using eBPF (BCC) + Python.
- **Mode in scope**: **Kprobe** . The monitor hooks `udp_sendmsg`, `udp_recvmsg`, and optionally TCP equivalents to capture DNS traffic at the socket layer.
- **Entrypoint**: `dns_analyzer.py` → `dns_monitor.main.main()`.
- **BPF source**: `dns_ebpf_improved.bpf.c`. Events are sent to userspace via **perf buffer** (`BPF_PERF_OUTPUT(events)`).
- **Userspace**: `dns_monitor/` — `loader.py` (load BPF, no TC attach in this context), `main.py`, `event_handler.py` (parse DNS payload, domain extraction, metrics).

---

## 2. Kprobe data flow (relevant to unparseable)

1. **Kernel (eBPF)**  
   - Hooks: `kprobe__udp_sendmsg`, `kretprobe__udp_recvmsg`, etc.  
   - For each DNS packet (port 53), the code:
     - Reads `struct msghdr` → `msg_iter` (kernel `struct iov_iter`).
     - Gets a **data pointer** from `iov_iter` via `get_data_ptr_from_iter()` (handles `ITER_UBUF` and `ITER_IOVEC`; fixed offsets for the union, e.g. 24 primary, 16 fallback).
     - Reads up to 256 bytes of DNS payload with `read_dns_payload()`: **prefers** `bpf_probe_read_user(dst, size, src)`; on failure **fallback** `bpf_probe_read_kernel(dst, size, src)`.
   - Fills `struct dns_event` (pid, tid, comm, saddr, daddr, sport, dport, protocol, direction, dns_id, dns_flags, dns_questions, dns_answers, timestamp_ns, **data_len**, **dns_data[256]**) and submits to perf buffer.

2. **Userspace (Python)**  
   - `event_handler.handle_event()` receives the event.  
   - If `data_len >= 12`, it parses the domain from the DNS payload starting at offset 12 (`parse_dns_name()`).  
   - If parsing fails or `data_len == 0`, the domain is shown as **`<unparseable>`**.

---

## 3. The “unparseable domain” problem

- **Symptom**: In Kubernetes (or in containers), many or all events show **domain = `<unparseable>`** even though DNS traffic is clearly present (correct PID, IPs, dns_id, etc.).
- **Observed in logs**:  
  - eBPF debug shows steps like `send_iter_ok`, `send_ptr_ok`, `ptr_primary_probe_ok`, `send_read_kernel_ok`, `recv_read_kernel_ok`, and **`read: user_ok=0, kernel_ok=40`**.  
  - So: pointer extraction works; full 256-byte read “succeeds” (no error) via **kernel** read; **user** read never succeeds in this environment.
- **Payload content**: When the kernel read is used, the **content** of `dns_data` is wrong: e.g. `byte[12]=0x00` and pointer-like bytes at 2–11. So we are **not** reading the process’s real DNS buffer; we are reading whatever the kernel returns for that (user) VA when using `bpf_probe_read_kernel` (e.g. zero page or another mapping). Hence parsing fails and domain stays `<unparseable>`.

**Root cause (for this K8s setup):**  
- The DNS payload lives in **user-space** (process buffer; `iov_iter` type UBUF/IOVEC).  
- In the container, `bpf_probe_read_user` **fails** for that address (likely user namespace / context).  
- Fallback `bpf_probe_read_kernel` on the same user VA does **not** fault but returns **wrong memory**, so the payload cannot be used for domain parsing.

---

## 4. Debug counters (eBPF → Python)

The BPF code maintains counters that Python reads every 30s and prints to stderr (visible in `kubectl logs`). Use them to see **where** the pipeline fails.

- **Failure reasons** (`ebpf_debug_fail`):  
  - `udp_send_data_ptr_null` — `get_data_ptr_from_iter()` returned NULL (iter type/layout).  
  - `udp_send_probe_read_fail` — both user and kernel read failed.  
  - `udp_recv_no_ptr` — no data pointer in recv path.  
  - `udp_recv_probe_read_fail` — both reads failed in recv.  
  - `union_primary_ok` / `union_fallback_ok` — pointer obtained from union at offset 24 vs 16.

- **Steps** (`ebpf_debug_steps`):  
  - `send_iter_ok`, `send_ptr_ok`, `send_ptr_null` — UDP send: iter read, pointer from iter.  
  - `ptr_primary_probe_ok`, `ptr_fallback_probe_ok` — 2-byte probe at union offset 24 / 16.  
  - `send_read_user_ok`, `send_read_kernel_ok`, `send_read_fail` — payload read (send).  
  - `recv_iter_ok`, `recv_ptr_ok`, `recv_ptr_null`, `recv_read_user_ok`, `recv_read_kernel_ok`, `recv_read_fail` — same for recv.

- **Read outcome** (`ebpf_debug_read`): `user_ok` vs `kernel_ok` — which read path succeeded.

If you see **pointer OK + kernel_ok > 0 but user_ok = 0** and domains still `<unparseable>`, the situation is “kernel read returns wrong content” as above.

---

## 5. Code locations (kprobe path only)

- **BPF**: `dns_ebpf_improved.bpf.c`  
  - `get_data_ptr_from_iter()`, `extract_data_ptr_from_iter_union()` — pointer from `iov_iter` (offsets `IOV_ITER_ITER_TYPE_OFF`, `IOV_ITER_UNION_OFF_PRIMARY`, `IOV_ITER_UNION_OFF_FALLBACK`).  
  - `read_dns_payload()` — `bpf_probe_read_user` then `bpf_probe_read_kernel`.  
  - `kprobe__udp_sendmsg`, `kretprobe__udp_recvmsg`, and TCP hooks — all use the same pointer/read logic.  
  - Maps: `ebpf_debug_fail`, `ebpf_debug_iter_type`, `ebpf_debug_read`, `ebpf_debug_steps`.

- **Python**:  
  - `dns_monitor/loader.py` — loads BPF from `dns_ebpf_improved.bpf.c` (kprobe mode: no TC attach).  
  - `dns_monitor/event_handler.py` — `handle_event()`, `parse_dns_name()`, domain parsing; sets `domain = "<unparseable>"` when parsing fails or `data_len == 0`.  
  - `dns_monitor/main.py` — reads debug maps and prints the eBPF debug line (steps, read user_ok/kernel_ok, etc.).

---

## 6. Hypotheses (why unparseable in K8s)

1. **User read fails in container**  
   User buffer not readable with `bpf_probe_read_user` (user namespace / context). Fallback kernel read returns different memory → wrong payload → unparseable.

2. **`iov_iter` layout / iter_type**  
   Different kernel version or different code path → wrong union offset or unsupported iter type → NULL pointer or wrong pointer → `data_len=0` or garbage. Debug: check `udp_send_data_ptr_null` and iter_type distribution.

3. **Libc / multiple iovecs**  
   Containers (e.g. Alpine/musl) may use multiple iovecs; we only read the first `iov_base`. Partial or wrong data → parse fails.

4. **Different kernel on nodes**  
   `struct iov_iter` layout (union offset) differs between kernels; fixed offsets in eBPF may be wrong for the node kernel.

---

## 7. What to try next (for an LLM or developer)

- Run with **host PID** and/or **host user** namespace (e.g. `runAsUser: 0`, same host `/proc`) and see if `user_ok` becomes non-zero and domains parse.
- Confirm **node kernel** `struct iov_iter` (e.g. `include/linux/uio.h`) and adjust eBPF offsets or add support for the actual iter_type seen in debug.
- Try **small user read** in eBPF (e.g. 12 bytes only) to see if user space is readable at all.
- Consider a **different hook** where DNS is already in kernel memory (e.g. after copy into skb, or XDP/skb-based capture) to avoid reading from the process user buffer in container context.
- Document as limitation: “In Kubernetes, payload read from process buffer fails (user read fails; kernel read returns wrong data); domain-level detection may require host namespace or kernel-level capture.”

