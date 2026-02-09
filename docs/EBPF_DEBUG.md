# eBPF debug: why data_len=0 in containers

eBPF runs in the kernel, so you don’t see C `printf` in container logs. We added a **failure counter map** that the kernel updates and Python reads; the result is printed to **stderr** (visible with `kubectl logs <pod>`).

## What you’ll see

Every 30 seconds, if any eBPF failure occurred, a line like:

```text
[eBPF debug] data_len=0 failures: udp_send_data_ptr_null=42, udp_recv_no_ptr=10
```

So you can see **which** failure path is taken without mounting `trace_pipe` or debugfs.

## Reason codes (match C `EBPF_DEBUG_*`)

| Counter | Meaning |
|--------|---------|
| `udp_send_iter_read_fail` | `bpf_probe_read_kernel(&iter, ...)` failed in `udp_sendmsg` |
| `udp_send_data_ptr_null` | `get_data_ptr_from_iter()` returned NULL in `udp_sendmsg` (iter type/layout) |
| `udp_send_probe_read_fail` | `bpf_probe_read_user(dns_data, ...)` failed in `udp_sendmsg` |
| `udp_recv_no_ptr` | No data pointer in `udp_recvmsg` (kprobe or get_data_ptr failed) |
| `udp_recv_probe_read_fail` | `bpf_probe_read_user` failed in `udp_recvmsg` kretprobe |

## What to do

- **High `udp_send_data_ptr_null` or `udp_recv_no_ptr`**  
  Usually means the kernel’s `struct iov_iter` layout doesn’t match what the eBPF code expects (e.g. different kernel version). The code uses fixed offsets (`IOV_ITER_ITER_TYPE_OFF`, `IOV_ITER_UNION_OFF`) and only handles `ITER_UBUF` and `ITER_IOVEC`. On your kernel, the iter might be a different type or the union might be at a different offset. Check `include/linux/uio.h` on the node (or the kernel you build against) and adjust the eBPF offsets or add support for the actual iter type.

- **High `*_probe_read_fail`**  
  The pointer was valid but the read failed (e.g. page not present, bad address). Less common; can depend on timing or container/net namespace.

- **On a VM it works, in the container it doesn’t**  
  Same eBPF binary can run on a different kernel in the container’s node; or the network path (who sends DNS) differs so a different hook/code path is used. Use the counters to see which path fails in the container.

## Implementation

- **C**: Map `ebpf_debug_fail` (BPF_ARRAY, key = reason 1..5, value = u64). At each place we set `event.data_len = 0` or skip a valid read, we call `ebpf_debug_fail.increment(REASON_CODE)`.
- **Python**: Daemon thread every 30s reads `bpf["ebpf_debug_fail"]` and, if any count > 0, prints one line to stderr.

No `trace_pipe` or debugfs mount is required; everything appears in normal container logs.

---

## Hypotheses: why it works on a VM but fails in K8s

Below are the main hypotheses, in order of likelihood. The **eBPF debug counters** tell you which one is happening (e.g. high `udp_send_data_ptr_null` → #1 or #2).

### 1. Different kernel on nodes → wrong `iov_iter` layout (most likely)

- **VM**: One kernel (e.g. 5.15). The eBPF uses **fixed offsets** for `struct iov_iter` (`IOV_ITER_ITER_TYPE_OFF=0`, `IOV_ITER_UNION_OFF=16`). On that kernel the layout matches, so `get_data_ptr_from_iter()` works.
- **K8s nodes**: Often a **different** kernel (e.g. 5.4, 5.10, 6.1). Layout of `iov_iter` (and the union where `ubuf`/`__iov` live) **changed between versions**. With the wrong offset we read garbage, get wrong `iter_type` or wrong pointer → we return NULL → `data_len=0`.
- **Check**: Compare kernel versions on VM vs node (`uname -r`). If they differ, treat this as the prime suspect and fix by using the **node** kernel’s `include/linux/uio.h` (or BTF) to get correct offsets / layout for that kernel.

### 2. Different `iter_type` in K8s (we only handle UBUF and IOVEC)

- **VM**: Processes (systemd-resolve, browsers, etc.) end up with `ITER_UBUF` or `ITER_IOVEC` when calling `sendmsg()`, so our code path works.
- **K8s**: In containers, **who** sends DNS changes: Python (dns-monitor), `nslookup`, CoreDNS, often with different libc (e.g. **musl** in Alpine) or different socket usage. The kernel may build an `iov_iter` with another type (e.g. `ITER_KVEC`, `ITER_BVEC`, or a newer type). We **only** handle `ITER_UBUF` (0) and `ITER_IOVEC` (1); anything else returns NULL → `data_len=0`.
- **Check**: If debug shows high `udp_send_data_ptr_null`, add a counter in eBPF for “unknown iter_type” (the value we read at `IOV_ITER_ITER_TYPE_OFF`) and log it from Python. That shows the real type on the failing path.

### 3. Libc / syscall path (musl vs glibc)

- **Containers** often use **Alpine (musl)**. `sendmsg()` / `writev()` may be implemented differently than glibc: different way to set up `msghdr` / `iovec`, or multiple small iovecs. The kernel then might use `ITER_IOVEC` with **multiple** segments; we only read the **first** `iov_base`. If the DNS payload is split across segments, we either get a wrong pointer or only the first chunk (and parsing fails). So we could see `data_ptr` non-NULL but wrong/partial data, or the kernel might use a different iter type.
- So this can manifest as either “pointer NULL” (if iter type is something we don’t handle) or “pointer valid but wrong data” (if we only read first iovec).

### 4. Different processes and code paths

- **VM**: “Real” clients (browsers, systemd-resolve, etc.) — one typical path.
- **K8s**: Same eBPF hooks, but **different processes** (python3, nslookup in minimal image, CoreDNS). They might use TCP for DNS in some cases, or a different syscall pattern, so we might hit `udp_sendmsg` less or with a different iter state. The debug counters show **which** hook path is failing (send vs recv, iter vs read).

### 5. Timing (less likely for “always fail” in K8s)

- In `udp_sendmsg` we’re in **entry** (kprobe). In theory `msg_iter` might not be fully set up yet in some paths. If in K8s that path is always taken and on the VM a different path is taken, we could see “always NULL in K8s”. This is less likely than layout/iter_type, but if counters show “iter read fail” or “ptr null” only on send path, it’s possible.

---

**What to do next**

1. Deploy with the eBPF debug counters and check **which** counter is high in K8s (`udp_send_data_ptr_null` vs `udp_recv_no_ptr` vs `*_probe_read_fail`).
2. If it’s **`udp_send_data_ptr_null`** or **`udp_recv_no_ptr`**: treat as **layout or iter_type** (hypotheses #1 and #2). Get the node kernel’s `struct iov_iter` (and `include/linux/uio.h`) and either:
   - adjust `IOV_ITER_*` offsets for that kernel, or
   - add handling for the actual `iter_type` you see (e.g. log it first, then add a branch).
3. If it’s **`*_probe_read_fail`**: pointer is non-NULL but read fails (e.g. page/address issue); then consider namespace/timing (hypotheses #3–5).
