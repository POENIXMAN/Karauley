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
| `udp_send_probe_read_fail` | `bpf_probe_read_user` + `bpf_probe_read_kernel` both failed in `udp_sendmsg` |
| `udp_recv_no_ptr` | No data pointer in `udp_recvmsg` (kprobe or get_data_ptr failed) |
| `udp_recv_probe_read_fail` | Both reads failed in `udp_recvmsg` kretprobe |
| `union_primary_ok` | Data pointer obtained from iov_iter union at offset 24 |
| `union_fallback_ok` | Data pointer obtained from iov_iter union at offset 16 |

Additional debug (printed when non-zero):

- **iter_type** — distribution of `iov_iter.iter_type`: UBUF=0, IOVEC=1, KVEC=2, BVEC=3, etc. If you see only type 2 or 8 and no union_primary_ok/union_fallback_ok, the union layout is wrong for that type.
- **read: user_ok=…, kernel_ok=…** — how many payload reads succeeded via user vs kernel. If both are 0 but union_*_ok > 0, the pointer is valid but not readable (wrong space or page not present).

**UBUF = user buffer:** The pointer is user-space. We **prefer** `bpf_probe_read_user` (correct payload). If it fails (e.g. in container user namespace), we **fall back** to `bpf_probe_read_kernel` so we at least get `dns_id` and header (otherwise we’d see ID:0000). In that case the domain may stay unparseable until user read works in your environment.

### Step-by-step pipeline (`[eBPF debug] steps:`)

These counters show **at which step** the pipeline succeeds or fails (for K8s debugging):

| Step | Meaning |
|------|--------|
| `send_iter_ok` | UDP send: read `msg_iter` from `msghdr` OK |
| `send_ptr_ok` | UDP send: `get_data_ptr_from_iter` returned non-NULL |
| `send_ptr_null` | UDP send: pointer NULL (union offset / iter_type mismatch) |
| `ptr_primary_probe_ok` | Pointer validated by 2-byte probe read at union offset **24** |
| `ptr_fallback_probe_ok` | Pointer validated by 2-byte probe read at union offset **16** |
| `send_read_user_ok` | UDP send: `bpf_probe_read_user` (full payload) OK |
| `send_read_kernel_ok` | UDP send: `bpf_probe_read_kernel` fallback OK |
| `send_read_fail` | UDP send: both user and kernel read failed |
| `recv_iter_ok` | UDP recv kprobe: iter read OK |
| `recv_ptr_ok` / `recv_ptr_null` | UDP recv: pointer from iter |
| `recv_read_user_ok` / `recv_read_kernel_ok` / `recv_read_fail` | UDP recv kretprobe: payload read |

**How to read:** If you see `send_iter_ok` but no `send_ptr_ok` → failure at **pointer extraction** (layout/offset). If you see `send_ptr_ok` and `send_read_fail` (and no `send_read_user_ok`/`send_read_kernel_ok`) → failure at **payload read** (user/kernel space or address invalid in container).

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

## Conclusion from K8s logs (e.g. logs-master.txt)

When you see:

```text
[eBPF debug] steps: send_iter_ok=15, send_ptr_ok=15, ptr_primary_probe_ok=40, send_read_kernel_ok=15, recv_iter_ok=25, recv_ptr_ok=25, recv_read_kernel_ok=25
[eBPF debug] read: user_ok=0, kernel_ok=40
```

**What this means:**

1. **Pointer extraction works** — `send_ptr_ok`, `recv_ptr_ok`, `ptr_primary_probe_ok`: we get a non-NULL pointer and the 2-byte probe read succeeds (so the address is readable at probe time).
2. **Full payload read “succeeds”** — `send_read_kernel_ok` / `recv_read_kernel_ok` and `kernel_ok`; no `send_read_fail` / `recv_read_fail`. So `bpf_probe_read_kernel(256 bytes)` returns 0 (no error).
3. **User read never works in K8s** — `user_ok=0`. The pointer we have is a **user-space** address (from `iov_iter` for UBUF). In the container, `bpf_probe_read_user` fails for that address; we then use `bpf_probe_read_kernel` and it “succeeds” but returns **different memory** (not the process’s DNS buffer).
4. **Payload content is wrong** — hex dump shows `byte[12]=0x00` and pointer-like bytes at 2–11. So we’re reading some kernel view of that VA (e.g. zero page or another mapping), not the real DNS packet. Hence `<unparseable>` and no real domains.

**Root cause (for this K8s setup):**  
User-space buffer is not readable with `bpf_probe_read_user` in the container (likely user namespace / context). Fallback `bpf_probe_read_kernel` on that user VA does not fault but returns the wrong content, so we must not rely on it for parsing.

**What to check / work on next:**

| Priority | Action | Purpose |
|----------|--------|--------|
| 1 | Run dns-monitor with **host PID** and/or **host user** namespace (e.g. `securityContext.runAsUser: 0`, mount host `/proc` already used) | See if user read starts working when eBPF runs in host user/pid context. |
| 2 | On the node, run `uname -r` and open `include/linux/uio.h` for that kernel; confirm `struct iov_iter` union offset (16 vs 24) and that we use the right one for UBUF. | Rule out layout mismatch (your logs show ptr_primary_probe_ok, so 24 is valid for the 2-byte test; the full 256-byte read is still wrong content). |
| 3 | Try **small user read** in eBPF: e.g. `bpf_probe_read_user(dst, 12, src)` (only DNS header). If it succeeds, then user space is readable but something fails for 256 bytes (e.g. partial map). | Differentiate “user VA invalid” vs “only long read fails”. |
| 4 | Consider a **different hook** where DNS payload is in kernel memory (e.g. after copy into skb in the network stack, or XDP/skb-based capture). | Avoid depending on reading from the process’s user buffer in container context. |
| 5 | Document in thesis: “In Kubernetes the payload read from the process buffer fails (user read fails; kernel read returns wrong data); detection still works at flow level (PID, pod, rate, IP); domain-level detection requires host namespace or kernel-level capture.” | Clear limitation and future work. |

---

## Hypotheses: why it works on host but fails in K8s

Use **`[eBPF debug] steps:`** to see where the pipeline stops in the cluster. Then match to one of the following.

| What you see in `steps:` | Failing step | Likely hypothesis |
|--------------------------|--------------|-------------------|
| `send_iter_ok` but no `send_ptr_ok`, many `send_ptr_null` | Pointer extraction | **#1** Wrong `iov_iter` layout on node kernel (union at 24/16 wrong). Or **#2** iter_type not UBUF/IOVEC. |
| `send_ptr_ok` (or `ptr_primary_probe_ok`/`ptr_fallback_probe_ok`) but no `send_read_user_ok`/`send_read_kernel_ok`, many `send_read_fail` | Payload read | **#3** User buffer not readable in container (user namespace / page not present). Kernel fallback also fails → wrong pointer or unmapped. |
| `send_read_kernel_ok` > 0 but domains still &lt;unparseable&gt; | Data is wrong | Pointer valid but not the DNS buffer (e.g. wrong offset); or kernel returns different memory in container. |
| `recv_*` steps: same pattern as send | Recv path | Same causes on `udp_recvmsg` (kprobe: ptr, kretprobe: read). |


## Теория: где почитать

### eBPF: probe_read_user vs probe_read_kernel

- **Kernel docs (официально):**  
  https://docs.kernel.org/bpf/helpers.html  
  Раздел «Reading kernel memory»: `bpf_probe_read_user()` — только user-space; `bpf_probe_read_kernel()` — только kernel memory. Чтение не из того адресного пространства даёт ошибку.
- **Почему в контейнерах фейлится user read:** данные в буфере сокета могут быть уже в kernel (skb, splice, другой путь). Указатель из `iov_iter` тогда указывает на kernel memory → `bpf_probe_read_user` возвращает ошибку.

### struct iov_iter и типы итератора

- **Исходники ядра:**  
  `include/linux/uio.h` — определение `struct iov_iter`, типы `ITER_UBUF`, `ITER_IOVEC`, `ITER_KVEC`, `ITER_BVEC` и т.д.  
  Онлайн: https://elixir.bootlin.com/linux/latest/source/include/linux/uio.h
- **Как устроен iov_iter:**  
  LWN — «The iov_iter interface»: https://lwn.net/Articles/625077/  
  Плюс обновления по ядру (поиск «iov_iter» на lwn.net).

### Трассировка сетей в ядре с eBPF (на русском)

- **Ковалев М.Г.** Трассировка сетевых пакетов в ядре Linux с использованием eBPF // Труды ИСП РАН. 2020. Т. 32, вып. 3. С. 71–78.  
  Файл в проекте: `статьи/trassirovka-setevyh-paketov-v-yadre-linux-s-ispolzovaniem-ebpf.pdf`  
  Кратко про BPF/eBPF, виртуальная машина, трассировка пакетов в сетевом стеке.

### Книги и туториалы по eBPF

- **BPF Performance Tools** (Brendan Gregg) — главы про трассировку и чтение памяти из eBPF.
- **Cilium eBPF docs:** https://docs.cilium.io/en/stable/bpf/ — общая модель eBPF, меньше про `probe_read_*`.
- **BCC reference:** https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md — контекст вызовов из Python, какие хелперы доступны.
