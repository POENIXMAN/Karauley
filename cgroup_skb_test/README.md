# Minimal test: CGROUP_SKB for DNS payload

Standalone test to verify that **attaching to a cgroup** and **reading DNS payload from __sk_buff** works before refactoring the main project.

## Binding and payload (short)

- **Binding:** Python opens a cgroup path (e.g. `/sys/fs/cgroup`) → gets fd → calls `bpf.attach_cgroup("egress", cgroup_fd, BPF_CGROUP_INET_EGRESS)` and same for `"ingress"` with `BPF_CGROUP_INET_INGRESS`. The kernel then runs our BPF for every egress/ingress packet from that cgroup.
- **Payload:** In BPF, `ctx->data` / `ctx->data_end` point to the packet in **kernel memory**. We parse IP (protocol, header length), then UDP (port 53), then copy bytes after the UDP header into the event and submit to perf buffer. So we never touch user memory or iov_iter.

## What it does

1. **Binding:** Opens a cgroup path (e.g. `/sys/fs/cgroup`), attaches a BPF program to it for **egress** (and optionally ingress). Any UDP packet to/from port 53 from processes in that cgroup triggers the program.
2. **Payload:** In the BPF program, packet is in kernel memory (`ctx->data` / `data_end`). We parse IP + UDP, check port 53, copy first 64 bytes of payload to a perf buffer and pass to Python.
3. **Python:** Loads the BPF, attaches to cgroup, polls the perf buffer and prints received bytes (hex). If you see DNS-like bytes (e.g. transaction ID, then domain name), the approach works.

## Run (as root, on a node with cgroup v2)

```bash
cd prototype_improved/cgroup_skb_test
sudo python3 test_cgroup_skb.py
```

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
