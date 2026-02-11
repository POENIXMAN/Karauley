/*
 * DNS Tunnel Detector - eBPF Kernel Module
 * Главный файл: карты, хелперы с доступом к картам, инклуды UDP/TCP.
 * Общие структуры и хелперы без карт — в dns_ebpf_common.h
 * UDP/TCP kprobes — в dns_ebpf_udp.inc и dns_ebpf_tcp.inc
 */
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/uio.h>
#include <net/net_namespace.h>

#include "dns_ebpf_common.h"

BPF_PERF_OUTPUT(events);
BPF_ARRAY(ebpf_debug_fail, u64, 16);
BPF_ARRAY(ebpf_debug_iter_type, u64, 16);
BPF_ARRAY(ebpf_debug_read, u64, 4);
BPF_HASH(recv_ctx_map, u64, struct recv_context, 10240);
BPF_HASH(send_ctx_map, u64, struct send_context, 10240);

// Указатель на данные из iov_iter (использует карты отладки)
static __always_inline void *get_data_ptr_from_iter(struct iov_iter *iter) {
    if (!iter) return NULL;
    void *data_ptr = NULL;
    u8 iter_type = 0;
    u64 iov_offset = 0;
    long ret = bpf_probe_read_kernel(&iter_type, sizeof(iter_type), (void *)iter + IOV_ITER_ITER_TYPE_OFF);
    if (ret != 0) return NULL;
    u32 it_key = (u32)(iter_type & 0xf);
    ebpf_debug_iter_type.increment(it_key);
    bpf_probe_read_kernel(&iov_offset, sizeof(iov_offset), (void *)iter + IOV_ITER_IOV_OFFSET_OFF);
    data_ptr = extract_data_ptr_from_iter_union(iter, iter_type, IOV_ITER_UNION_OFF_PRIMARY);
    if (data_ptr) {
        ebpf_debug_fail.increment(EBPF_DEBUG_UNION_PRIMARY_OK);
        return (void *)((char *)data_ptr + iov_offset);
    }
    data_ptr = extract_data_ptr_from_iter_union(iter, iter_type, IOV_ITER_UNION_OFF_FALLBACK);
    if (data_ptr) {
        ebpf_debug_fail.increment(EBPF_DEBUG_UNION_FALLBACK_OK);
        return (void *)((char *)data_ptr + iov_offset);
    }
    return NULL;
}

static __always_inline long try_read_data(void *dst, u32 size, void *src) {
    long ret = bpf_probe_read_user(dst, size, src);
    if (ret == 0) {
        ebpf_debug_read.increment(0);
        return 0;
    }
    ret = bpf_probe_read_kernel(dst, size, src);
    if (ret == 0)
        ebpf_debug_read.increment(1);
    return ret;
}

#include "dns_ebpf_udp.inc"
#include "dns_ebpf_tcp.inc"
