/*
 * dns_ebpf_common.h — общие структуры, константы и хелперы (без карт).
 * Подключается из dns_ebpf_improved.bpf.c после системных инклудов.
 */
#ifndef DNS_EBPF_COMMON_H
#define DNS_EBPF_COMMON_H

#define MAX_DNS_DATA 256
#define DNS_HEADER_SIZE 12

struct dns_event {
    u32 pid;
    u32 tid;
    char comm[16];
    u64 cgroup_id;
    u32 netns_id;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  protocol;
    u8  direction;
    u16 dns_id;
    u16 dns_flags;
    u16 dns_questions;
    u16 dns_answers;
    u64 timestamp_ns;
    u16 data_len;
    u8  dns_data[MAX_DNS_DATA];
} __attribute__((packed));

struct recv_context {
    void *data_ptr;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  protocol;
};

struct send_context {
    void *data_ptr;
    struct msghdr *msg;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 cgroup_id;
    u32 netns_id;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char comm[16];
};

/* Debug reason codes (номера слотов в ebpf_debug_fail) */
#define EBPF_DEBUG_UDP_SEND_ITER_FAIL  1
#define EBPF_DEBUG_UDP_SEND_PTR_NULL  2
#define EBPF_DEBUG_UDP_SEND_READ_FAIL 3
#define EBPF_DEBUG_UDP_RECV_NO_PTR    4
#define EBPF_DEBUG_UDP_RECV_READ_FAIL 5
#define EBPF_DEBUG_UNION_PRIMARY_OK   6
#define EBPF_DEBUG_UNION_FALLBACK_OK  7

#ifndef ITER_UBUF
#define ITER_UBUF 0
#endif
#ifndef ITER_IOVEC
#define ITER_IOVEC 1
#endif
#define IOV_ITER_ITER_TYPE_OFF  0
#define IOV_ITER_IOV_OFFSET_OFF 8
#define IOV_ITER_UNION_OFF_PRIMARY   24
#define IOV_ITER_UNION_OFF_FALLBACK  16

static __always_inline u32 get_netns_id(struct sock *sk) {
    if (!sk) return 0;
    u32 netns = 0;
    struct net *net = NULL;
    long ret = bpf_probe_read_kernel(&net, sizeof(net), &sk->__sk_common.skc_net.net);
    if (ret == 0 && net)
        bpf_probe_read_kernel(&netns, sizeof(netns), &net->ns.inum);
    return netns;
}

static __always_inline void parse_dns_header(u8 *data, u16 data_len, struct dns_event *event) {
    if (!data || data_len < DNS_HEADER_SIZE) {
        event->dns_id = 0;
        event->dns_flags = 0;
        event->dns_questions = 0;
        event->dns_answers = 0;
        return;
    }
    event->dns_id = (data[0] << 8) | data[1];
    event->dns_flags = (data[2] << 8) | data[3];
    event->dns_questions = (data[4] << 8) | data[5];
    event->dns_answers = (data[6] << 8) | data[7];
}

static __always_inline void *extract_data_ptr_from_iter_union(struct iov_iter *iter, u8 iter_type, int union_off) {
    void *data_ptr = NULL;
    long ret;
    if (iter_type == ITER_UBUF) {
        ret = bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)iter + union_off);
        return (ret == 0) ? data_ptr : NULL;
    }
    if (iter_type == ITER_IOVEC) {
        const struct iovec *iov = NULL;
        ret = bpf_probe_read_kernel(&iov, sizeof(iov), (void *)iter + union_off);
        if (ret != 0 || !iov) return NULL;
        ret = bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)iov);
        return (ret == 0) ? data_ptr : NULL;
    }
    if (iter_type == 2 || iter_type == 8) {
        const struct kvec *kv = NULL;
        ret = bpf_probe_read_kernel(&kv, sizeof(kv), (void *)iter + union_off);
        if (ret != 0 || !kv) return NULL;
        ret = bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)kv);
        return (ret == 0) ? data_ptr : NULL;
    }
    return NULL;
}

#endif /* DNS_EBPF_COMMON_H */
