// ===== UDP DNS ЗАПРОСЫ =====

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    if (!sk || !msg) return 0;
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    if (dport != __constant_htons(53)) return 0;

    struct dns_event event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.netns_id = get_netns_id(sk);
    bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    event.dport = 53;
    event.protocol = 17;
    event.direction = 1;

    struct iov_iter iter;
    long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    if (ret != 0) {
        event.data_len = 0;
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_SEND_ITER_FAIL);
        events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    void *data_ptr = get_data_ptr_from_iter(&iter);
    if (data_ptr) {
        ret = try_read_data(event.dns_data, sizeof(event.dns_data), data_ptr);
        if (ret == 0) {
            event.data_len = MAX_DNS_DATA;
            parse_dns_header(event.dns_data, event.data_len, &event);
        } else {
            event.data_len = 0;
            ebpf_debug_fail.increment(EBPF_DEBUG_UDP_SEND_READ_FAIL);
        }
    } else {
        event.data_len = 0;
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_SEND_PTR_NULL);
    }
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// ===== UDP DNS ОТВЕТЫ (kprobe + kretprobe) =====

int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    if (!sk || !msg) return 0;
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    if (dport != __constant_htons(53)) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recv_context rctx = {};
    bpf_probe_read_kernel(&rctx.saddr, sizeof(rctx.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&rctx.daddr, sizeof(rctx.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&rctx.sport, sizeof(rctx.sport), &sk->__sk_common.skc_num);
    rctx.dport = 53;
    rctx.protocol = 17;
    struct iov_iter iter;
    long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    if (ret == 0) {
        rctx.data_ptr = get_data_ptr_from_iter(&iter);
    } else {
        rctx.data_ptr = NULL;
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_RECV_NO_PTR);
    }
    if (!rctx.data_ptr && ret == 0)
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_RECV_NO_PTR);
    recv_ctx_map.update(&pid_tgid, &rctx);
    return 0;
}

int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recv_context *rctx = recv_ctx_map.lookup(&pid_tgid);
    if (!rctx || !rctx->data_ptr) {
        if (rctx && !rctx->data_ptr)
            ebpf_debug_fail.increment(EBPF_DEBUG_UDP_RECV_NO_PTR);
        recv_ctx_map.delete(&pid_tgid);
        return 0;
    }
    struct dns_event event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.netns_id = 0;
    event.saddr = rctx->saddr;
    event.daddr = rctx->daddr;
    event.sport = rctx->sport;
    event.dport = rctx->dport;
    event.protocol = rctx->protocol;
    event.direction = 2;
    long ret = try_read_data(event.dns_data, sizeof(event.dns_data), rctx->data_ptr);
    if (ret == 0) {
        event.data_len = MAX_DNS_DATA;
        parse_dns_header(event.dns_data, event.data_len, &event);
    } else {
        event.data_len = 0;
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_RECV_READ_FAIL);
    }
    recv_ctx_map.delete(&pid_tgid);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
