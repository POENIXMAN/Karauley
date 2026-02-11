// ===== TCP DNS ЗАПРОСЫ (kprobe + kretprobe) =====

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    if (!sk || !msg) return 0;
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    if (dport != __constant_htons(53)) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct iov_iter iter;
    long ret_iter = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    void *data_ptr = NULL;
    if (ret_iter == 0)
        data_ptr = get_data_ptr_from_iter(&iter);
    if (data_ptr) {
        u8 tcp_header[2];
        long ret = try_read_data(tcp_header, sizeof(tcp_header), data_ptr);
        if (ret == 0) {
            u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
            if (dns_len >= 12 && dns_len <= 512) {
                struct dns_event event = {};
                event.timestamp_ns = bpf_ktime_get_ns();
                event.pid = pid_tgid >> 32;
                event.tid = pid_tgid & 0xFFFFFFFF;
                bpf_get_current_comm(&event.comm, sizeof(event.comm));
                event.cgroup_id = bpf_get_current_cgroup_id();
                event.netns_id = get_netns_id(sk);
                bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
                bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
                bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
                event.dport = 53;
                event.protocol = 6;
                event.direction = 1;
                ret = try_read_data(event.dns_data,
                                   dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                   data_ptr + 2);
                if (ret == 0) {
                    event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                    parse_dns_header(event.dns_data, event.data_len, &event);
                    events.perf_submit(ctx, &event, sizeof(event));
                    return 0;
                }
            }
        }
    }
    struct send_context sctx = {};
    sctx.timestamp_ns = bpf_ktime_get_ns();
    sctx.pid = pid_tgid >> 32;
    sctx.tid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&sctx.comm, sizeof(sctx.comm));
    sctx.cgroup_id = bpf_get_current_cgroup_id();
    sctx.netns_id = get_netns_id(sk);
    bpf_probe_read_kernel(&sctx.saddr, sizeof(sctx.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&sctx.daddr, sizeof(sctx.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sctx.sport, sizeof(sctx.sport), &sk->__sk_common.skc_num);
    sctx.dport = 53;
    sctx.data_ptr = data_ptr;
    sctx.msg = msg;
    send_ctx_map.update(&pid_tgid, &sctx);
    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct send_context *sctx = send_ctx_map.lookup(&pid_tgid);
    if (!sctx || !sctx->data_ptr) {
        if (sctx) send_ctx_map.delete(&pid_tgid);
        return 0;
    }
    struct dns_event event = {};
    event.timestamp_ns = sctx->timestamp_ns;
    event.pid = sctx->pid;
    event.tid = sctx->tid;
    __builtin_memcpy(&event.comm, &sctx->comm, sizeof(event.comm));
    event.cgroup_id = sctx->cgroup_id;
    event.netns_id = sctx->netns_id;
    event.saddr = sctx->saddr;
    event.daddr = sctx->daddr;
    event.sport = sctx->sport;
    event.dport = sctx->dport;
    event.protocol = 6;
    event.direction = 1;
    void *data_ptr = sctx->data_ptr;
    int data_read = 0;
    if (data_ptr) {
        u8 tcp_header[2];
        long ret = try_read_data(tcp_header, sizeof(tcp_header), data_ptr);
        if (ret == 0) {
            u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
            if (dns_len >= 12 && dns_len <= 512) {
                ret = try_read_data(event.dns_data,
                                   dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                   data_ptr + 2);
                if (ret == 0) {
                    event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                    parse_dns_header(event.dns_data, event.data_len, &event);
                    data_read = 1;
                }
            }
        }
        if (!data_read) {
            long ret = try_read_data(event.dns_data, MAX_DNS_DATA, data_ptr);
            if (ret == 0) {
                event.data_len = MAX_DNS_DATA;
                parse_dns_header(event.dns_data, event.data_len, &event);
                data_read = 1;
            }
        }
    }
    if (!data_read && sctx->msg) {
        struct iov_iter iter;
        long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &sctx->msg->msg_iter);
        if (ret == 0) {
            void *new_data_ptr = get_data_ptr_from_iter(&iter);
            if (new_data_ptr) {
                u8 tcp_header[2];
                ret = try_read_data(tcp_header, sizeof(tcp_header), new_data_ptr);
                if (ret == 0) {
                    u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
                    if (dns_len >= 12 && dns_len <= 512) {
                        ret = try_read_data(event.dns_data,
                                           dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                           new_data_ptr + 2);
                        if (ret == 0) {
                            event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                            parse_dns_header(event.dns_data, event.data_len, &event);
                            data_read = 1;
                        }
                    }
                }
                if (!data_read) {
                    ret = try_read_data(event.dns_data, MAX_DNS_DATA, new_data_ptr);
                    if (ret == 0) {
                        event.data_len = MAX_DNS_DATA;
                        parse_dns_header(event.dns_data, event.data_len, &event);
                        data_read = 1;
                    }
                }
            }
        }
    }
    if (!data_read) event.data_len = 0;
    send_ctx_map.delete(&pid_tgid);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// ===== TCP DNS ОТВЕТЫ =====

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
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
    rctx.protocol = 6;
    struct iov_iter iter;
    long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    if (ret == 0)
        rctx.data_ptr = get_data_ptr_from_iter(&iter);
    else
        rctx.data_ptr = NULL;
    recv_ctx_map.update(&pid_tgid, &rctx);
    return 0;
}

int kretprobe__tcp_recvmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct recv_context *rctx = recv_ctx_map.lookup(&pid_tgid);
    if (!rctx || !rctx->data_ptr) {
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
    u8 tcp_header[2];
    long ret = try_read_data(tcp_header, sizeof(tcp_header), rctx->data_ptr);
    if (ret == 0) {
        u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
        if (dns_len >= 12 && dns_len <= 512) {
            ret = try_read_data(event.dns_data,
                               dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                               rctx->data_ptr + 2);
            if (ret == 0) {
                event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                parse_dns_header(event.dns_data, event.data_len, &event);
            } else {
                try_read_data(event.dns_data, MAX_DNS_DATA, rctx->data_ptr);
                event.data_len = MAX_DNS_DATA;
                parse_dns_header(event.dns_data, event.data_len, &event);
            }
        } else {
            try_read_data(event.dns_data, MAX_DNS_DATA, rctx->data_ptr);
            event.data_len = MAX_DNS_DATA;
            parse_dns_header(event.dns_data, event.data_len, &event);
        }
    } else {
        try_read_data(event.dns_data, MAX_DNS_DATA, rctx->data_ptr);
        event.data_len = MAX_DNS_DATA;
        parse_dns_header(event.dns_data, event.data_len, &event);
    }
    recv_ctx_map.delete(&pid_tgid);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
