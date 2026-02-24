/*
 * DNS monitor via cgroup_skb: cluster-agnostic, identifies source by cgroup_id.
 * Used by working.py (load from file or inline).
 */
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DNS_PORT 53
#define PAYLOAD_SAMPLE 64

struct event_t {
    uint8_t  direction;
    uint8_t  _pad[7];   /* align cgroup_id to 8 bytes */
    uint64_t cgroup_id; /* source cgroup (pod); egress has it, ingress may be 0 on some kernels */
    uint8_t  payload[PAYLOAD_SAMPLE];
};

BPF_PERF_OUTPUT(events);

static __always_inline int monitor_dns(struct __sk_buff *ctx, uint8_t dir) {
    uint8_t proto;
    if (bpf_skb_load_bytes(ctx, 9, &proto, 1) < 0) return 1;
    if (proto != IPPROTO_UDP) return 1;

    uint16_t sport, dport;
    if (bpf_skb_load_bytes(ctx, 20, &sport, 2) < 0) return 1;
    if (bpf_skb_load_bytes(ctx, 22, &dport, 2) < 0) return 1;
    sport = __builtin_bswap16(sport);
    dport = __builtin_bswap16(dport);
    if (sport != DNS_PORT && dport != DNS_PORT) return 1;

    struct event_t ev = {};
    ev.direction = dir;
    ev.cgroup_id = bpf_skb_cgroup_id(ctx);
    bpf_skb_load_bytes(ctx, 28, ev.payload, PAYLOAD_SAMPLE);
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 1;
}

int egress_hook(struct __sk_buff *ctx)  { return monitor_dns(ctx, 1); }
int ingress_hook(struct __sk_buff *ctx) { return monitor_dns(ctx, 2); }
