#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DNS_PORT 53
#define PAYLOAD_SAMPLE 64

// Optional: set from userspace. 0 = only DNS, 1 = any UDP (to verify hooks fire), 2 = any IP
BPF_ARRAY(debug_level, uint32_t, 1);

struct event_t {
    uint32_t direction; // 1=egress, 2=ingress
    uint32_t kind;      // 0=DNS, 1=any_udp, 2=any_ip (for debug)
    uint8_t  payload[PAYLOAD_SAMPLE];
};

BPF_PERF_OUTPUT(events);

// L2 offset: 0 = skb->data is IP (typical for cgroup_skb), 14 = skip Ethernet
#define L2_OFFSET 0

static __always_inline int monitor_dns(struct __sk_buff *ctx, uint32_t dir) {
    uint32_t *dbg = debug_level.lookup(&(uint32_t){0});
    uint32_t level = dbg ? *dbg : 0;

    unsigned int off = L2_OFFSET;
    if (ctx->data + off + 20 > ctx->data_end) return 1;

    uint8_t proto;
    if (bpf_skb_load_bytes(ctx, off + 9, &proto, 1) < 0) return 1;
    if (level >= 2) {
        struct event_t ev = {};
        ev.direction = dir;
        ev.kind = 2;
        bpf_skb_load_bytes(ctx, off + 20, ev.payload, 32);
        events.perf_submit(ctx, &ev, sizeof(ev));
        return 1;
    }
    if (proto != IPPROTO_UDP) return 1;

    if (ctx->data + off + 28 > ctx->data_end) return 1;
    uint16_t sport, dport;
    if (bpf_skb_load_bytes(ctx, off + 20, &sport, 2) < 0) return 1;
    if (bpf_skb_load_bytes(ctx, off + 22, &dport, 2) < 0) return 1;
    sport = __builtin_bswap16(sport);
    dport = __builtin_bswap16(dport);

    if (sport != DNS_PORT && dport != DNS_PORT) {
        if (level >= 1) {
            struct event_t ev = {};
            ev.direction = dir;
            ev.kind = 1;
            bpf_skb_load_bytes(ctx, off + 28, ev.payload, PAYLOAD_SAMPLE);
            events.perf_submit(ctx, &ev, sizeof(ev));
        }
        return 1;
    }

    struct event_t ev = {};
    ev.direction = dir;
    ev.kind = 0;
    bpf_skb_load_bytes(ctx, off + 28, ev.payload, PAYLOAD_SAMPLE);
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 1;
}
int egress(struct __sk_buff *ctx)  { return monitor_dns(ctx, 1); }
int ingress(struct __sk_buff *ctx) { return monitor_dns(ctx, 2); }
