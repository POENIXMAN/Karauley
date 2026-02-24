#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DNS_PORT 53
#define PAYLOAD_SAMPLE 64

struct event_t {
    uint32_t direction; // 1=egress, 2=ingress
    uint8_t  payload[PAYLOAD_SAMPLE];
};

BPF_PERF_OUTPUT(events);

// Helper to process packets
static __always_inline int monitor_dns(struct __sk_buff *ctx, uint32_t dir) {
    // 1. Fixed offset check: IPv4 protocol field is at offset 9
    uint8_t proto;
    if (bpf_skb_load_bytes(ctx, 9, &proto, 1) < 0) return 1;
    if (proto != IPPROTO_UDP) return 1;

    // 2. Load ports: UDP header starts at offset 20 (assuming no IP options)
    // Source port at 20, Dest port at 22
    uint16_t sport, dport;
    if (bpf_skb_load_bytes(ctx, 20, &sport, 2) < 0) return 1;
    if (bpf_skb_load_bytes(ctx, 22, &dport, 2) < 0) return 1;

    sport = __builtin_bswap16(sport);
    dport = __builtin_bswap16(dport);

    // 3. Filter for DNS
    if (sport != DNS_PORT && dport != DNS_PORT) return 1;

    // 4. Prep event - Zero-init is MANDATORY for verifier
    struct event_t ev = {}; 
    ev.direction = dir;

    // DNS payload starts at offset 28 (20 bytes IP + 8 bytes UDP)
    bpf_skb_load_bytes(ctx, 28, ev.payload, PAYLOAD_SAMPLE);
    
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 1;
}

int egress(struct __sk_buff *ctx)  { return monitor_dns(ctx, 1); }
int ingress(struct __sk_buff *ctx) { return monitor_dns(ctx, 2); }