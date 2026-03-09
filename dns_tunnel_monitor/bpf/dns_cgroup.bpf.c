#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DNS_PORT 53

/* Min DNS payload length to accept packet; rest zero-padded. 12 = DNS header only. */
#define MIN_PAYLOAD 12
/* Bytes copied to userspace;  */
#define PAYLOAD_SAMPLE 256
/*
 * Shared ring buffer size in pages.
 */
#define EVENTS_RINGBUF_PAGES 64

#define MIN_PKT_LEN (28 + MIN_PAYLOAD)

struct event_t {
    uint8_t  direction;
    uint8_t  _pad[7];
    uint64_t cgroup_id;
    uint8_t  payload[PAYLOAD_SAMPLE];
    uint8_t  ip_version;  /* first nibble of packet (4 or 6) — for unparseable diagnostics */
};

BPF_RINGBUF_OUTPUT(events, EVENTS_RINGBUF_PAGES);

static __always_inline int monitor_dns(struct __sk_buff *ctx, uint8_t dir) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + MIN_PKT_LEN > data_end)
        return 1;

    uint8_t proto = *(uint8_t *)(data + 9);
    if (proto != IPPROTO_UDP)
        return 1;

    uint16_t sport = __builtin_bswap16(*(uint16_t *)(data + 20));
    uint16_t dport = __builtin_bswap16(*(uint16_t *)(data + 22));
    if (sport != DNS_PORT && dport != DNS_PORT)
        return 1;

    struct event_t ev = {};
    ev.direction = dir;
    ev.cgroup_id = bpf_skb_cgroup_id(ctx);
    ev.ip_version = (*(uint8_t *)(data + 0)) >> 4;  /* IP version for diagnostics */
#pragma unroll
    for (int i = 0; i < PAYLOAD_SAMPLE; i++) {
        if (data + 28 + i < data_end)
            ev.payload[i] = *(uint8_t *)(data + 28 + i);
        else
            ev.payload[i] = 0;
    }

    events.ringbuf_output(&ev, sizeof(ev), 0);
    return 1;
}

int egress_hook(struct __sk_buff *ctx)  { return monitor_dns(ctx, 1); }
int ingress_hook(struct __sk_buff *ctx) { return monitor_dns(ctx, 2); }
