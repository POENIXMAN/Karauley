/*
 * DNS monitor via cgroup_skb: cluster-agnostic, identifies source by cgroup_id.
 *
 * Packet access: direct (ctx->data / data_end) instead of bpf_skb_load_bytes.
 * - Pro: one bounds check, verifier-friendly; no helper call per read; explicit.
 * - Con: only linear part of skb; fragmented UDP could see less than 92 bytes
 *   (for typical DNS over UDP, packets are small and linear — OK).
 * - IPv4 only: DNS payload at offset 28. IPv6 would need offset 48 (not yet).
 *
 * Tuning (keep in sync with event_struct.PAYLOAD_SAMPLE in Python):
 * - MIN_PAYLOAD: min DNS payload bytes required to accept packet. Keep small (e.g. 12 = DNS
 *   header) so we do not drop short queries; tail is zero-padded when copying.
 * - PAYLOAD_SAMPLE: bytes we copy to userspace (rest zero-padded if packet shorter).
 *   128 covers known tunnel tools (e.g. DNSExfiltrator 55-char chunks). 256 for extra margin;
 *   UDP DNS payload max 512.
 */
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DNS_PORT 53

/* Min DNS payload length to accept packet; rest zero-padded. 12 = DNS header only. */
#define MIN_PAYLOAD 12
/* Bytes copied to userspace; increase to 256 if needed for very long names. */
#define PAYLOAD_SAMPLE 128

#define MIN_PKT_LEN (28 + MIN_PAYLOAD)

struct event_t {
    uint8_t  direction;
    uint8_t  _pad[7];
    uint64_t cgroup_id;
    uint8_t  payload[PAYLOAD_SAMPLE];
    uint8_t  ip_version;  /* first nibble of packet (4 or 6) — for unparseable diagnostics */
};

BPF_PERF_OUTPUT(events);

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

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 1;
}

int egress_hook(struct __sk_buff *ctx)  { return monitor_dns(ctx, 1); }
int ingress_hook(struct __sk_buff *ctx) { return monitor_dns(ctx, 2); }
