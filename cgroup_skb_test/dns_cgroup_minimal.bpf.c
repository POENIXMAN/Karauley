/*
 * Minimal CGROUP_SKB test: egress/ingress, UDP port 53, copy 64 bytes payload.
 * Verifier-friendly: fixed 20-byte IP header only. All offsets are constants.
 */
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DNS_PORT 53
#define PAYLOAD_SAMPLE 64
#define EVENT_SIZE (1 + PAYLOAD_SAMPLE)

#define IP_HDR_LEN  20
#define UDP_HDR_LEN 8
#define PAYLOAD_OFF 28   /* IP_HDR_LEN + UDP_HDR_LEN */

BPF_PERF_OUTPUT(events);

/* Egress: fixed offsets only, no variable ip_len */
int egress(struct __sk_buff *ctx)
__attribute__((section("cgroup_skb/egress")))
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    if (data + 10 > data_end)
        return 1;
    if (((u8 *)data)[9] != 17)   /* IPPROTO_UDP */
        return 1;
    if (data + PAYLOAD_OFF + PAYLOAD_SAMPLE > data_end)
        return 1;
    /* UDP dest port at offset 22 (20 + 2) */
    if (__builtin_bswap16(*(u16 *)(data + 22)) != DNS_PORT)
        return 1;

    u8 buf[EVENT_SIZE];
    buf[0] = 1;
    if (bpf_skb_load_bytes(ctx, PAYLOAD_OFF, &buf[1], PAYLOAD_SAMPLE) == 0)
        events.perf_submit(ctx, buf, EVENT_SIZE);
    return 1;
}

/* Ingress */
int ingress(struct __sk_buff *ctx)
__attribute__((section("cgroup_skb/ingress")))
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    if (data + 10 > data_end)
        return 1;
    if (((u8 *)data)[9] != 17)
        return 1;
    if (data + PAYLOAD_OFF + PAYLOAD_SAMPLE > data_end)
        return 1;
    /* UDP source port at offset 20 */
    if (__builtin_bswap16(*(u16 *)(data + 20)) != DNS_PORT)
        return 1;

    u8 buf[EVENT_SIZE];
    buf[0] = 2;
    if (bpf_skb_load_bytes(ctx, PAYLOAD_OFF, &buf[1], PAYLOAD_SAMPLE) == 0)
        events.perf_submit(ctx, buf, EVENT_SIZE);
    return 1;
}
