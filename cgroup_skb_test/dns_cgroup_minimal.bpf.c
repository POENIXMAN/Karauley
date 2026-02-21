/*
 * Minimal CGROUP_SKB test: egress/ingress hook, UDP port 53, copy first 64 bytes
 * of payload to perf buffer. No iov_iter, no user memory — payload from skb.
 * Sections cgroup_skb/egress and cgroup_skb/ingress for loader.
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DNS_PORT 53
#define PAYLOAD_SAMPLE 64

struct event_t {
    u8  direction;  /* 1=egress 2=ingress */
    u8  payload[PAYLOAD_SAMPLE];
};

BPF_PERF_OUTPUT(events);

static __always_inline u32 ip_hdr_len(struct iphdr *ip)
{
    return ((u32)(ip->ihl)) * 4;
}

#define SEC(name) __attribute__((section(name)))

/* Egress: outgoing packets from this cgroup */
SEC("cgroup_skb/egress")
int egress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct iphdr *ip = (struct iphdr *)data;
    if (data + sizeof(struct iphdr) > data_end)
        return 1;
    u32 ip_len = ip_hdr_len(ip);
    if (ip_len < sizeof(struct iphdr) || data + ip_len + sizeof(struct udphdr) > data_end)
        return 1;
    if (ip->protocol != IPPROTO_UDP)
        return 1;

    struct udphdr *udp = (struct udphdr *)(data + ip_len);
    u16 dport = __builtin_bswap16(udp->dest);
    if (dport != DNS_PORT)
        return 1;

    u32 payload_off = ip_len + sizeof(struct udphdr);
    if (data + payload_off + 1 > data_end)
        return 1;

    struct event_t ev = { .direction = 1 };
    u32 avail = (u32)(data_end - data - payload_off);
    u32 copy  = avail > PAYLOAD_SAMPLE ? PAYLOAD_SAMPLE : avail;
    if (copy > 0) {
        long ret = bpf_skb_load_bytes(ctx, payload_off, ev.payload, copy);
        if (ret == 0)
            events.perf_submit(ctx, &ev, sizeof(ev));
    }
    return 1; /* pass packet */
}

/* Ingress: incoming packets to this cgroup */
SEC("cgroup_skb/ingress")
int ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct iphdr *ip = (struct iphdr *)data;
    if (data + sizeof(struct iphdr) > data_end)
        return 1;
    u32 ip_len = ip_hdr_len(ip);
    if (ip_len < sizeof(struct iphdr) || data + ip_len + sizeof(struct udphdr) > data_end)
        return 1;
    if (ip->protocol != IPPROTO_UDP)
        return 1;

    struct udphdr *udp = (struct udphdr *)(data + ip_len);
    u16 sport = __builtin_bswap16(udp->source);
    if (sport != DNS_PORT)
        return 1;

    u32 payload_off = ip_len + sizeof(struct udphdr);
    if (data + payload_off + 1 > data_end)
        return 1;

    struct event_t ev = { .direction = 2 };
    u32 avail = (u32)(data_end - data - payload_off);
    u32 copy  = avail > PAYLOAD_SAMPLE ? PAYLOAD_SAMPLE : avail;
    if (copy > 0) {
        long ret = bpf_skb_load_bytes(ctx, payload_off, ev.payload, copy);
        if (ret == 0)
            events.perf_submit(ctx, &ev, sizeof(ev));
    }
    return 1;
}
