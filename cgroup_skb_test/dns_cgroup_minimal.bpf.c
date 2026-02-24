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

/* Egress: outgoing packets from this cgroup (BCC uses section name for program type) */
int egress(struct __sk_buff *ctx)
__attribute__((section("cgroup_skb/egress")))
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct iphdr *ip = (struct iphdr *)data;
    
    if (data + sizeof(struct iphdr) > data_end)
        return 1;

    // FIX: Added missing ip_len calculation
    u32 ip_len = ip_hdr_len(ip);
    if (ip_len < sizeof(struct iphdr) || data + ip_len + sizeof(struct udphdr) > data_end)
        return 1;

    if (ip->protocol != IPPROTO_UDP)
        return 1;

    struct udphdr *udp = (struct udphdr *)(data + ip_len);
    u16 dport = bpf_ntohs(udp->dest);
    if (dport != DNS_PORT)
        return 1;

    u32 payload_off = ip_len + sizeof(struct udphdr);
    
    struct event_t ev = { .direction = 1 };
    
    // FIX: Use ctx->len instead of pointer subtraction
    if (ctx->len <= payload_off)
        return 1;
        
    u32 avail = ctx->len - payload_off;
    u32 copy  = avail > PAYLOAD_SAMPLE ? PAYLOAD_SAMPLE : avail;
    
    if (copy > 0) {
        long ret = bpf_skb_load_bytes(ctx, payload_off, ev.payload, copy);
        if (ret == 0)
            events.perf_submit(ctx, &ev, sizeof(ev));
    }
    
    return 1; /* pass packet */
}

/* Ingress: incoming packets to this cgroup */
int ingress(struct __sk_buff *ctx)
__attribute__((section("cgroup_skb/ingress")))
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
    
    // FIX: Removed the duplicate ip_len block that was here

    struct udphdr *udp = (struct udphdr *)(data + ip_len);
    u16 sport = bpf_ntohs(udp->source); 
    if (sport != DNS_PORT)
        return 1;

    u32 payload_off = ip_len + sizeof(struct udphdr);

    struct event_t ev = { .direction = 2 };
    
    // FIX: Use ctx->len instead of pointer subtraction
    if (ctx->len <= payload_off)
        return 1;
        
    u32 avail = ctx->len - payload_off;
    u32 copy  = avail > PAYLOAD_SAMPLE ? PAYLOAD_SAMPLE : avail;
    
    if (copy > 0) {
        long ret = bpf_skb_load_bytes(ctx, payload_off, ev.payload, copy);
        if (ret == 0)
            events.perf_submit(ctx, &ev, sizeof(ev));
    }
    
    return 1;
}