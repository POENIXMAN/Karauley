/*
 * DNS Tunnel Detector - eBPF Kernel Module
 * =========================================
 * 
 * Перехватывает DNS трафик (UDP/TCP) через kprobes на:
 * - udp_sendmsg / udp_recvmsg
 * - tcp_sendmsg / tcp_recvmsg
 * 
 * Все DNS пакеты отправляются в userspace для анализа.
 * Фильтрация и детекция туннелей происходит в userspace.
 * 
 * Собирает данные для детекции:
 * - C2 (Command & Control)
 * - Data Exfiltration
 * - IP-Over-DNS (iodine, dns2tcp)
 * 
 * Версия: 2.1 (Ring Buffer)
 * 
 * Изменения в 2.1:
 * - Ring Buffer вместо Perf Buffer
 * - Гарантированный порядок событий (FIFO)
 * - Требует ядро 5.8+
 */

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/uio.h>
#include <net/net_namespace.h>

// Буфер для DNS данных
// 256 байт достаточно для детекции DNS туннелирования:
// - DNS header: 12 байт
// - Question section: ~50-100 байт (доменное имя + тип)
// - Answer section: ~100-200 байт (данные в ответах)
// Итого: 12 + 100 + 144 = 256 байт (покрывает 95%+ DNS трафика)
// 
// Почему не 512 байт (RFC 1035 максимум)?
// - eBPF стек ограничен 512 байтами
// - Структура события с dns_data[512] превысит лимит стека
// - Для детекции туннелей достаточно 256 байт (включает все эвристики)
//
// Почему не полный UDP пакет?
// - Мы читаем только DNS payload (без UDP/IP headers)
// - UDP header (8 байт) создается ядром ПОСЛЕ kprobe
// - UDP/IP headers не содержат информации для детекции туннелей
#define MAX_DNS_DATA 256

// Минимальный размер DNS заголовка
#define DNS_HEADER_SIZE 12

// Структура события (расширенная для всех типов туннелей)
struct dns_event {
    // === Метаданные процесса ===
    u32 pid;
    u32 tid;
    char comm[16];
    
    // === Идентификация пода в K8s ===
    u64 cgroup_id;          // ID контейнерной cgroup
    u32 netns_id;           // ID network namespace
    
    // === Сетевые данные ===
    u32 saddr;              // Source IP
    u32 daddr;              // Dest IP
    u16 sport;              // Source port
    u16 dport;              // Dest port
    
    // === DNS метаданные ===
    u8  protocol;           // 6=TCP, 17=UDP
    u8  direction;          // 1=query, 2=response
    u16 dns_id;             // Transaction ID (для корреляции C2)
    u16 dns_flags;          // Flags (QR, Opcode, RCODE)
    u16 dns_questions;      // Question count
    u16 dns_answers;        // Answer count (большие = IP-Over-DNS)
    
    // === Timestamp (для анализа частоты) ===
    u64 timestamp_ns;
    
    // === DNS данные ===
    u16 data_len;           // Реальная длина данных
    u8  dns_data[MAX_DNS_DATA];
} __attribute__((packed));

// Perf Buffer — другой путь выделения памяти в ядре; при "Cannot allocate memory"
// с Ring Buffer часто помогает (требует ядро 4.4+).
BPF_PERF_OUTPUT(events);

// Debug: failure reason counters for container logs (Python reads via bpf["ebpf_debug_fail"]).
// Reason codes: 1=udp_send iter_read_fail, 2=udp_send data_ptr_null, 3=udp_send probe_read_fail,
//               4=udp_recv no_ptr, 5=udp_recv probe_read_fail
//               6=union_primary_ok (offset 24), 7=union_fallback_ok (offset 16)
#define EBPF_DEBUG_UDP_SEND_ITER_FAIL  1
#define EBPF_DEBUG_UDP_SEND_PTR_NULL  2
#define EBPF_DEBUG_UDP_SEND_READ_FAIL 3
#define EBPF_DEBUG_UDP_RECV_NO_PTR    4
#define EBPF_DEBUG_UDP_RECV_READ_FAIL 5
#define EBPF_DEBUG_UNION_PRIMARY_OK   6
#define EBPF_DEBUG_UNION_FALLBACK_OK  7
BPF_ARRAY(ebpf_debug_fail, u64, 16);

// Debug: distribution of iov_iter.iter_type (0=ITER_UBUF, 1=ITER_IOVEC, 2=ITER_KVEC, ...)
BPF_ARRAY(ebpf_debug_iter_type, u64, 16);

// Debug: which read succeeded — 0=user_ok, 1=kernel_ok
BPF_ARRAY(ebpf_debug_read, u64, 4);

// Map для сохранения контекста между kprobe и kretprobe
struct recv_context {
    void *data_ptr;
    u8   iter_type;  // ITER_UBUF=user buffer: must use bpf_probe_read_user only
    u32  saddr;
    u32  daddr;
    u16  sport;
    u16  dport;
    u8   protocol;
};
BPF_HASH(recv_ctx_map, u64, struct recv_context, 10240);

// Контекст для TCP sendmsg (kretprobe)
struct send_context {
    void *data_ptr;
    u8   iter_type;   // UBUF = only user read
    struct msghdr *msg;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 cgroup_id;
    u32 netns_id;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char comm[16];
};
BPF_HASH(send_ctx_map, u64, struct send_context, 10240);

// ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====

// Получение ID network namespace
static __always_inline u32 get_netns_id(struct sock *sk) {
    if (!sk) {
        return 0;
    }
    
    u32 netns = 0;
    struct net *net = NULL;
    
    // Безопасное чтение указателя на net структуру
    long ret = bpf_probe_read_kernel(&net, sizeof(net), &sk->__sk_common.skc_net.net);
    if (ret == 0 && net) {
        bpf_probe_read_kernel(&netns, sizeof(netns), &net->ns.inum);
    }
    
    return netns;
}

// Парсинг DNS заголовка с bounds checking
static __always_inline void parse_dns_header(u8 *data, u16 data_len, struct dns_event *event) {
    // DNS Header format (12 bytes minimum):
    // [0-1]  Transaction ID
    // [2-3]  Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    // [4-5]  Questions
    // [6-7]  Answers
    // [8-9]  Authority
    // [10-11] Additional
    
    // BOUNDS CHECK: минимум 12 байт для заголовка
    if (!data || data_len < DNS_HEADER_SIZE) {
        event->dns_id = 0;
        event->dns_flags = 0;
        event->dns_questions = 0;
        event->dns_answers = 0;
        return;
    }
    
        event->dns_id = (data[0] << 8) | data[1];
        event->dns_flags = (data[2] << 8) | data[3];
        event->dns_questions = (data[4] << 8) | data[5];
        event->dns_answers = (data[6] << 8) | data[7];
    }

// Константы iter_type из include/linux/uio.h (могут отличаться между ядрами)
#ifndef ITER_UBUF
#define ITER_UBUF 0
#endif
#ifndef ITER_IOVEC
#define ITER_IOVEC 1
#endif

// Получение указателя на данные из iov_iter.
// Совместимость: рассчитано на ядро 5.15+ (layout из mainline uio.h).
// В разных ядрах layout может отличаться, поэтому пробуем несколько смещений.
// Часто встречается:
// - iter_type: 0
// - iov_offset: 8
// - union (__iov/__kvec/__ubuf_iovec): 24
// В старых/иных сборках union может оказаться на 16.
#define IOV_ITER_ITER_TYPE_OFF  0
#define IOV_ITER_IOV_OFFSET_OFF 8
#define IOV_ITER_UNION_OFF_PRIMARY   24
#define IOV_ITER_UNION_OFF_FALLBACK  16

static __always_inline void *extract_data_ptr_from_iter_union(struct iov_iter *iter, u8 iter_type, int union_off) {
    void *data_ptr = NULL;
    long ret;

    if (iter_type == ITER_UBUF) {
        // struct iovec __ubuf_iovec; iov_base — первое поле
        ret = bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)iter + union_off);
        return (ret == 0) ? data_ptr : NULL;
    }

    if (iter_type == ITER_IOVEC) {
        const struct iovec *iov = NULL;
        ret = bpf_probe_read_kernel(&iov, sizeof(iov), (void *)iter + union_off);
        if (ret != 0 || !iov) {
            return NULL;
        }
        ret = bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)iov);
        return (ret == 0) ? data_ptr : NULL;
    }

    // ITER_KVEC встречается в части путей ядра/контейнерной сети.
    // На разных версиях/конфигурациях может быть 2 или 8.
    if (iter_type == 2 || iter_type == 8) {
        const struct kvec *kv = NULL;
        ret = bpf_probe_read_kernel(&kv, sizeof(kv), (void *)iter + union_off);
        if (ret != 0 || !kv) {
            return NULL;
        }
        ret = bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)kv);
        return (ret == 0) ? data_ptr : NULL;
    }

    return NULL;
}

// iter_type_out: set to iter_type so caller can use user-only read for UBUF
static __always_inline void *get_data_ptr_from_iter(struct iov_iter *iter, u8 *iter_type_out) {
    if (!iter || !iter_type_out) {
        return NULL;
    }
    
    void *data_ptr = NULL;
    u8 iter_type = 0;
    u64 iov_offset = 0;
    long ret;
    
    ret = bpf_probe_read_kernel(&iter_type, sizeof(iter_type), (void *)iter + IOV_ITER_ITER_TYPE_OFF);
    if (ret != 0) {
        return NULL;
    }
    *iter_type_out = iter_type;

    // Debug: распределение iter_type (0=UBUF, 1=IOVEC, 2=KVEC, …)
    u32 it_key = (u32)(iter_type & 0xf);
    ebpf_debug_iter_type.increment(it_key);

    // iov_offset сдвигает текущую позицию внутри iovec/kvec/ubuf
    bpf_probe_read_kernel(&iov_offset, sizeof(iov_offset), (void *)iter + IOV_ITER_IOV_OFFSET_OFF);

    // Сначала пробуем union на 24, затем на 16
    data_ptr = extract_data_ptr_from_iter_union(iter, iter_type, IOV_ITER_UNION_OFF_PRIMARY);
    if (data_ptr) {
        ebpf_debug_fail.increment(EBPF_DEBUG_UNION_PRIMARY_OK);
        return (void *)((char *)data_ptr + iov_offset);
    }
    data_ptr = extract_data_ptr_from_iter_union(iter, iter_type, IOV_ITER_UNION_OFF_FALLBACK);
    if (data_ptr) {
        ebpf_debug_fail.increment(EBPF_DEBUG_UNION_FALLBACK_OK);
        return (void *)((char *)data_ptr + iov_offset);
    }

    return NULL;
}

// Helper: try user read first, fallback to kernel read (for IOVEC/KVEC when data may be in kernel)
static __always_inline long try_read_data(void *dst, u32 size, void *src) {
    long ret = bpf_probe_read_user(dst, size, src);
    if (ret == 0) {
        ebpf_debug_read.increment(0);  // user_read_ok
        return 0;
    }
    ret = bpf_probe_read_kernel(dst, size, src);
    if (ret == 0) {
        ebpf_debug_read.increment(1);  // kernel_read_ok
    }
    return ret;
}

// For UBUF the pointer is user-space; kernel read returns garbage (wrong domain, byte[12]=0).
// Use only bpf_probe_read_user for UBUF so we don't show corrupted data.
static __always_inline long read_dns_payload(void *dst, u32 size, void *src, u8 iter_type) {
    if (iter_type == ITER_UBUF) {
        long ret = bpf_probe_read_user(dst, size, src);
        if (ret == 0) {
            ebpf_debug_read.increment(0);
        }
        return ret;  // no kernel fallback — would read wrong memory
    }
    return try_read_data(dst, size, src);
}

// ===== UDP DNS ЗАПРОСЫ =====

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    // Проверка на NULL (best practice)
    if (!sk || !msg) {
        return 0;
    }
    
    // Фильтрация по порту 53 (DNS)
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (dport != __constant_htons(53)) {
        return 0;
    }
    
    struct dns_event event = {};
    
    // Timestamp (для анализа частоты - детекция C2, IP-Over-DNS)
    event.timestamp_ns = bpf_ktime_get_ns();
    
    // Метаданные процесса
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Идентификация пода
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.netns_id = get_netns_id(sk);
    
    // Сетевые данные
    bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    event.dport = 53;
    event.protocol = 17;  // UDP
    event.direction = 1;  // Query
    
    // Получаем данные из msg_iter
    struct iov_iter iter;
    long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    
    if (ret != 0) {
        event.data_len = 0;
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_SEND_ITER_FAIL);
        events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    
    u8 iter_type = 0;
    void *data_ptr = get_data_ptr_from_iter(&iter, &iter_type);
    
    if (data_ptr) {
        // UBUF = user buffer: only user read; else try user then kernel
        ret = read_dns_payload(event.dns_data, sizeof(event.dns_data), data_ptr, iter_type);
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
    
    // Отправляем ВСЕ DNS события в userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// ===== UDP DNS ОТВЕТЫ (kprobe + kretprobe) =====

int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    // Проверка на NULL (best practice)
    if (!sk || !msg) {
        return 0;
    }
    
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (dport != __constant_htons(53)) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct recv_context rctx = {};
    
    // Сохраняем сетевые данные
    bpf_probe_read_kernel(&rctx.saddr, sizeof(rctx.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&rctx.daddr, sizeof(rctx.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&rctx.sport, sizeof(rctx.sport), &sk->__sk_common.skc_num);
    rctx.dport = 53;
    rctx.protocol = 17;
    
    // Получаем указатель на буфер и тип итератора (UBUF = только user read)
    struct iov_iter iter;
    long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    
    rctx.iter_type = 0xff;  // invalid
    if (ret == 0) {
        u8 it = 0;
        rctx.data_ptr = get_data_ptr_from_iter(&iter, &it);
        rctx.iter_type = it;
    } else {
        rctx.data_ptr = NULL;
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_RECV_NO_PTR);
    }
    if (!rctx.data_ptr && ret == 0) {
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_RECV_NO_PTR);
    }
    
    recv_ctx_map.update(&pid_tgid, &rctx);
    return 0;
}

int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct recv_context *rctx = recv_ctx_map.lookup(&pid_tgid);
    if (!rctx || !rctx->data_ptr) {
        if (rctx && !rctx->data_ptr) {
            ebpf_debug_fail.increment(EBPF_DEBUG_UDP_RECV_NO_PTR);
        }
        recv_ctx_map.delete(&pid_tgid);
        return 0;
    }
    
    struct dns_event event = {};
    
    event.timestamp_ns = bpf_ktime_get_ns();
    
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.netns_id = 0;  // Не доступен в kretprobe без sock
    
    // Сетевые данные из контекста
    event.saddr = rctx->saddr;
    event.daddr = rctx->daddr;
    event.sport = rctx->sport;
    event.dport = rctx->dport;
    event.protocol = rctx->protocol;
    event.direction = 2;  // Response
    
    // UBUF = user buffer: only user read; else try user then kernel
    long ret = read_dns_payload(event.dns_data, sizeof(event.dns_data), rctx->data_ptr, rctx->iter_type);
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

// ===== TCP DNS ЗАПРОСЫ (kprobe + kretprobe) =====

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    // Проверка на NULL (best practice)
    if (!sk || !msg) {
        return 0;
    }
    
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (dport != __constant_htons(53)) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    u8 iter_type = 0xff;
    struct iov_iter iter;
    long ret_iter = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    void *data_ptr = NULL;
    
    if (ret_iter == 0) {
        data_ptr = get_data_ptr_from_iter(&iter, &iter_type);
    }
    
    if (data_ptr) {
        u8 tcp_header[2];
        long ret = read_dns_payload(tcp_header, sizeof(tcp_header), data_ptr, iter_type);
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
                ret = read_dns_payload(event.dns_data,
                                       dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                       data_ptr + 2, iter_type);
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
    sctx.iter_type = iter_type;
    sctx.msg = msg;
    
    send_ctx_map.update(&pid_tgid, &sctx);
    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct send_context *sctx = send_ctx_map.lookup(&pid_tgid);
    if (!sctx || !sctx->data_ptr) {
        if (sctx) {
            send_ctx_map.delete(&pid_tgid);
        }
        return 0;
    }
    
    struct dns_event event = {};
    
    // Копируем данные из контекста
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
    event.protocol = 6;   // TCP
    event.direction = 1;  // Query
    
    // В kretprobe данные уже отправлены, но указатель может быть еще валидным
    // Пробуем прочитать данные
    void *data_ptr = sctx->data_ptr;
    int data_read = 0;
    
    u8 it = sctx->iter_type;
    if (data_ptr) {
        u8 tcp_header[2];
        long ret = read_dns_payload(tcp_header, sizeof(tcp_header), data_ptr, it);
        if (ret == 0) {
            u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
            if (dns_len >= 12 && dns_len <= 512) {
                ret = read_dns_payload(event.dns_data,
                                       dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                       data_ptr + 2, it);
                if (ret == 0) {
                    event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                    parse_dns_header(event.dns_data, event.data_len, &event);
                    data_read = 1;
                }
            }
        }
        if (!data_read) {
            long ret = read_dns_payload(event.dns_data, MAX_DNS_DATA, data_ptr, it);
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
            u8 it2 = 0;
            void *new_data_ptr = get_data_ptr_from_iter(&iter, &it2);
            if (new_data_ptr) {
                u8 tcp_header[2];
                ret = read_dns_payload(tcp_header, sizeof(tcp_header), new_data_ptr, it2);
                if (ret == 0) {
                    u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
                    if (dns_len >= 12 && dns_len <= 512) {
                        ret = read_dns_payload(event.dns_data,
                                               dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                               new_data_ptr + 2, it2);
                        if (ret == 0) {
                            event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                            parse_dns_header(event.dns_data, event.data_len, &event);
                            data_read = 1;
                        }
                    }
                }
                if (!data_read) {
                    ret = read_dns_payload(event.dns_data, MAX_DNS_DATA, new_data_ptr, it2);
                    if (ret == 0) {
                        event.data_len = MAX_DNS_DATA;
                        parse_dns_header(event.dns_data, event.data_len, &event);
                        data_read = 1;
                    }
                }
            }
        }
    }
    
    // Если все еще не удалось, отправляем с data_len=0
    if (!data_read) {
        event.data_len = 0;
    }
    
    send_ctx_map.delete(&pid_tgid);
    
    // Отправляем ВСЕ DNS события в userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// ===== TCP DNS ОТВЕТЫ =====

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    // Проверка на NULL (best practice)
    if (!sk || !msg) {
        return 0;
    }
    
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (dport != __constant_htons(53)) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct recv_context rctx = {};
    
    // Сохраняем сетевые данные
    bpf_probe_read_kernel(&rctx.saddr, sizeof(rctx.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&rctx.daddr, sizeof(rctx.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&rctx.sport, sizeof(rctx.sport), &sk->__sk_common.skc_num);
    rctx.dport = 53;
    rctx.protocol = 6;
    rctx.iter_type = 0xff;
    
    struct iov_iter iter;
    long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    if (ret == 0) {
        u8 it = 0;
        rctx.data_ptr = get_data_ptr_from_iter(&iter, &it);
        rctx.iter_type = it;
    } else {
        rctx.data_ptr = NULL;
    }
    
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
    event.netns_id = 0;  // Не доступен в kretprobe без sock
    
    event.saddr = rctx->saddr;
    event.daddr = rctx->daddr;
    event.sport = rctx->sport;
    event.dport = rctx->dport;
    event.protocol = rctx->protocol;
    event.direction = 2;  // Response
    
    u8 tcp_header[2];
    long ret = read_dns_payload(tcp_header, sizeof(tcp_header), rctx->data_ptr, rctx->iter_type);
    if (ret == 0) {
        u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
        if (dns_len >= 12 && dns_len <= 512) {
            ret = read_dns_payload(event.dns_data,
                                   dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                   rctx->data_ptr + 2, rctx->iter_type);
            if (ret == 0) {
                event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                parse_dns_header(event.dns_data, event.data_len, &event);
            } else {
                read_dns_payload(event.dns_data, MAX_DNS_DATA, rctx->data_ptr, rctx->iter_type);
                event.data_len = MAX_DNS_DATA;
                parse_dns_header(event.dns_data, event.data_len, &event);
            }
        } else {
            read_dns_payload(event.dns_data, MAX_DNS_DATA, rctx->data_ptr, rctx->iter_type);
            event.data_len = MAX_DNS_DATA;
            parse_dns_header(event.dns_data, event.data_len, &event);
        }
    } else {
        read_dns_payload(event.dns_data, MAX_DNS_DATA, rctx->data_ptr, rctx->iter_type);
        event.data_len = MAX_DNS_DATA;
        parse_dns_header(event.dns_data, event.data_len, &event);
    }
    
    recv_ctx_map.delete(&pid_tgid);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
