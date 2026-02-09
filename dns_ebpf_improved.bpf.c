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
#define EBPF_DEBUG_UDP_SEND_ITER_FAIL  1
#define EBPF_DEBUG_UDP_SEND_PTR_NULL  2
#define EBPF_DEBUG_UDP_SEND_READ_FAIL 3
#define EBPF_DEBUG_UDP_RECV_NO_PTR    4
#define EBPF_DEBUG_UDP_RECV_READ_FAIL 5
BPF_ARRAY(ebpf_debug_fail, u64, 8);

// Map для сохранения контекста между kprobe и kretprobe
struct recv_context {
    void *data_ptr;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  protocol;
};
BPF_HASH(recv_ctx_map, u64, struct recv_context, 10240);

// Контекст для TCP sendmsg (kretprobe)
struct send_context {
    void *data_ptr;  // Указатель на данные
    struct msghdr *msg; // Сохраняем msg для чтения в kretprobe
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

// Константы iter_type из include/linux/uio.h (5.15+)
#ifndef ITER_UBUF
#define ITER_UBUF 0
#endif
#ifndef ITER_IOVEC
#define ITER_IOVEC 1
#endif

// Получение указателя на данные из iov_iter.
// Совместимость: рассчитано на ядро 5.15+ (layout из mainline uio.h).
// В 5.15+ ubuf/__iov во вложенной анонимной union — используем смещения.
// Смещения: iter_type=0; union после iter_type,nofault,data_source,iov_offset → 16.
// На 6.x layout может совпадать; при сбоях на новых ядрах проверьте offsetof(struct iov_iter).
#define IOV_ITER_ITER_TYPE_OFF  0
#define IOV_ITER_UNION_OFF      16

static __always_inline void *get_data_ptr_from_iter(struct iov_iter *iter) {
    if (!iter) {
        return NULL;
    }
    
    void *data_ptr = NULL;
    u8 iter_type = 0;
    long ret;
    
    ret = bpf_probe_read_kernel(&iter_type, sizeof(iter_type), (void *)iter + IOV_ITER_ITER_TYPE_OFF);
    if (ret != 0) {
        return NULL;
    }
    
    if (iter_type == ITER_UBUF) {
        // Один буфер: в union лежит struct iovec __ubuf_iovec, iov_base в начале
        ret = bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)iter + IOV_ITER_UNION_OFF);
        return (ret == 0) ? data_ptr : NULL;
    }
    
    if (iter_type == ITER_IOVEC) {
        // Массив iovec: в union лежит указатель __iov на const struct iovec*
        const struct iovec *iov = NULL;
        ret = bpf_probe_read_kernel(&iov, sizeof(iov), (void *)iter + IOV_ITER_UNION_OFF);
        if (ret != 0 || !iov) {
            return NULL;
        }
        // iov_base — первое поле struct iovec, читаем по указателю iov
        ret = bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), (void *)iov);
        return (ret == 0) ? data_ptr : NULL;
    }
    
    return NULL;
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
    
    void *data_ptr = get_data_ptr_from_iter(&iter);
    
    if (data_ptr) {
        // Читаем DNS пакет
        ret = bpf_probe_read_user(event.dns_data, sizeof(event.dns_data), data_ptr);
        if (ret == 0) {
        event.data_len = MAX_DNS_DATA;
            // Парсим заголовок (с bounds check)
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
    
    // Получаем указатель на буфер
    struct iov_iter iter;
    long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    
    if (ret == 0) {
        rctx.data_ptr = get_data_ptr_from_iter(&iter);
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
    
    // Читаем данные (уже в буфере после recvmsg)
    long ret = bpf_probe_read_user(event.dns_data, sizeof(event.dns_data), rctx->data_ptr);
    if (ret == 0) {
    event.data_len = MAX_DNS_DATA;
        // Парсим заголовок (с bounds check)
        parse_dns_header(event.dns_data, event.data_len, &event);
    } else {
        event.data_len = 0;
        ebpf_debug_fail.increment(EBPF_DEBUG_UDP_RECV_READ_FAIL);
    }
    
    recv_ctx_map.delete(&pid_tgid);
    
    // Отправляем ВСЕ DNS события в userspace
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
    
    // Пробуем прочитать данные сразу в kprobe
    struct iov_iter iter;
    long ret_iter = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    void *data_ptr = NULL;
    
    if (ret_iter == 0) {
        data_ptr = get_data_ptr_from_iter(&iter);
    }
    
    if (data_ptr) {
        // Пробуем прочитать length prefix и данные
        u8 tcp_header[2];
        long ret = bpf_probe_read_user(tcp_header, sizeof(tcp_header), data_ptr);
        
        if (ret == 0) {
            u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
            
            // Проверяем валидность длины
            if (dns_len >= 12 && dns_len <= 512) {
                // Пробуем прочитать DNS данные
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
                
                ret = bpf_probe_read_user(event.dns_data, 
                                         dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                         data_ptr + 2);
                
                if (ret == 0) {
                    // Успешно прочитали - отправляем сразу
                    event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                    parse_dns_header(event.dns_data, event.data_len, &event);
                    events.perf_submit(ctx, &event, sizeof(event));
                    return 0;
                }
            }
        }
    }
    
    // Если не удалось прочитать в kprobe, сохраняем контекст для kretprobe
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
    sctx.msg = msg;  // Сохраняем msg для чтения в kretprobe
    
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
    
    // Сначала пробуем прочитать из сохраненного указателя
    if (data_ptr) {
        // TCP DNS имеет 2-байтный length prefix
        u8 tcp_header[2];
        long ret = bpf_probe_read_user(tcp_header, sizeof(tcp_header), data_ptr);
        
        if (ret == 0) {
            u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
            
            // Проверяем валидность длины (DNS пакет обычно 12-512 байт)
            if (dns_len >= 12 && dns_len <= 512) {
                // Читаем DNS данные после length prefix
                ret = bpf_probe_read_user(event.dns_data, 
                                         dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                         data_ptr + 2);
                
                if (ret == 0) {
                    event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                    parse_dns_header(event.dns_data, event.data_len, &event);
                    data_read = 1;
                }
            }
        }
        
        // Если не удалось прочитать с length prefix, пробуем без него
        if (!data_read) {
            long ret = bpf_probe_read_user(event.dns_data, MAX_DNS_DATA, data_ptr);
            if (ret == 0) {
                event.data_len = MAX_DNS_DATA;
                parse_dns_header(event.dns_data, event.data_len, &event);
                data_read = 1;
            }
        }
    }
    
    // Если не удалось прочитать из указателя, пробуем прочитать из msg->msg_iter в kretprobe
    if (!data_read && sctx->msg) {
        struct iov_iter iter;
        long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &sctx->msg->msg_iter);
        
        if (ret == 0) {
            void *new_data_ptr = get_data_ptr_from_iter(&iter);
            
            if (new_data_ptr) {
                // Пробуем прочитать length prefix
                u8 tcp_header[2];
                ret = bpf_probe_read_user(tcp_header, sizeof(tcp_header), new_data_ptr);
                
                if (ret == 0) {
                    u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
                    
                    if (dns_len >= 12 && dns_len <= 512) {
                        ret = bpf_probe_read_user(event.dns_data, 
                                                 dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                                 new_data_ptr + 2);
                        
                        if (ret == 0) {
                            event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                            parse_dns_header(event.dns_data, event.data_len, &event);
                            data_read = 1;
                        }
                    }
                }
                
                // Если не удалось с length prefix, пробуем без него
                if (!data_read) {
                    ret = bpf_probe_read_user(event.dns_data, MAX_DNS_DATA, new_data_ptr);
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
    rctx.protocol = 6;  // TCP
    
    // Получаем указатель на буфер
    struct iov_iter iter;
    long ret = bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    
    if (ret == 0) {
        rctx.data_ptr = get_data_ptr_from_iter(&iter);
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
    
    // TCP DNS с length prefix
    u8 tcp_header[2];
    long ret = bpf_probe_read_user(tcp_header, sizeof(tcp_header), rctx->data_ptr);
    
    if (ret == 0) {
        u16 dns_len = (tcp_header[0] << 8) | tcp_header[1];
        
        // Проверяем валидность длины (DNS пакет обычно 12-512 байт)
        if (dns_len >= 12 && dns_len <= 512) {
            // Читаем DNS данные после length prefix
            ret = bpf_probe_read_user(event.dns_data, 
                                     dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA,
                                     rctx->data_ptr + 2);
            
            if (ret == 0) {
                event.data_len = dns_len < MAX_DNS_DATA ? dns_len : MAX_DNS_DATA;
                parse_dns_header(event.dns_data, event.data_len, &event);
            } else {
                // Если чтение не удалось, пробуем без length prefix
                bpf_probe_read_user(event.dns_data, MAX_DNS_DATA, rctx->data_ptr);
                event.data_len = MAX_DNS_DATA;
                parse_dns_header(event.dns_data, event.data_len, &event);
            }
        } else {
            // Невалидная длина - пробуем без length prefix (может быть данные уже без префикса)
            bpf_probe_read_user(event.dns_data, MAX_DNS_DATA, rctx->data_ptr);
            event.data_len = MAX_DNS_DATA;
            parse_dns_header(event.dns_data, event.data_len, &event);
        }
    } else {
        // Не удалось прочитать length prefix - пробуем без него
        bpf_probe_read_user(event.dns_data, MAX_DNS_DATA, rctx->data_ptr);
    event.data_len = MAX_DNS_DATA;
        parse_dns_header(event.dns_data, event.data_len, &event);
    }
    
    recv_ctx_map.delete(&pid_tgid);
    
    // Отправляем ВСЕ DNS события в userspace
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
