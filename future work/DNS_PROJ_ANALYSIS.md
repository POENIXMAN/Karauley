# Анализ кода из dns-proj для улучшения нашего модуля

## Полезные алгоритмы и подходы

### 1. DNS Query Class (QTYPE) фильтрация

**Где**: `dns_tc.bpf.c:309-331`

**Что делает**:
- Фильтрует DNS запросы по QTYPE (класс запроса)
- Разделяет на BENIGN, SUSPICIOUS, MALICIOUS

**Код**:
```c
#define EXFIL_SECURITY_FILTER_DNS_QUERY_CLASS(__dns_query_class) \
    do {                                            \
        switch ((__dns_query_class)){               \
            case 0x0001:  // A
            case 0x0002:  // NS
            case 0x0005:  // CNAME
            case 0x0006:  // SOA
            case 0x001C:  // AAAA
            case 0x0041:  // OPT (EDNS0)
                return BENIGN;                      \
            case 0x000F:  // MX
            case 0x0021:  // SRV
            case 0x0023:  // NSEC
            case 0x0029:  // A6
            case 0x0010:  // TXT
                return SUSPICIOUS;                  \
            case 0x00FF:  // ANY
            case 0x000A:  // NULL
                return MALICIOUS;                   \
            default:                                \
                return SUSPICIOUS;                  \
        }                                           \
    }while(0);
```

**Применение для нас**:
- ✅ **Можно добавить в kernel** - быстрая фильтрация подозрительных QTYPE
- ✅ **TXT запросы** (0x0010) помечаются как SUSPICIOUS - это важно для C2 детекции
- ✅ **NULL записи** (0x000A) помечаются как MALICIOUS - это IP-Over-DNS (iodine)

**Где добавить**:
- В функцию `parse_dns_header()` после чтения QTYPE
- Быстро отфильтровать явно подозрительные запросы

---

### 2. Rate Limiting в Kernel

**Где**: `dns_tc.bpf.c:280-306`

**Что делает**:
- Volume-based rate limiting (leaky bucket)
- Token bucket rate limiting
- Защита от DNS flood атак

**Код**:
```c
struct dns_volume_stats {
    __u64 last_timestamp;
    __u32 packet_size;
} __attribute__((packed));

// Volume-based (leaky bucket)
struct exfil_security_egress_volume_rate_limit_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);
    __type(value, struct dns_volume_stats);
    __uint(max_entries, 1);
} exfil_security_egress_volume_rate_limit_map SEC(".maps");
```

**Применение для нас**:
- ⚠️ **Можно добавить, но не обязательно** - у нас детекция, а не блокировка
- ✅ **Полезно для защиты** от flood атак в production
- ⚠️ **Усложняет код** - лучше оставить в userspace

**Рекомендация**: Оставить в userspace, но можно добавить как опциональную функцию.

---

### 3. Счетчик туннелей с порогом

**Где**: `dns_tun.bpf.c:70-93`

**Что делает**:
- Считает количество DNS пакетов через туннель
- При превышении порога (100 пакетов) возвращает флаг для дропа

**Код**:
```c
#define MAX_TUNNEL_TUN_TAP_TRANSFER_THRESHOLD 100

static __always_inline bool __inc_tunnel_packet_transfer() {
    __u32 TUNNEL_METRIC_KEY = 0;
    __u32 *tunnel_layer7_dns_count = bpf_map_lookup_elem(&exfil_tunnel_dns_encap_transfer, &TUNNEL_METRIC_KEY);
    if (tunnel_layer7_dns_count) {
        if (*tunnel_layer7_dns_count >= MAX_TUNNEL_TUN_TAP_TRANSFER_THRESHOLD) {
            // Reset counter
            __u32 reset_kernel_packet_value = 0;
            bpf_map_update_elem(&exfil_tunnel_dns_encap_transfer, &TUNNEL_METRIC_KEY, &reset_kernel_packet_value, 0);
            return 1; // Drop packet
        }
        __sync_fetch_and_add(tunnel_layer7_dns_count, 1); // Atomic increment
    } else {
        __u32 init_tunnel_count = 1;
        bpf_map_update_elem(&exfil_tunnel_dns_encap_transfer, &TUNNEL_METRIC_KEY, &init_tunnel_count, 0);
    }
    return 0;
}
```

**Применение для нас**:
- ⚠️ **Не подходит напрямую** - у нас нет блокировки пакетов
- ✅ **Можно адаптировать** - считать подозрительные пакеты по PID/cgroup_id
- ✅ **Полезно для детекции** - если много подозрительных запросов от одного процесса

**Рекомендация**: Можно добавить счетчик подозрительных запросов по PID в kernel, но детекцию оставить в userspace.

---

### 4. C2 Health Check Detection

**Где**: `dns_tc.bpf.c:569-598` (функция `check_for_c2c_health_process`)

**Что делает**:
- Проверяет паттерны C2 health check
- Анализирует длину домена и query class

**Применение для нас**:
- ✅ **Уже реализовано в userspace** - `C2Detector` в `dns_analyzer_improved.py`
- ⚠️ **Не нужно в kernel** - слишком сложная логика

---

### 5. Subdomain Range Filtering

**Где**: `dns_tc.bpf.c:340-363`

**Что делает**:
- Фильтрует по длине subdomain labels
- Использует bitset для приоритетов нарушений

**Применение для нас**:
- ⚠️ **Слишком сложно для kernel** - требует парсинга домена
- ✅ **Уже реализовано в userspace** - `ExfiltrationDetector` проверяет длину домена

---

### 6. Dynamic Blacklist для C2 серверов

**Где**: `dns_tc.bpf.c:365-388`

**Что делает**:
- Динамический blacklist IP адресов C2 серверов
- Блокирует трафик на уровне L3

**Код**:
```c
#if L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
    static __always_inline bool __l3_ipv4_netpool_egress_filter_for_dns_c2_server(struct iphdr *ip) {
        __u32 daddr = bpf_ntohl(ip->daddr);
        __u32 *isDynamicBlacklisted = bpf_map_lookup_elem(&exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter, &daddr);
        if (isDynamicBlacklisted) 
            return DROP_L3_DYANMIC_NETPOOL_TRAFFIC;
        return false;
    }
#endif
```

**Применение для нас**:
- ✅ **Можно добавить** - быстрая проверка blacklist в kernel
- ✅ **Полезно для production** - блокировка известных C2 серверов
- ⚠️ **Требует userspace** для обновления blacklist

**Рекомендация**: Можно добавить как опциональную функцию для production.

---

## Что стоит добавить в наш код

### 1. DNS Query Class фильтрация (PRIORITY: HIGH)

**Почему**:
- Быстрая фильтрация подозрительных QTYPE в kernel
- TXT запросы (C2) и NULL записи (IP-Over-DNS) сразу помечаются
- Не требует парсинга домена

**Где добавить**:
- В функцию `parse_dns_header()` после чтения QTYPE
- Добавить поле `suspicious_qtype` в `dns_event`

**Код**:
```c
// В parse_dns_header() после чтения QTYPE
static __always_inline u8 check_qtype_suspicious(u16 qtype) {
    switch (qtype) {
        case 0x0001:  // A
        case 0x0002:  // NS
        case 0x0005:  // CNAME
        case 0x0006:  // SOA
        case 0x001C:  // AAAA
        case 0x0041:  // OPT (EDNS0)
            return 0;  // BENIGN
        case 0x0010:  // TXT (C2)
        case 0x000F:  // MX
        case 0x0021:  // SRV
            return 1;  // SUSPICIOUS
        case 0x00FF:  // ANY
        case 0x000A:  // NULL (IP-Over-DNS)
            return 2;  // MALICIOUS
        default:
            return 1;  // SUSPICIOUS
    }
}
```

---

### 2. Счетчик подозрительных запросов по PID (PRIORITY: MEDIUM)

**Почему**:
- Быстрая детекция процессов с множественными подозрительными запросами
- Можно использовать для раннего предупреждения

**Где добавить**:
- Map для хранения счетчиков по PID
- Инкремент при обнаружении подозрительного QTYPE

**Код**:
```c
struct suspicious_count {
    u32 count;
    u64 last_timestamp;
};
BPF_HASH(suspicious_pid_map, u32, struct suspicious_count, 10240);

// В kprobe после parse_dns_header
if (event.suspicious_qtype > 0) {
    u32 pid = event.pid;
    struct suspicious_count *cnt = suspicious_pid_map.lookup(&pid);
    if (cnt) {
        __sync_fetch_and_add(&cnt->count, 1);
        cnt->last_timestamp = bpf_ktime_get_ns();
    } else {
        struct suspicious_count new_cnt = {.count = 1, .last_timestamp = bpf_ktime_get_ns()};
        suspicious_pid_map.update(&pid, &new_cnt);
    }
}
```

---

### 3. Dynamic Blacklist для C2 серверов (PRIORITY: LOW)

**Почему**:
- Полезно для production
- Требует userspace для обновления

**Где добавить**:
- Map для blacklist IP адресов
- Проверка в kprobe перед отправкой события

**Код**:
```c
BPF_HASH(c2_blacklist, u32, u8, 10240);

// В kprobe перед отправкой события
u32 daddr = event.daddr;
u8 *is_blacklisted = c2_blacklist.lookup(&daddr);
if (is_blacklisted) {
    // Пометить событие как blacklisted
    event.is_blacklisted = 1;
}
```

---

## Что НЕ стоит добавлять

### 1. Rate Limiting в Kernel
- **Причина**: У нас детекция, а не блокировка. Rate limiting лучше в userspace.

### 2. Полный парсинг домена в Kernel
- **Причина**: Слишком сложно для eBPF verifier. Уже реализовано в userspace.

### 3. C2 Health Check в Kernel
- **Причина**: Слишком сложная логика. Уже реализовано в userspace.

---

## Итоговые рекомендации

### Добавить сейчас (для улучшения детекции):

1. ✅ **DNS Query Class фильтрация** - быстрая фильтрация подозрительных QTYPE
2. ✅ **Счетчик подозрительных запросов** - детекция процессов с множественными подозрительными запросами

### Добавить позже (для production):

3. ⚠️ **Dynamic Blacklist** - блокировка известных C2 серверов
4. ⚠️ **Rate Limiting** - защита от flood атак

### Не добавлять:

5. ❌ **Полный парсинг домена** - слишком сложно, уже в userspace
6. ❌ **C2 Health Check** - слишком сложно, уже в userspace

---

## Выводы

**Основные находки**:
1. **DNS Query Class фильтрация** - самое полезное, можно добавить сразу
2. **Счетчик подозрительных запросов** - полезно для ранней детекции
3. **Dynamic Blacklist** - полезно для production, но требует userspace

**Наш подход правильный**:
- ✅ Детекция в userspace (гибкость, сложная логика)
- ✅ Минимальная обработка в kernel (производительность, простота)
- ✅ Ring Buffer для передачи событий (эффективность)

**Что улучшить**:
- Добавить быструю фильтрацию по QTYPE в kernel
- Добавить счетчик подозрительных запросов по PID

