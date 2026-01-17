# eBPF DNS Monitor: Глубокое погружение

## Содержание

1. [Введение в eBPF](#1-введение-в-ebpf)
2. [Архитектура перехвата DNS](#2-архитектура-перехвата-dns)
3. [UDP DNS Query: Пошаговый разбор](#3-udp-dns-query-пошаговый-разбор)
4. [UDP DNS Response: kprobe + kretprobe](#4-udp-dns-response-kprobe--kretprobe)
5. [Структуры данных и типы](#5-структуры-данных-и-типы)
6. [Maps: Хранилище данных в eBPF](#6-maps-хранилище-данных-в-ebpf)
7. [Ring Buffer: Передача данных в userspace](#7-ring-buffer-передача-данных-в-userspace)
8. [DNS протокол и парсинг](#8-dns-протокол-и-парсинг)
9. [Ограничения eBPF verifier](#9-ограничения-ebpf-verifier)
10. [Полный цикл события](#10-полный-цикл-события)

---

## 1. Введение в eBPF

### 1.1 Что такое eBPF?

**eBPF (extended Berkeley Packet Filter)** — технология, позволяющая запускать изолированные программы внутри ядра Linux без изменения исходного кода ядра или загрузки модулей.

```
┌─────────────────────────────────────────────────────────────┐
│                      USERSPACE                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │   Python    │    │   Go/Rust   │    │     C       │      │
│  │  Application│    │  Application│    │  Application│      │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│                            ▼                                 │
│                    ┌───────────────┐                         │
│                    │  BCC / libbpf │  ← Загрузчик eBPF       │
│                    └───────┬───────┘                         │
├────────────────────────────┼─────────────────────────────────┤
│                      KERNEL│SPACE                            │
│                            ▼                                 │
│                    ┌───────────────┐                         │
│                    │ eBPF Verifier │  ← Проверка безопасности│
│                    └───────┬───────┘                         │
│                            │                                 │
│                            ▼                                 │
│                    ┌───────────────┐                         │
│                    │  JIT Compiler │  ← Компиляция в машкод  │
│                    └───────┬───────┘                         │
│                            │                                 │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   eBPF Programs                          ││
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ ││
│  │  │  kprobe  │  │ kretprobe│  │tracepoint│  │   XDP    │ ││
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ ││
│  └───────┼─────────────┼─────────────┼─────────────┼────────┘│
│          │             │             │             │         │
│          ▼             ▼             ▼             ▼         │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Linux Kernel Functions                      ││
│  │   udp_sendmsg()  tcp_recvmsg()  sys_open()  etc.        ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Типы eBPF программ

| Тип | Описание | Когда использовать |
|-----|----------|-------------------|
| **kprobe** | Перехват входа в функцию ядра | Доступ к аргументам функции |
| **kretprobe** | Перехват выхода из функции | Доступ к возвращаемому значению, данные после выполнения |
| **tracepoint** | Заранее определенные точки в ядре | Стабильный API между версиями ядра |
| **XDP** | Обработка пакетов до network stack | Высокопроизводительная фильтрация |
| **tc** | Traffic Control | Модификация пакетов |

### 1.3 Почему kprobe для DNS?

**Альтернативы**:

1. **XDP** — слишком рано (до расшифровки IP/UDP)
2. **tc** — после IP, но до приложения
3. **kprobe** ✅ — перехват на уровне socket API (видим процесс, данные)

```
Packet Flow:
                                                      
 NIC → XDP → tc → ip_rcv → udp_rcv → udp_recvmsg() → Application
                                            ↑
                                      kprobe здесь
                                      (видим приложение)
```

---

## 2. Архитектура перехвата DNS

### 2.1 Точки перехвата

```
┌─────────────────────────────────────────────────────────────┐
│                     APPLICATION                              │
│                                                              │
│     ┌─────────────────┐      ┌─────────────────┐            │
│     │   dig/nslookup  │      │   Application   │            │
│     └────────┬────────┘      └────────┬────────┘            │
│              │                        │                      │
│              │    DNS Query           │    DNS Response      │
│              ▼                        ▼                      │
│     ┌─────────────────┐      ┌─────────────────┐            │
│     │   sendmsg()     │      │   recvmsg()     │            │
│     └────────┬────────┘      └────────┬────────┘            │
└──────────────┼────────────────────────┼──────────────────────┘
               │                        │
═══════════════╪════════════════════════╪═══════════════════════
               │      KERNEL SPACE      │
               ▼                        ▼
       ┌───────────────┐       ┌───────────────────┐
       │ udp_sendmsg() │       │  udp_recvmsg()    │
       │               │       │                   │
       │  ┌─────────┐  │       │  ┌─────────────┐  │
       │  │ kprobe  │◄─┼───────┼──┤   kprobe    │  │
       │  └─────────┘  │       │  └─────────────┘  │
       │               │       │         │         │
       │               │       │  ┌──────▼──────┐  │
       │               │       │  │ [function]  │  │
       │               │       │  │  executes   │  │
       │               │       │  └──────┬──────┘  │
       │               │       │         │         │
       │               │       │  ┌──────▼──────┐  │
       │               │       │  │ kretprobe   │◄─┼── Данные готовы!
       │               │       │  └─────────────┘  │
       └───────┬───────┘       └───────────────────┘
               │
               ▼
        ┌─────────────┐
        │ Network TX  │
        └─────────────┘
```

### 2.2 Почему разные подходы для Query и Response?

#### DNS Query (sendmsg)

```c
// Приложение вызывает:
sendmsg(fd, &msg, flags);
         ↓
// Ядро вызывает:
udp_sendmsg(sk, msg, len);
             ↑
          msg->msg_iter содержит DNS данные
          СРАЗУ ДОСТУПНЫ в kprobe!
```

**Вывод**: Для Query достаточно **только kprobe** — данные уже в буфере.

#### DNS Response (recvmsg)

```c
// Приложение вызывает:
recvmsg(fd, &msg, flags);
         ↓
// Ядро вызывает:
udp_recvmsg(sk, msg, len, flags, addr_len);
              ↑
           msg->msg_iter = ПУСТОЙ БУФЕР!
           Данные будут ЗАПИСАНЫ сюда.
```

```
Timeline:

  kprobe                    kretprobe
     │                          │
     ▼                          ▼
     ┌──────────────────────────┐
     │    udp_recvmsg()         │
     │                          │
     │  msg_iter: [ пусто ]     │   msg_iter: [ DNS данные ]
     │       ↑                  │         ↑
     │  До копирования          │   После копирования
     └──────────────────────────┘
```

**Вывод**: Для Response нужны **оба** — kprobe для сохранения указателя, kretprobe для чтения данных.

---

## 3. UDP DNS Query: Пошаговый разбор

### 3.1 Полный код функции

```c
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    // === ЭТАП 1: Фильтрация по порту ===
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (dport != __constant_htons(53)) {
        return 0;
    }
    
    // === ЭТАП 2: Создание структуры события ===
    struct dns_event event = {};
    
    // === ЭТАП 3: Timestamp ===
    event.timestamp_ns = bpf_ktime_get_ns();
    
    // === ЭТАП 4: Метаданные процесса ===
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // === ЭТАП 5: Идентификация контейнера ===
    event.cgroup_id = bpf_get_current_cgroup_id();
    event.netns_id = get_netns_id(sk);
    
    // === ЭТАП 6: Сетевые данные ===
    bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    event.dport = 53;
    event.protocol = 17;  // UDP
    event.direction = 1;  // Query
    
    // === ЭТАП 7: Чтение DNS данных ===
    struct iov_iter iter;
    bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    
    void *data_ptr = get_data_ptr_from_iter(&iter);
    
    if (data_ptr) {
        bpf_probe_read_user(event.dns_data, sizeof(event.dns_data), data_ptr);
        event.data_len = MAX_DNS_DATA;
        parse_dns_header(event.dns_data, event.data_len, &event);
    } else {
        event.data_len = 0;
    }
    
    // === ЭТАП 8: Отправка в userspace ===
    events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}
```

### 3.2 ЭТАП 1: Фильтрация по порту

```c
u16 dport = 0;
bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

if (dport != __constant_htons(53)) {
    return 0;
}
```

#### Почему `bpf_probe_read_kernel()`?

В eBPF нельзя напрямую обращаться к памяти ядра:

```c
// ❌ НЕПРАВИЛЬНО — verifier отклонит
u16 dport = sk->__sk_common.skc_dport;

// ✅ ПРАВИЛЬНО — безопасное чтение
bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
```

**Причина**: eBPF verifier требует, чтобы все доступы к памяти были проверены. `bpf_probe_read_kernel()` — helper-функция, которая:
1. Проверяет валидность указателя
2. Возвращает 0 при успехе, -1 при ошибке
3. Гарантирует безопасность

#### Структура `struct sock`

```c
// Упрощенная структура (net/sock.h)
struct sock {
    struct sock_common __sk_common;
    // ... много других полей
};

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;      // Destination IP
            __be32 skc_rcv_saddr;  // Source IP
        };
    };
    union {
        struct {
            __be16 skc_dport;      // Destination port (network byte order!)
            __u16  skc_num;        // Source port (host byte order)
        };
    };
    struct net *skc_net;           // Network namespace
    // ...
};
```

#### Почему `__constant_htons(53)`?

```
Network Byte Order vs Host Byte Order:

Host (x86):    Little-endian
Network:       Big-endian

Port 53 в разных представлениях:
  Host order:    0x0035 = 53
  Network order: 0x3500 = 13568

Сравнение:
  sk->skc_dport хранит в network order
  Нужно сравнивать в том же формате!
```

```c
// __constant_htons() — compile-time преобразование
// htons() — runtime преобразование

// ✅ Эффективнее (compile-time):
if (dport != __constant_htons(53))

// ❌ Менее эффективно (runtime):
if (dport != htons(53))
```

### 3.3 ЭТАП 2: Создание структуры события

```c
struct dns_event event = {};
```

#### Почему `= {}`?

```c
// ❌ Неинициализированная структура — может содержать мусор
struct dns_event event;

// ✅ Инициализация нулями — все поля = 0
struct dns_event event = {};
```

**Важно для eBPF**: Verifier может отклонить код, если используются неинициализированные переменные.

### 3.4 ЭТАП 3: Timestamp

```c
event.timestamp_ns = bpf_ktime_get_ns();
```

#### Типы времени в Linux

```
┌─────────────────────────────────────────────────────────┐
│                    Типы времени                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  CLOCK_REALTIME ("wall clock")                          │
│  ├── Зависит от NTP                                      │
│  ├── Может "прыгать" назад                              │
│  └── Для отображения пользователю                        │
│                                                          │
│  CLOCK_MONOTONIC (bpf_ktime_get_ns)  ← Используем       │
│  ├── Не зависит от NTP                                   │
│  ├── Только вперед                                       │
│  └── Для измерения интервалов                           │
│                                                          │
│  CLOCK_BOOTTIME                                          │
│  ├── Как MONOTONIC, но включает suspend                 │
│  └── Для таймеров, которые должны работать после sleep  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Почему MONOTONIC?**
- Детекция C2 требует анализа **интервалов** между запросами
- Не важно реальное время, важна **стабильность**
- NTP коррекции могут сбить анализ

### 3.5 ЭТАП 4: Метаданные процесса

```c
u64 pid_tgid = bpf_get_current_pid_tgid();
event.pid = pid_tgid >> 32;
event.tid = pid_tgid & 0xFFFFFFFF;
bpf_get_current_comm(&event.comm, sizeof(event.comm));
```

#### Разбор `pid_tgid`

```
bpf_get_current_pid_tgid() возвращает u64:

┌───────────────────────────────────────────────────────────┐
│ 63                              32 31                    0│
│ ├────────────────────────────────┼────────────────────────┤
│ │           TGID (PID)           │          TID           │
│ └────────────────────────────────┴────────────────────────┘

TGID = Thread Group ID = то, что пользователь видит как PID
TID  = Thread ID = уникальный ID потока

Пример:
  Процесс nginx (PID 1234) с 4 потоками:
    Поток 1: pid_tgid = 1234 << 32 | 1234 = 0x4D200004D2
    Поток 2: pid_tgid = 1234 << 32 | 1235 = 0x4D200004D3
    Поток 3: pid_tgid = 1234 << 32 | 1236 = 0x4D200004D4
    Поток 4: pid_tgid = 1234 << 32 | 1237 = 0x4D200004D5

Извлечение:
  pid = pid_tgid >> 32;           // Сдвиг на 32 бита → TGID
  tid = pid_tgid & 0xFFFFFFFF;    // Маска на младшие 32 бита → TID
```

#### `bpf_get_current_comm()`

```c
bpf_get_current_comm(&event.comm, sizeof(event.comm));
```

Заполняет `comm` именем процесса (до 16 символов):
- `dig`, `nslookup`, `curl`, `python3`

**Ограничение 16 символов**: Это ограничение Linux (TASK_COMM_LEN = 16).

### 3.6 ЭТАП 5: Идентификация контейнера

```c
event.cgroup_id = bpf_get_current_cgroup_id();
event.netns_id = get_netns_id(sk);
```

#### cgroup_id

```
Kubernetes использует cgroups для изоляции pods:

/sys/fs/cgroup/
├── kubepods/
│   ├── burstable/
│   │   ├── pod-abc123/           ← cgroup_id уникален
│   │   │   ├── container-1/
│   │   │   └── container-2/
│   │   └── pod-def456/           ← другой cgroup_id
│   └── guaranteed/
│       └── pod-ghi789/
└── system.slice/
    └── ssh.service/
```

`bpf_get_current_cgroup_id()` возвращает уникальный ID, который можно сопоставить с pod.

#### netns_id (Network Namespace)

```c
static __always_inline u32 get_netns_id(struct sock *sk) {
    u32 netns = 0;
    
    struct net *net = NULL;
    bpf_probe_read_kernel(&net, sizeof(net), &sk->__sk_common.skc_net.net);
    if (net) {
        bpf_probe_read_kernel(&netns, sizeof(netns), &net->ns.inum);
    }
    
    return netns;
}
```

**Путь чтения**:
```
sk → __sk_common → skc_net → net → ns → inum
                                         ↑
                                    namespace inode number
```

**Network namespaces в Kubernetes**:
```
┌─────────────────────────────────────────────────────────┐
│ Host                                                     │
│ netns_id = 4026531840 (default)                         │
│                                                          │
│  ┌────────────────────┐  ┌────────────────────┐         │
│  │ Pod A              │  │ Pod B              │         │
│  │ netns_id = 40265...│  │ netns_id = 40265...│         │
│  │ 31993              │  │ 32145              │         │
│  │                    │  │                    │         │
│  │ eth0: 10.0.0.5     │  │ eth0: 10.0.0.6     │         │
│  └────────────────────┘  └────────────────────┘         │
└─────────────────────────────────────────────────────────┘
```

### 3.7 ЭТАП 6: Сетевые данные

```c
bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
bpf_probe_read_kernel(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
event.dport = 53;
event.protocol = 17;  // UDP
event.direction = 1;  // Query
```

#### Разница между `skc_dport` и `skc_num`

```
┌─────────────────────────────────────────────────────────┐
│ struct sock_common                                       │
├─────────────────────────────────────────────────────────┤
│ skc_dport  = Destination port (NETWORK byte order)      │
│              Хранит 0x3500 для порта 53                 │
│              Нужно ntohs() для отображения              │
│                                                          │
│ skc_num    = Source port (HOST byte order)              │
│              Хранит 0x0035 для порта 53                 │
│              Можно использовать напрямую                │
└─────────────────────────────────────────────────────────┘
```

**Почему так?**
- `skc_dport` приходит из сети → network byte order
- `skc_num` устанавливается локально → host byte order

#### Константы протокола

```c
event.protocol = 17;  // UDP (IPPROTO_UDP)
event.direction = 1;  // Query

// Стандартные значения (netinet/in.h):
// IPPROTO_TCP = 6
// IPPROTO_UDP = 17
```

### 3.8 ЭТАП 7: Чтение DNS данных

```c
struct iov_iter iter;
bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);

void *data_ptr = get_data_ptr_from_iter(&iter);

if (data_ptr) {
    bpf_probe_read_user(event.dns_data, sizeof(event.dns_data), data_ptr);
    event.data_len = MAX_DNS_DATA;
    parse_dns_header(event.dns_data, event.data_len, &event);
}
```

#### Структура `msghdr`

```c
// Пользовательское сообщение (uapi/linux/socket.h)
struct msghdr {
    void         *msg_name;       // Адрес назначения (sockaddr)
    int          msg_namelen;     // Длина адреса
    struct iov_iter msg_iter;     // Данные сообщения ← ЗДЕСЬ DNS!
    void         *msg_control;    // Ancillary data
    __kernel_size_t msg_controllen;
    unsigned int msg_flags;
};
```

#### Структура `iov_iter`

```c
// Iterator для данных (linux/uio.h)
struct iov_iter {
    u8 iter_type;          // Тип итератора
    bool copy_mc;
    bool nofault;
    bool data_source;
    bool user_backed;
    union {
        size_t iov_offset;
        int last_offset;
    };
    size_t count;          // Общий размер данных
    union {
        const struct iovec *__iov;    // Старые ядра (5.x)
        void __user *ubuf;             // Новые ядра (5.14+, 6.x)
        // ...
    };
    // ...
};
```

#### Функция `get_data_ptr_from_iter()`

```c
static __always_inline void *get_data_ptr_from_iter(struct iov_iter *iter) {
    void *data_ptr = NULL;
    
    // Пробуем ubuf (ядра 5.14+, 6.x)
    bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), &iter->ubuf);
    
    if (!data_ptr) {
        // Fallback: iov (ядра 5.x и ранее)
        const struct iovec *iov = NULL;
        bpf_probe_read_kernel(&iov, sizeof(iov), &iter->__iov);
        if (iov) {
            bpf_probe_read_kernel(&data_ptr, sizeof(data_ptr), &iov->iov_base);
        }
    }
    
    return data_ptr;
}
```

**Почему два подхода?**

```
Изменения в ядре Linux:

Ядро 5.x (старый API):
┌─────────────────────────────────────┐
│ struct iov_iter                      │
│   ├── __iov → struct iovec[]         │
│   │            ├── iov_base (ptr)    │
│   │            └── iov_len           │
│   └── ...                            │
└─────────────────────────────────────┘

Ядро 5.14+, 6.x (новый API):
┌─────────────────────────────────────┐
│ struct iov_iter                      │
│   ├── ubuf → void* (прямой указатель)│
│   └── ...                            │
└─────────────────────────────────────┘

Наш код поддерживает оба варианта!
```

#### `bpf_probe_read_user()` vs `bpf_probe_read_kernel()`

```c
// Чтение из KERNEL памяти (структуры ядра)
bpf_probe_read_kernel(&dst, size, &sk->field);

// Чтение из USER памяти (данные приложения)
bpf_probe_read_user(event.dns_data, size, data_ptr);
```

**Разница**:
- `bpf_probe_read_kernel()` — для структур ядра (sk, msg, iter)
- `bpf_probe_read_user()` — для данных пользователя (DNS пакет)

**Почему важно?**
- Разные адресные пространства
- Разные проверки безопасности
- Неправильное использование → ошибка или неверные данные

### 3.9 ЭТАП 8: Отправка в userspace

```c
events.ringbuf_output(&event, sizeof(event), 0);
```

Подробнее о Ring Buffer — в разделе 7.

---

## 4. UDP DNS Response: kprobe + kretprobe

### 4.1 Проблема

```
Когда вызывается udp_recvmsg():

  ВХОД (kprobe):
    msg->msg_iter указывает на ПУСТОЙ буфер
    Данные еще НЕ скопированы

  ВЫХОД (kretprobe):
    msg->msg_iter указывает на ЗАПОЛНЕННЫЙ буфер
    Данные УЖЕ скопированы
```

### 4.2 Решение: Сохранение контекста

```
┌─────────────────────────────────────────────────────────┐
│                         TIME →                           │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  kprobe                              kretprobe           │
│     │                                    │               │
│     ▼                                    ▼               │
│  ┌──────────────────┐             ┌──────────────────┐  │
│  │ 1. Сохраняем     │             │ 4. Достаём       │  │
│  │    указатель     │             │    указатель     │  │
│  │    на буфер      │             │    из map        │  │
│  │                  │             │                  │  │
│  │ 2. Сохраняем     │             │ 5. Читаем        │  │
│  │    сетевые       │             │    DNS данные    │  │
│  │    данные        │             │    из буфера     │  │
│  │                  │             │                  │  │
│  │ 3. Записываем    │             │ 6. Удаляем       │  │
│  │    в map         │             │    из map        │  │
│  └────────┬─────────┘             └────────┬─────────┘  │
│           │                                │             │
│           ▼                                ▼             │
│      ┌────────────────────────────────────────┐         │
│      │           recv_ctx_map                  │         │
│      │                                         │         │
│      │  key: pid_tgid    value: recv_context  │         │
│      │  ─────────────    ──────────────────   │         │
│      │  0x4D200004D2  →  { data_ptr, saddr,   │         │
│      │                     daddr, sport, ... }│         │
│      └────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────┘
```

### 4.3 Код kprobe (сохранение контекста)

```c
int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    // Фильтрация по порту
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (dport != __constant_htons(53)) {
        return 0;
    }
    
    // Получаем уникальный ключ для map
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Создаем контекст
    struct recv_context rctx = {};
    
    // Сохраняем сетевые данные (доступны в kprobe)
    bpf_probe_read_kernel(&rctx.saddr, sizeof(rctx.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&rctx.daddr, sizeof(rctx.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&rctx.sport, sizeof(rctx.sport), &sk->__sk_common.skc_num);
    rctx.dport = 53;
    rctx.protocol = 17;
    
    // Сохраняем указатель на буфер (данных еще нет!)
    struct iov_iter iter;
    bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    rctx.data_ptr = get_data_ptr_from_iter(&iter);
    
    // Записываем в map
    recv_ctx_map.update(&pid_tgid, &rctx);
    return 0;
}
```

### 4.4 Код kretprobe (чтение данных)

```c
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Достаем контекст из map
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
    
    // Сетевые данные из контекста
    event.saddr = rctx->saddr;
    event.daddr = rctx->daddr;
    event.sport = rctx->sport;
    event.dport = rctx->dport;
    event.protocol = rctx->protocol;
    event.direction = 2;  // Response
    
    // ТЕПЕРЬ данные есть в буфере!
    bpf_probe_read_user(event.dns_data, sizeof(event.dns_data), rctx->data_ptr);
    event.data_len = MAX_DNS_DATA;
    parse_dns_header(event.dns_data, event.data_len, &event);
    
    // Удаляем из map (важно для предотвращения утечек!)
    recv_ctx_map.delete(&pid_tgid);
    
    events.ringbuf_output(&event, sizeof(event), 0);
    
    return 0;
}
```

### 4.5 Почему нельзя использовать только kretprobe?

```c
// ❌ В kretprobe НЕТ доступа к аргументам функции!

int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    // ctx содержит ТОЛЬКО return value
    // sk, msg — НЕДОСТУПНЫ!
    
    struct sock *sk = ???;    // Откуда взять?
    struct msghdr *msg = ???; // Откуда взять?
}
```

**Решение**: Сохранить нужные данные в map при входе (kprobe).

---

## 5. Структуры данных и типы

### 5.1 Типы данных в eBPF

```c
// Целочисленные типы (фиксированный размер)
u8   →  unsigned char        (1 байт)
u16  →  unsigned short       (2 байта)
u32  →  unsigned int         (4 байта)
u64  →  unsigned long long   (8 байт)

s8   →  signed char          (1 байт)
s16  →  signed short         (2 байта)
s32  →  signed int           (4 байта)
s64  →  signed long long     (8 байт)

// Специальные типы
__be16  →  Big-endian u16 (network byte order)
__be32  →  Big-endian u32 (network byte order)
__le16  →  Little-endian u16
__le32  →  Little-endian u32
```

### 5.2 Структура события DNS

```c
struct dns_event {
    // === Метаданные процесса (24 байта) ===
    u32 pid;              // 4 байта — Process ID
    u32 tid;              // 4 байта — Thread ID
    char comm[16];        // 16 байт — Имя процесса
    
    // === Идентификация пода (12 байт) ===
    u64 cgroup_id;        // 8 байт — Cgroup ID
    u32 netns_id;         // 4 байта — Network namespace ID
    
    // === Сетевые данные (12 байт) ===
    u32 saddr;            // 4 байта — Source IP (IPv4)
    u32 daddr;            // 4 байта — Destination IP (IPv4)
    u16 sport;            // 2 байта — Source port
    u16 dport;            // 2 байта — Destination port
    
    // === DNS метаданные (12 байт) ===
    u8  protocol;         // 1 байт  — 6=TCP, 17=UDP
    u8  direction;        // 1 байт  — 1=query, 2=response
    u16 dns_id;           // 2 байта — Transaction ID
    u16 dns_flags;        // 2 байта — Flags
    u16 dns_questions;    // 2 байта — Question count
    u16 dns_answers;      // 2 байта — Answer count
    
    // === Timestamp (8 байт) ===
    u64 timestamp_ns;     // 8 байт — Monotonic time
    
    // === DNS данные (258 байт) ===
    u16 data_len;         // 2 байта — Реальная длина
    u8  dns_data[256];    // 256 байт — DNS payload
    
} __attribute__((packed));
// Общий размер: 24 + 12 + 12 + 12 + 8 + 258 = 326 байт
```

### 5.3 Зачем `__attribute__((packed))`?

```
Без packed (с выравниванием):
┌─────────────────────────────────────────────────────────┐
│ pid (4)  │ tid (4)  │ comm (16) │ padding (4) │ cgroup │
└─────────────────────────────────────────────────────────┘
            ↑                       ↑
         OK (4-aligned)         PADDING для 8-aligned

С packed (без выравнивания):
┌─────────────────────────────────────────────────────────┐
│ pid (4)  │ tid (4)  │ comm (16) │ cgroup_id (8)        │
└─────────────────────────────────────────────────────────┘
                                    ↑
                               БЕЗ padding
```

**Зачем packed?**
1. Экономия памяти в Ring Buffer
2. Точное соответствие между C и Python структурами
3. Предсказуемое расположение полей

### 5.4 Структура контекста

```c
struct recv_context {
    void *data_ptr;       // 8 байт — Указатель на буфер
    u32 saddr;            // 4 байта
    u32 daddr;            // 4 байта
    u16 sport;            // 2 байта
    u16 dport;            // 2 байта
    u8  protocol;         // 1 байт
    // padding            // 3 байта (выравнивание)
};
// Размер: ~24 байта
```

---

## 6. Maps: Хранилище данных в eBPF

### 6.1 Что такое BPF Maps?

**BPF Maps** — структуры данных для хранения состояния между вызовами eBPF программ и для обмена данными с userspace.

```
┌─────────────────────────────────────────────────────────┐
│                      KERNEL SPACE                        │
│                                                          │
│   eBPF Program 1        eBPF Program 2                  │
│        │                      │                          │
│        │  write               │  read                    │
│        ▼                      ▼                          │
│   ┌────────────────────────────────────────────┐        │
│   │                  BPF Map                    │        │
│   │                                             │        │
│   │   key → value                               │        │
│   │   key → value                               │        │
│   │   key → value                               │        │
│   └────────────────────────────────────────────┘        │
│                         ▲                                │
│                         │ read/write                     │
├─────────────────────────┼────────────────────────────────┤
│                         │                                │
│                    USER SPACE                            │
│                         │                                │
│   ┌─────────────────────┴─────────────────────────┐     │
│   │              Python / Go / C                   │     │
│   │                                                │     │
│   │   bpf["map_name"][key] = value                │     │
│   │   value = bpf["map_name"][key]                │     │
│   └────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────┘
```

### 6.2 Типы Maps

| Тип | Описание | Использование |
|-----|----------|---------------|
| **BPF_HASH** | Key-value хранилище | Контекст между kprobe/kretprobe |
| **BPF_ARRAY** | Массив с числовым индексом | Счетчики, конфигурация |
| **BPF_RINGBUF** | Circular buffer (FIFO) | Передача событий в userspace |
| **BPF_PERF_OUTPUT** | Per-CPU event buffer | Альтернатива Ring Buffer |
| **BPF_LRU_HASH** | Hash с автоочисткой | Ограниченный кэш |

### 6.3 BPF_HASH для контекста

```c
// Определение map
BPF_HASH(recv_ctx_map, u64, struct recv_context, 10240);
//        ↑            ↑     ↑                   ↑
//     имя map       key   value              размер (записей)
```

**Операции**:

```c
// Запись
recv_ctx_map.update(&key, &value);

// Чтение
struct recv_context *ctx = recv_ctx_map.lookup(&key);

// Удаление
recv_ctx_map.delete(&key);
```

**Почему 10240 записей?**

```
Расчет:
  - Типичная нагрузка: 1000 DNS запросов/сек
  - Время между kprobe и kretprobe: ~1-10 µs
  - Максимум одновременных контекстов: 1000 * 0.00001 ≈ 10
  - Запас для burst: 10240 >> 10
  
Память:
  - Размер записи: ~24 байта
  - 10240 записей: ~245 KB
  - Приемлемо для ядра
```

### 6.4 Важность очистки map

```c
// ❌ ПЛОХО — утечка памяти!
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    struct recv_context *rctx = recv_ctx_map.lookup(&pid_tgid);
    // Забыли удалить!
    return 0;
}

// ✅ ПРАВИЛЬНО — всегда удаляем
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    struct recv_context *rctx = recv_ctx_map.lookup(&pid_tgid);
    if (!rctx) {
        return 0;
    }
    // ... обработка ...
    recv_ctx_map.delete(&pid_tgid);  // Обязательно!
    return 0;
}
```

---

## 7. Ring Buffer: Передача данных в userspace

### 7.1 Архитектура Ring Buffer

```
┌─────────────────────────────────────────────────────────┐
│                    RING BUFFER                           │
│                                                          │
│   Размер: 256 KB (1 << 18)                              │
│                                                          │
│   ┌───────────────────────────────────────────────────┐ │
│   │                                                    │ │
│   │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐       ┌─────┐   │ │
│   │  │ E1  │ │ E2  │ │ E3  │ │ E4  │ ...   │ En  │   │ │
│   │  └─────┘ └─────┘ └─────┘ └─────┘       └─────┘   │ │
│   │    ↑                                      ↑       │ │
│   │  read                                   write     │ │
│   │  pointer                               pointer    │ │
│   │                                                    │ │
│   └───────────────────────────────────────────────────┘ │
│                                                          │
│   Характеристики:                                        │
│   - FIFO (порядок гарантирован)                         │
│   - Lock-free (без блокировок)                          │
│   - Shared memory (kernel ↔ userspace)                  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 7.2 Определение Ring Buffer

```c
BPF_RINGBUF_OUTPUT(events, 1 << 18);  // 256 KB
//                 ↑       ↑
//              имя    размер (должен быть степенью 2)
```

**Расчет размера**:
```
1 << 18 = 2^18 = 262144 байт = 256 KB

Сколько событий помещается:
  - Размер события: ~326 байт
  - Вместимость: 256 KB / 326 ≈ 800 событий

Выбор размера:
  - 1 << 16 = 64 KB  — мало (200 событий)
  - 1 << 18 = 256 KB — оптимально (800 событий) ✅
  - 1 << 20 = 1 MB   — много (3000 событий)
```

### 7.3 Запись в Ring Buffer

```c
// Из eBPF программы
events.ringbuf_output(&event, sizeof(event), 0);
//                     ↑       ↑             ↑
//                  данные  размер        флаги (0 = без флагов)
```

**Что происходит**:
1. Резервируется место в буфере (atomic)
2. Данные копируются в буфер
3. Запись помечается как "готова"
4. Userspace может прочитать

### 7.4 Чтение в userspace (Python)

```python
# Открытие Ring Buffer
b["events"].open_ring_buffer(callback)

# Callback для обработки событий
def callback(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(DNSEvent)).contents
    # Обработка события...

# Polling (ожидание событий)
while True:
    b.ring_buffer_poll(timeout=100)  # 100ms timeout
```

**Процесс чтения**:
```
┌─────────────────────────────────────────────────────────┐
│                    USERSPACE                             │
│                                                          │
│   Python Application                                     │
│        │                                                 │
│        │ 1. ring_buffer_poll()                          │
│        ▼                                                 │
│   ┌─────────────────────────────────────────────────┐   │
│   │ Проверяет: есть ли новые события?               │   │
│   │                                                  │   │
│   │ Если да → вызывает callback для каждого         │   │
│   │ Если нет → ждет timeout или возвращается       │   │
│   └─────────────────────────────────────────────────┘   │
│        │                                                 │
│        │ 2. callback(ctx, data, size)                   │
│        ▼                                                 │
│   ┌─────────────────────────────────────────────────┐   │
│   │ data указывает на событие в shared memory      │   │
│   │ Нужно скопировать/обработать до возврата!      │   │
│   └─────────────────────────────────────────────────┘   │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### 7.5 Ring Buffer vs Perf Buffer

```
┌─────────────────────────────────────────────────────────┐
│                  PERF BUFFER                             │
│                                                          │
│   Per-CPU буферы (по одному на каждый CPU):             │
│                                                          │
│   CPU 0        CPU 1        CPU 2        CPU 3          │
│   ┌─────┐      ┌─────┐      ┌─────┐      ┌─────┐        │
│   │ buf │      │ buf │      │ buf │      │ buf │        │
│   └──┬──┘      └──┬──┘      └──┬──┘      └──┬──┘        │
│      │            │            │            │            │
│      └────────────┴────────────┴────────────┘            │
│                        │                                 │
│                    epoll_wait()                          │
│                        │                                 │
│                    USERSPACE                             │
│                                                          │
│   Проблема: события с разных CPU могут прийти           │
│   не в том порядке, в котором произошли!                │
│                                                          │
└──────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   RING BUFFER                            │
│                                                          │
│   Один общий буфер для всех CPU:                        │
│                                                          │
│   CPU 0 ──┐                                              │
│   CPU 1 ──┼──► ┌─────────────────────────────┐          │
│   CPU 2 ──┤    │     Shared Ring Buffer      │          │
│   CPU 3 ──┘    │     (lock-free, ordered)    │          │
│                └─────────────┬───────────────┘          │
│                              │                           │
│                          polling                         │
│                              │                           │
│                          USERSPACE                       │
│                                                          │
│   Преимущество: порядок событий ГАРАНТИРОВАН (FIFO)     │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

| Характеристика | Perf Buffer | Ring Buffer |
|----------------|-------------|-------------|
| Порядок событий | ❌ Не гарантирован | ✅ FIFO |
| CPU overhead | Выше (per-CPU) | Ниже |
| Latency (низкая нагрузка) | Выше | ✅ Ниже |
| Burst нагрузка | ✅ Лучше (per-CPU) | Хуже |
| API | Legacy | ✅ Современный |
| Требования | Linux 4.9+ | Linux 5.8+ |

---

## 8. DNS протокол и парсинг

### 8.1 Структура DNS пакета

```
┌─────────────────────────────────────────────────────────┐
│                    DNS PACKET                            │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │                   HEADER (12 bytes)                │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ Transaction ID    (2 bytes)                        │  │
│  │ Flags             (2 bytes)                        │  │
│  │ Question Count    (2 bytes)                        │  │
│  │ Answer Count      (2 bytes)                        │  │
│  │ Authority Count   (2 bytes)                        │  │
│  │ Additional Count  (2 bytes)                        │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │                   QUESTION SECTION                 │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ QNAME  (variable)  - Domain name                  │  │
│  │ QTYPE  (2 bytes)   - Query type (A, AAAA, TXT...) │  │
│  │ QCLASS (2 bytes)   - Query class (IN = Internet)  │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │                   ANSWER SECTION                   │  │
│  │                 (в ответах)                        │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### 8.2 DNS Header (12 байт)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Transaction ID        |              Flags            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Question Count         |         Answer Count          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Authority Count         |        Additional Count       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Bytes:
  [0-1]   Transaction ID   - Уникальный ID запроса/ответа
  [2-3]   Flags            - QR, Opcode, AA, TC, RD, RA, Z, RCODE
  [4-5]   Question Count   - Количество вопросов
  [6-7]   Answer Count     - Количество ответов
  [8-9]   Authority Count  - Количество authority записей
  [10-11] Additional Count - Количество дополнительных записей
```

### 8.3 DNS Flags (2 байта)

```
Bit layout:

 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

QR (1 bit):     0 = Query, 1 = Response
Opcode (4 bit): 0 = Standard query
                1 = Inverse query
                2 = Status request
AA (1 bit):     Authoritative Answer
TC (1 bit):     Truncated (ответ обрезан, нужен TCP)
RD (1 bit):     Recursion Desired
RA (1 bit):     Recursion Available
RCODE (4 bit):  0 = No error
                1 = Format error
                2 = Server failure
                3 = Name error (NXDOMAIN)
```

### 8.4 Парсинг DNS заголовка в eBPF

```c
static __always_inline void parse_dns_header(u8 *data, u16 data_len, struct dns_event *event) {
    // DNS Header: 12 bytes minimum
    // [0-1]  Transaction ID
    // [2-3]  Flags
    // [4-5]  Questions
    // [6-7]  Answers
    // [8-9]  Authority
    // [10-11] Additional
    
    // === BOUNDS CHECK ===
    // Verifier требует проверки перед доступом к массиву!
    if (!data || data_len < DNS_HEADER_SIZE) {
        event->dns_id = 0;
        event->dns_flags = 0;
        event->dns_questions = 0;
        event->dns_answers = 0;
        return;
    }
    
    // === Парсинг (Big-Endian → Host) ===
    // DNS использует network byte order (big-endian)
    
    // Transaction ID: bytes 0-1
    event->dns_id = (data[0] << 8) | data[1];
    //               ↑              ↑
    //          старший байт   младший байт
    
    // Flags: bytes 2-3
    event->dns_flags = (data[2] << 8) | data[3];
    
    // Question count: bytes 4-5
    event->dns_questions = (data[4] << 8) | data[5];
    
    // Answer count: bytes 6-7
    event->dns_answers = (data[6] << 8) | data[7];
}
```

**Почему `(data[0] << 8) | data[1]`?**

```
Network byte order (Big-Endian):
  Число 0x1234 хранится как: [0x12] [0x34]
                              ↑       ↑
                           byte 0  byte 1

Преобразование в host order (x86 = Little-Endian):
  data[0] = 0x12
  data[1] = 0x34
  
  result = (0x12 << 8) | 0x34
         = 0x1200 | 0x34
         = 0x1234  ✓
```

### 8.5 QNAME (Domain Name) формат

```
Пример: "www.google.com"

Формат в DNS пакете:
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ 3 │ w │ w │ w │ 6 │ g │ o │ o │ g │ l │ e │ 3 │ c │ o │ m │ 0 │
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
  ↑                 ↑                         ↑               ↑
  длина "www"      длина "google"           длина "com"      терминатор

Каждая метка (label):
  [length byte] [characters...]

Конец домена: length byte = 0
```

### 8.6 DNS Record Types

```c
// Основные типы (для детекции туннелей)
#define DNS_TYPE_A      1    // IPv4 адрес
#define DNS_TYPE_NS     2    // Name server
#define DNS_TYPE_CNAME  5    // Canonical name
#define DNS_TYPE_MX     15   // Mail exchange
#define DNS_TYPE_TXT    16   // Text ← Часто для C2!
#define DNS_TYPE_AAAA   28   // IPv6 адрес
#define DNS_TYPE_NULL   10   // NULL ← iodine tunnel!

// Подозрительные типы для туннелей:
// TXT  - Может содержать произвольные данные (Base64)
// NULL - Используется iodine для IP-over-DNS
```

### 8.7 Размеры DNS пакетов

```
┌─────────────────────────────────────────────────────────┐
│                    DNS PACKET SIZES                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  UDP DNS:                                                │
│    Минимум:  12 bytes (только заголовок)                │
│    Типично:  40-100 bytes                               │
│    Максимум: 512 bytes (RFC 1035)                       │
│              4096 bytes (EDNS0)                         │
│                                                          │
│  TCP DNS:                                                │
│    Формат:   [2-byte length] + [DNS packet]             │
│    Максимум: 65535 bytes                                │
│                                                          │
│  Наш буфер (MAX_DNS_DATA = 256):                        │
│    Покрывает 99%+ нормальных запросов                   │
│    Длинные ответы обрезаются (заголовок всегда есть)    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 9. Ограничения eBPF Verifier

### 9.1 Что такое Verifier?

```
┌─────────────────────────────────────────────────────────┐
│                   eBPF VERIFIER                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Статический анализатор, проверяющий eBPF программу     │
│  ПЕРЕД загрузкой в ядро.                                │
│                                                          │
│  Гарантирует:                                           │
│    ✓ Программа завершится (нет бесконечных циклов)     │
│    ✓ Все доступы к памяти безопасны                    │
│    ✓ Нет утечек указателей                              │
│    ✓ Все пути возвращают значение                       │
│                                                          │
│  Если проверка не пройдена → программа НЕ загружается   │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### 9.2 Типичные ошибки и решения

#### Ошибка 1: Небезопасный доступ к памяти

```c
// ❌ ОТКЛОНЕНО — прямой доступ к указателю
u16 port = sk->__sk_common.skc_dport;

// ✅ ПРИНЯТО — использование helper
u16 port = 0;
bpf_probe_read_kernel(&port, sizeof(port), &sk->__sk_common.skc_dport);
```

#### Ошибка 2: Возможный NULL pointer

```c
// ❌ ОТКЛОНЕНО — не проверили на NULL
struct recv_context *rctx = recv_ctx_map.lookup(&key);
u32 addr = rctx->saddr;  // rctx может быть NULL!

// ✅ ПРИНЯТО — проверка на NULL
struct recv_context *rctx = recv_ctx_map.lookup(&key);
if (!rctx) {
    return 0;
}
u32 addr = rctx->saddr;  // Теперь безопасно
```

#### Ошибка 3: Доступ за границы массива

```c
// ❌ ОТКЛОНЕНО — нет bounds check
void parse(u8 *data, u16 len) {
    u16 id = (data[0] << 8) | data[1];  // А если len < 2?
}

// ✅ ПРИНЯТО — bounds check
void parse(u8 *data, u16 len) {
    if (len < 2) return;
    u16 id = (data[0] << 8) | data[1];  // Теперь безопасно
}
```

#### Ошибка 4: Слишком сложный код

```c
// ❌ ОТКЛОНЕНО — слишком много инструкций
for (int i = 0; i < 1000; i++) {
    // много кода...
}

// ✅ ПРИНЯТО — ограниченное количество итераций
#pragma unroll
for (int i = 0; i < 10; i++) {
    // код...
}
```

### 9.3 Лимиты Verifier

```
┌─────────────────────────────────────────────────────────┐
│                   VERIFIER LIMITS                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Максимум инструкций:                                   │
│    Linux < 5.2:   4096 instructions                     │
│    Linux ≥ 5.2:   1,000,000 instructions                │
│                                                          │
│  Максимум вложенность:                                   │
│    Глубина стека вызовов: 8                             │
│                                                          │
│  Размер стека:                                          │
│    512 байт на программу                                │
│                                                          │
│  Циклы:                                                  │
│    Ограниченные (bounded loops) — OK                    │
│    Неограниченные — ОТКЛОНЕНО                           │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### 9.4 `__always_inline`

```c
// Все helper функции должны быть inline!
static __always_inline void *get_data_ptr_from_iter(struct iov_iter *iter) {
    // ...
}

// Почему?
// 1. eBPF не поддерживает обычные вызовы функций (до Linux 5.10)
// 2. __always_inline заставляет компилятор встроить код
// 3. Без inline — ошибка линковки
```

### 9.5 Инициализация переменных

```c
// ❌ ОТКЛОНЕНО — неинициализированная переменная
struct dns_event event;
event.pid = pid;  // Остальные поля содержат мусор!

// ✅ ПРИНЯТО — явная инициализация
struct dns_event event = {};  // Все поля = 0
event.pid = pid;

// Или
struct dns_event event;
__builtin_memset(&event, 0, sizeof(event));
```

---

## 10. Полный цикл события

### 10.1 DNS Query: От приложения до userspace

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: Application sends DNS query                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   dig google.com                                                │
│       │                                                          │
│       ▼                                                          │
│   sendto(fd, dns_packet, len, flags, &dns_server, addrlen)      │
│       │                                                          │
│       ▼                                                          │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    SYSCALL BOUNDARY                      │   │
│   └─────────────────────────────────────────────────────────┘   │
│       │                                                          │
│       ▼                                                          │
│   sys_sendto() → sock_sendmsg() → udp_sendmsg()                 │
│                                          │                       │
└──────────────────────────────────────────┼───────────────────────┘
                                           │
┌──────────────────────────────────────────┼───────────────────────┐
│ STEP 2: kprobe intercepts udp_sendmsg    │                       │
├──────────────────────────────────────────┼───────────────────────┤
│                                          ▼                       │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                    kprobe__udp_sendmsg                   │   │
│   │                                                          │   │
│   │  1. Check port == 53                    ✓                │   │
│   │  2. Get timestamp                       bpf_ktime_get_ns │   │
│   │  3. Get process info                    pid, tid, comm   │   │
│   │  4. Get container info                  cgroup, netns    │   │
│   │  5. Get network info                    saddr, daddr     │   │
│   │  6. Read DNS data from msg->msg_iter   bpf_probe_read_* │   │
│   │  7. Parse DNS header                    id, flags, etc   │   │
│   │  8. Submit to ring buffer              ringbuf_output    │   │
│   │                                                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
└───────────────────────────┼──────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│ STEP 3: Event in Ring Buffer                                    │
├───────────────────────────┼──────────────────────────────────────┤
│                           ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                     RING BUFFER                          │   │
│   │                                                          │   │
│   │   ┌──────────────────────────────────────────────────┐  │   │
│   │   │ Event:                                            │  │   │
│   │   │   pid: 12345                                      │  │   │
│   │   │   comm: "dig"                                     │  │   │
│   │   │   saddr: 192.168.1.100                           │  │   │
│   │   │   daddr: 8.8.8.8                                 │  │   │
│   │   │   dns_id: 0x1234                                 │  │   │
│   │   │   dns_data: [12 bytes header + query]            │  │   │
│   │   └──────────────────────────────────────────────────┘  │   │
│   │                                                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
└───────────────────────────┼──────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│ STEP 4: Python reads event                                       │
├───────────────────────────┼──────────────────────────────────────┤
│                           ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                  dns_analyzer_improved.py                │   │
│   │                                                          │   │
│   │  while True:                                             │   │
│   │      b.ring_buffer_poll(timeout=100)  ← Читаем событие  │   │
│   │                                                          │   │
│   │  def handle_event(ctx, data, size):                     │   │
│   │      event = cast(data, POINTER(DNSEvent)).contents     │   │
│   │      domain = parse_dns_name(event.dns_data)            │   │
│   │      suspicious = check_suspicious(domain)               │   │
│   │      log_event(event, domain, suspicious)               │   │
│   │                                                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
└───────────────────────────┼──────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│ STEP 5: Output                                                   │
├───────────────────────────┼──────────────────────────────────────┤
│                           ▼                                      │
│                                                                  │
│   [14:32:15] UDP QUERY | ID:1234 | PID:12345 dig | A | google.com│
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 10.2 DNS Response: Полный цикл с kretprobe

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: DNS Response arrives                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Network → NIC → Driver → ip_rcv → udp_rcv                     │
│                                              │                   │
│                                              ▼                   │
│   Application calls: recvfrom(fd, buffer, ...)                  │
│                                              │                   │
│                                              ▼                   │
│   sys_recvfrom → sock_recvmsg → udp_recvmsg                     │
│                                        │                         │
└────────────────────────────────────────┼─────────────────────────┘
                                         │
┌────────────────────────────────────────┼─────────────────────────┐
│ STEP 2: kprobe saves context           │                         │
├────────────────────────────────────────┼─────────────────────────┤
│                                        ▼                         │
│   ┌────────────────────────────────────────────────────────┐    │
│   │              kprobe__udp_recvmsg (ENTRY)                │    │
│   │                                                         │    │
│   │  1. Check port == 53                                    │    │
│   │                                                         │    │
│   │  2. msg->msg_iter → буфер ПУСТ (данные ещё не получены)│    │
│   │                                                         │    │
│   │  3. Сохраняем в map:                                    │    │
│   │     ┌─────────────────────────────────────────────┐    │    │
│   │     │ recv_ctx_map[pid_tgid] = {                   │    │    │
│   │     │     data_ptr: указатель на buffer            │    │    │
│   │     │     saddr: source IP                         │    │    │
│   │     │     daddr: dest IP                           │    │    │
│   │     │     sport: source port                       │    │    │
│   │     │     dport: 53                                │    │    │
│   │     │     protocol: UDP                            │    │    │
│   │     │ }                                            │    │    │
│   │     └─────────────────────────────────────────────┘    │    │
│   │                                                         │    │
│   └────────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│              [ udp_recvmsg executes... ]                        │
│              [ копирует данные в buffer ]                       │
│                            │                                     │
└────────────────────────────┼─────────────────────────────────────┘
                             │
┌────────────────────────────┼─────────────────────────────────────┐
│ STEP 3: kretprobe reads data                                     │
├────────────────────────────┼─────────────────────────────────────┤
│                            ▼                                     │
│   ┌────────────────────────────────────────────────────────┐    │
│   │            kretprobe__udp_recvmsg (EXIT)                │    │
│   │                                                         │    │
│   │  1. Lookup context from map:                            │    │
│   │     rctx = recv_ctx_map.lookup(&pid_tgid)               │    │
│   │                                                         │    │
│   │  2. ТЕПЕРЬ данные в буфере!                            │    │
│   │     bpf_probe_read_user(dns_data, 256, rctx->data_ptr) │    │
│   │                                                         │    │
│   │  3. Parse DNS header                                    │    │
│   │                                                         │    │
│   │  4. Create event & submit to ring buffer                │    │
│   │                                                         │    │
│   │  5. ВАЖНО: Удаляем из map!                             │    │
│   │     recv_ctx_map.delete(&pid_tgid)                      │    │
│   │                                                         │    │
│   └────────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 10.3 Временная диаграмма

```
Time →
────────────────────────────────────────────────────────────────────

UDP QUERY:
                                                     
  App          Kernel          eBPF           Ring Buffer    Python
   │              │               │                │            │
   │ sendto()    │               │                │            │
   ├─────────────►│               │                │            │
   │              │ udp_sendmsg() │                │            │
   │              ├───────────────►│               │            │
   │              │               │ kprobe         │            │
   │              │               │ read data      │            │
   │              │               │ parse header   │            │
   │              │               │ submit event   │            │
   │              │               ├────────────────►│           │
   │              │               │                │            │
   │              │◄──────────────┤                │            │
   │              │               │                │  poll()    │
   │              │               │                │◄───────────┤
   │              │               │                │ callback   │
   │              │               │                ├───────────►│
   │              │               │                │            │ log


UDP RESPONSE:

  App          Kernel          eBPF             Map         Ring    Python
   │              │               │               │           │        │
   │ recvfrom()  │               │               │           │        │
   ├─────────────►│               │               │           │        │
   │              │ udp_recvmsg() │               │           │        │
   │              ├───────────────►│              │           │        │
   │              │               │ kprobe        │           │        │
   │              │               │ save context  │           │        │
   │              │               ├───────────────►│          │        │
   │              │               │               │           │        │
   │              │   [copy data to buffer]       │           │        │
   │              │               │               │           │        │
   │              │───────────────►│              │           │        │
   │              │               │ kretprobe     │           │        │
   │              │               │ lookup ctx    │           │        │
   │              │               │◄──────────────┤           │        │
   │              │               │ read DNS data │           │        │
   │              │               │ delete ctx    │           │        │
   │              │               ├───────────────►│(delete)  │        │
   │              │               │ submit event  │           │        │
   │              │               ├───────────────────────────►│       │
   │◄─────────────┤               │               │           │        │
   │              │               │               │           │  poll  │
   │              │               │               │           │◄───────┤
   │              │               │               │           │callback│
   │              │               │               │           ├────────►│
```

---

## 11. Заключение

### 11.1 Ключевые концепции

1. **kprobe vs kretprobe**:
   - kprobe: доступ к аргументам функции на входе
   - kretprobe: доступ к результатам после выполнения
   - Для recvmsg нужны оба: сохранить указатель (kprobe), прочитать данные (kretprobe)

2. **BPF Maps**:
   - Хранят состояние между вызовами
   - Позволяют передавать данные между kprobe и kretprobe
   - Важно очищать для предотвращения утечек

3. **Ring Buffer**:
   - Эффективная передача событий в userspace
   - FIFO порядок гарантирован
   - Lock-free, shared memory

4. **Безопасность eBPF**:
   - Все доступы через bpf_probe_read_*
   - Bounds checking обязателен
   - Verifier проверяет до загрузки

5. **DNS парсинг**:
   - Заголовок всегда 12 байт
   - Big-endian формат
   - 256 байт буфера достаточно для 99% случаев

### 11.2 Рекомендуемое чтение

- [BPF and XDP Reference Guide (Cilium)](https://docs.cilium.io/en/stable/bpf/)
- [Linux Kernel Documentation: BPF](https://www.kernel.org/doc/html/latest/bpf/)
- [BCC Python Developer Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)
- [RFC 1035: DNS Protocol](https://tools.ietf.org/html/rfc1035)