# Инсайты из статьи про DNS Truncation для детекции туннелей

## Ключевые моменты статьи

### 1. DNS Truncation (TC флаг)

**Что это**:
- Когда DNS ответ через UDP слишком большой (>512 байт), сервер устанавливает **TC (Truncation) флаг**
- Клиент должен **игнорировать усеченный ответ** и перезапросить через **TCP**
- Это стандартное поведение DNS (RFC 2181)

**Статистика из статьи**:
- 0.24% резолверов **используют данные из усеченных ответов** (нарушение стандарта)
- 0.77% резолверов **не переключаются на TCP** после получения усеченного ответа
- Особенно распространено в сетях Китая, Чили, Индии

---

## Полезные инсайты для детекции DNS туннелей

### 1. TC флаг как индикатор туннелирования

**Почему полезно**:
- ✅ **DNS туннели часто используют большие ответы** → TC флаг устанавливается
- ✅ **Множественные TC флаги** от одного процесса → подозрительно
- ✅ **TC флаг + отсутствие TCP переключения** → очень подозрительно

**Применение**:
```python
# В dns_analyzer_improved.py
class TunnelDetector:
    def detect_truncation_abuse(self, events):
        """
        Детекция злоупотребления TC флагом:
        - Множественные TC флаги от одного процесса
        - TC флаг без последующего TCP запроса
        """
        tc_events = [e for e in events if e.dns_flags & 0x0200]  # TC bit
        
        # Группировка по PID
        by_pid = {}
        for event in tc_events:
            pid = event.pid
            if pid not in by_pid:
                by_pid[pid] = []
            by_pid[pid].append(event)
        
        # Детекция: >5 TC флагов за минуту
        for pid, events in by_pid.items():
            if len(events) > 5:
                return True, f"TC abuse: {len(events)} truncated responses from PID {pid}"
        
        return False, None
```

**Добавить в kernel**:
```c
// В dns_event структуру
struct dns_event {
    // ... существующие поля ...
    u8  tc_flag;  // Truncation flag (бит из dns_flags)
};

// В parse_dns_header()
event->tc_flag = (event->dns_flags & 0x0200) ? 1 : 0;
```

---

### 2. UDP → TCP переключение как обход детекции

**Почему полезно**:
- ✅ **Злоумышленники могут использовать TCP** для обхода UDP-детекции
- ✅ **Отсутствие TCP после TC** → либо нарушение стандарта, либо обход
- ✅ **Множественные UDP→TCP переключения** → подозрительно

**Применение**:
```python
class TunnelDetector:
    def detect_udp_tcp_switching(self, events):
        """
        Детекция подозрительного переключения UDP→TCP:
        - TC флаг в UDP ответе
        - Отсутствие последующего TCP запроса
        - Множественные переключения
        """
        # Группировка по transaction ID
        udp_tc_events = {}
        tcp_events = {}
        
        for event in events:
            if event.protocol == 17 and (event.dns_flags & 0x0200):  # UDP + TC
                udp_tc_events[event.dns_id] = event
            elif event.protocol == 6:  # TCP
                tcp_events[event.dns_id] = event
        
        # Проверка: есть ли TCP запрос после UDP TC?
        suspicious = []
        for dns_id, udp_event in udp_tc_events.items():
            if dns_id not in tcp_events:
                # TC флаг, но нет TCP переключения
                suspicious.append(udp_event)
        
        if len(suspicious) > 3:
            return True, f"UDP→TCP switching abuse: {len(suspicious)} cases"
        
        return False, None
```

---

### 3. IP фрагментация как способ скрытия

**Почему полезно**:
- ✅ **DNS туннели могут использовать фрагментацию** для скрытия трафика
- ✅ **Фрагментированные пакеты часто дропаются** файрволами → злоумышленники могут использовать это
- ✅ **IPv6 не поддерживает фрагментацию** → может быть использовано для обхода

**Применение**:
```python
# В userspace (мы не видим фрагментацию в kprobe, но можем детектировать паттерны)
class TunnelDetector:
    def detect_fragmentation_patterns(self, events):
        """
        Детекция паттернов, указывающих на использование фрагментации:
        - Большие DNS пакеты (>512 байт) через UDP
        - Множественные запросы с одинаковым transaction ID
        - Отсутствие ответов на большие запросы
        """
        large_udp = [e for e in events 
                    if e.protocol == 17 and e.data_len > 512]
        
        if len(large_udp) > 10:
            return True, f"Large UDP packets: {len(large_udp)} packets >512 bytes"
        
        return False, None
```

---

### 4. Нестандартное поведение резолверов

**Почему полезно**:
- ✅ **Некоторые сети имеют нестандартное поведение** (Китай, Чили)
- ✅ **Это может быть использовано злоумышленниками** для обхода детекции
- ✅ **Whitelist известных "хороших" резолверов** может помочь

**Применение**:
```python
# Whitelist известных резолверов с нестандартным поведением
KNOWN_NONSTANDARD_RESOLVERS = {
    # Китайские сети (из статьи)
    'AS4837': 'CHINA UNICOM Backbone',
    'AS17816': 'China Unicom Guangdong',
    'AS4134': 'CHINANET Backbone',
    # Чилийские сети
    'AS7418': 'Telefonica Chile',
    'AS52341': 'WOM Chile',
}

def is_known_nonstandard_resolver(ip):
    # Проверка по ASN (требует GeoIP базу)
    # Если IP из известной сети с нестандартным поведением - не детектировать
    pass
```

---

## Что добавить в наш код

### 1. TC флаг в kernel (PRIORITY: HIGH)

**Почему**:
- Быстрая детекция в kernel
- Не требует сложной логики
- Полезно для ранней фильтрации

**Код**:
```c
// В dns_event структуру
struct dns_event {
    // ... существующие поля ...
    u8  tc_flag;  // Truncation flag (1 = set, 0 = not set)
};

// В parse_dns_header()
static __always_inline void parse_dns_header(u8 *data, u16 data_len, struct dns_event *event) {
    // ... существующий код ...
    
    // TC флаг находится в бите 9 (0x0200) флагов
    event->tc_flag = (event->dns_flags & 0x0200) ? 1 : 0;
}
```

---

### 2. Детекция TC abuse в userspace (PRIORITY: MEDIUM)

**Почему**:
- Множественные TC флаги от одного процесса → подозрительно
- TC флаг без TCP переключения → подозрительно

**Код**:
```python
# В dns_analyzer_improved.py
class TCAbuseDetector:
    def __init__(self):
        self.tc_events_by_pid = {}  # PID -> [events]
        self.tc_without_tcp = {}  # DNS ID -> event
    
    def check_tc_abuse(self, event):
        """Проверка злоупотребления TC флагом"""
        if not event.tc_flag:
            return None
        
        pid = event.pid
        
        # Счетчик TC флагов по PID
        if pid not in self.tc_events_by_pid:
            self.tc_events_by_pid[pid] = []
        self.tc_events_by_pid[pid].append(event)
        
        # Проверка: >5 TC флагов за минуту
        recent_tc = [e for e in self.tc_events_by_pid[pid] 
                    if (event.timestamp_ns - e.timestamp_ns) < 60_000_000_000]
        
        if len(recent_tc) > 5:
            return {
                'type': 'TC_ABUSE',
                'severity': 'HIGH',
                'message': f'Multiple TC flags from PID {pid}: {len(recent_tc)} in 1 minute',
                'pid': pid,
                'count': len(recent_tc)
            }
        
        return None
```

---

### 3. Детекция UDP→TCP switching abuse (PRIORITY: MEDIUM)

**Почему**:
- TC флаг в UDP ответе должен приводить к TCP переключению
- Отсутствие TCP после TC → подозрительно

**Код**:
```python
class UDPTCPSwitchingDetector:
    def __init__(self):
        self.udp_tc_events = {}  # DNS ID -> event
        self.tcp_events = set()  # DNS IDs
    
    def check_switching(self, event):
        """Проверка подозрительного переключения UDP→TCP"""
        if event.protocol == 17 and event.tc_flag:  # UDP + TC
            self.udp_tc_events[event.dns_id] = event
            # Проверяем через 5 секунд: был ли TCP запрос?
            # (это нужно делать в отдельном потоке или через таймер)
        
        elif event.protocol == 6:  # TCP
            self.tcp_events.add(event.dns_id)
        
        # Проверка: есть ли UDP TC без TCP?
        suspicious = []
        for dns_id, udp_event in self.udp_tc_events.items():
            if dns_id not in self.tcp_events:
                # Проверяем время: прошло ли >5 секунд?
                if (event.timestamp_ns - udp_event.timestamp_ns) > 5_000_000_000:
                    suspicious.append(udp_event)
        
        if len(suspicious) > 3:
            return {
                'type': 'UDP_TCP_SWITCHING_ABUSE',
                'severity': 'MEDIUM',
                'message': f'UDP TC without TCP switch: {len(suspicious)} cases',
                'count': len(suspicious)
            }
        
        return None
```

---

## Выводы

### Полезные инсайты:

1. ✅ **TC флаг как индикатор** - множественные TC флаги → подозрительно
2. ✅ **UDP→TCP переключение** - отсутствие TCP после TC → подозрительно
3. ✅ **IP фрагментация** - большие UDP пакеты (>512 байт) → подозрительно
4. ⚠️ **Нестандартное поведение** - некоторые сети имеют нестандартное поведение

### Что добавить:

1. ✅ **TC флаг в kernel** - простое добавление, высокая ценность
2. ✅ **TC abuse детекция в userspace** - множественные TC флаги
3. ✅ **UDP→TCP switching детекция** - отсутствие TCP после TC

### Что НЕ добавлять:

1. ❌ **Полная детекция фрагментации** - мы не видим фрагментацию в kprobe
2. ❌ **GeoIP проверка** - слишком сложно, не критично

---

## Рекомендации

### Для ВКР:

1. **Упомянуть TC флаг** в разделе про DNS протокол:
   - TC флаг используется для переключения UDP→TCP
   - Некоторые резолверы нарушают стандарт (0.24% случаев)
   - Это может быть использовано злоумышленниками

2. **Добавить детекцию TC abuse**:
   - Множественные TC флаги от одного процесса
   - TC флаг без последующего TCP запроса

3. **Упомянуть в обосновании**:
   - DNS туннели могут использовать большие ответы → TC флаг
   - Обход детекции через TCP переключение

### Для кода:

1. **Добавить TC флаг в kernel** (простое улучшение)
2. **Добавить TC abuse детекцию в userspace** (средняя сложность)
3. **Добавить UDP→TCP switching детекцию** (средняя сложность)

---

## Цитаты для ВКР

### Из статьи:

> "When a DNS client receives a reply with TC set, it should ignore that response, and query again, using a mechanism, such as a TCP connection, that will permit larger replies."

**Использование**: Обоснование того, что TC флаг должен приводить к TCP переключению.

> "0.24% of users were using DNS resolution environments which used the data held in truncated DNS responses over UDP."

**Использование**: Демонстрация того, что некоторые резолверы нарушают стандарт.

> "0.77% of users did not followup the truncated UDP response with a TCP session."

**Использование**: Демонстрация того, что некоторые резолверы не переключаются на TCP.

---

## Итог

**Основные находки**:
1. TC флаг как индикатор туннелирования
2. UDP→TCP переключение как способ обхода детекции
3. Нестандартное поведение некоторых резолверов

**Что добавить**:
1. TC флаг в kernel (простое)
2. TC abuse детекция в userspace (среднее)
3. UDP→TCP switching детекция (среднее)

**Ценность для ВКР**:
- ✅ Дополнительный индикатор туннелирования
- ✅ Обоснование важности TCP детекции
- ✅ Демонстрация понимания DNS протокола

