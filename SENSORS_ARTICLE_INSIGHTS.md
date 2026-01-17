# Инсайты из статьи: DNS Tunnelling, Exfiltration and Detection over Cloud Environments

**Источник**: Salat, L.; Davis, M.; Khan, N. DNS Tunnelling, Exfiltration and Detection over Cloud Environments. Sensors 2023, 23, 2760. https://doi.org/10.3390/s23052760

---

## Ключевые моменты статьи

### 1. Использование Elastic Stack для мониторинга

**Что они делают:**
- Используют **Elastic Stack** (Elasticsearch, Logstash, Kibana) для сбора и анализа DNS логов
- Создают дашборды для визуализации DNS активности
- Анализируют DNS трафик в реальном времени

**Полезность для нас:**
- ✅ **Можем добавить экспорт в Elasticsearch** для долгосрочного хранения и анализа
- ✅ **Kibana дашборды** для визуализации туннелей
- ⚠️ **Но это не критично** для ВКР - у нас уже есть Prometheus метрики

### 2. Payload Analysis (анализ содержимого)

**Что они делают:**
- Анализируют **содержимое DNS запросов/ответов**
- Ищут паттерны кодирования (Base64, Hex)
- Анализируют длину доменов и ответов

**Что у нас уже есть:**
- ✅ **Entropy анализ** (высокая энтропия = подозрительно)
- ✅ **Длина доменов** (длинные домены = подозрительно)
- ✅ **Base64/Hex паттерны** в subdomain'ах
- ✅ **Анализ DNS payload** (читаем 256 байт)

**Что можно добавить:**
- ⚠️ **Анализ содержимого ответов** (ответы с большим количеством данных)
- ⚠️ **Анализ кодирования в ответах** (Base64 в TXT записях)

### 3. Traffic Analysis (анализ трафика)

**Что они делают:**
- **Частота запросов** (высокая частота = подозрительно)
- **Регулярность запросов** (C2 beacon)
- **Количество уникальных доменов** от одного процесса
- **Время между запросами** (интервалы)

**Что у нас уже есть:**
- ✅ **Частота запросов** (`IPOverDNSDetector` - >50 req/sec)
- ✅ **Регулярность запросов** (`C2Detector` - анализ интервалов)
- ✅ **Много уникальных subdomain'ов** (`ExfiltrationDetector`)

**Что можно улучшить:**
- ⚠️ **Более точный анализ регулярности** (используя статистику из статьи)
- ⚠️ **Анализ временных паттернов** (day/night, рабочие часы)

### 4. Статистические методы детекции

**Что они используют:**
- **Shannon Entropy** (энтропия Шеннона) - у нас уже есть ✅
- **Длина доменов** - у нас уже есть ✅
- **Частота запросов** - у нас уже есть ✅
- **Количество ответов** - у нас уже есть ✅

**Новые методы из статьи:**
- ⚠️ **Анализ распределения символов** (какие символы чаще встречаются)
- ⚠️ **Анализ последовательностей** (паттерны в subdomain'ах)
- ⚠️ **Корреляция запросов/ответов** (связь между query и response)

### 5. Тестирование на Iodine и DNScat2

**Что они тестируют:**
- **Iodine** - IP-over-DNS туннель
- **DNScat2** - C2 канал через DNS

**Что у нас уже детектируется:**
- ✅ **Iodine** - детектируем через NULL записи и высокую частоту
- ✅ **DNScat2** - детектируем через регулярность и TXT записи

**Что можно улучшить:**
- ⚠️ **Специфичные сигнатуры** для Iodine и DNScat2
- ⚠️ **Тестирование на реальных туннелях** для валидации

### 6. Cloud Environment специфика

**Что они обнаружили:**
- **DNS разрешается через metadata server** даже при блокировке egress трафика
- **Firewall правила в облаке** не всегда блокируют DNS
- **Важность мониторинга DNS** в cloud environments

**Полезность для нас:**
- ✅ **Kubernetes интеграция** - мы уже делаем это
- ✅ **Cgroup/NetNS идентификация** - мы уже делаем это
- ⚠️ **Можно добавить детекцию metadata server запросов**

---

## Конкретные улучшения для userspace

### 1. Улучшенный анализ регулярности (C2)

**Текущая реализация:**
```python
# Простой анализ интервалов
intervals = [(timestamps[i+1] - timestamps[i]) / 1e9 
            for i in range(len(timestamps)-1)]
avg_interval = sum(intervals) / len(intervals)
cv = std_dev / avg_interval  # Коэффициент вариации
```

**Улучшение из статьи:**
```python
# Более точный анализ регулярности
def analyze_regularity_advanced(timestamps):
    """
    Анализирует регулярность с использованием статистических методов.
    Возвращает: (is_regular, confidence, interval)
    """
    if len(timestamps) < 5:
        return False, 0.0, 0.0
    
    intervals = [(timestamps[i+1] - timestamps[i]) / 1e9 
                for i in range(len(timestamps)-1)]
    
    # Среднее и стандартное отклонение
    avg_interval = statistics.mean(intervals)
    std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
    
    # Коэффициент вариации (CV)
    cv = std_dev / avg_interval if avg_interval > 0 else float('inf')
    
    # Дополнительные метрики
    # 1. Минимальный и максимальный интервал
    min_interval = min(intervals)
    max_interval = max(intervals)
    interval_range = max_interval - min_interval
    
    # 2. Процент интервалов в пределах ±20% от среднего
    tolerance = avg_interval * 0.2
    within_tolerance = sum(1 for i in intervals 
                          if abs(i - avg_interval) <= tolerance)
    consistency_ratio = within_tolerance / len(intervals)
    
    # 3. Регулярность определяется:
    # - CV < 0.15 (низкая вариация)
    # - Consistency > 0.8 (80% интервалов в пределах ±20%)
    # - Интервал > 5 секунд (не слишком часто)
    is_regular = (cv < 0.15 and 
                  consistency_ratio > 0.8 and 
                  avg_interval > 5.0)
    
    confidence = (1.0 - cv) * consistency_ratio
    
    return is_regular, confidence, avg_interval
```

### 2. Анализ распределения символов

**Новый метод:**
```python
def analyze_character_distribution(domain):
    """
    Анализирует распределение символов в домене.
    Туннели часто имеют необычное распределение (много цифр, Base64 символы).
    """
    if not domain:
        return {}
    
    domain_clean = domain.replace('.', '')
    total_chars = len(domain_clean)
    
    if total_chars == 0:
        return {}
    
    # Подсчет типов символов
    counts = {
        'digits': sum(c.isdigit() for c in domain_clean),
        'lowercase': sum(c.islower() for c in domain_clean),
        'uppercase': sum(c.isupper() for c in domain_clean),
        'base64_special': sum(c in '+/=' for c in domain_clean),
        'hex': sum(c in '0123456789abcdefABCDEF' for c in domain_clean),
    }
    
    # Процентное соотношение
    ratios = {k: v / total_chars for k, v in counts.items()}
    
    # Подозрительные паттерны:
    # - Много цифр (>30%) = возможно hex encoding
    # - Много Base64 символов (>5%) = возможно Base64 encoding
    # - Равномерное распределение = высокая энтропия
    
    suspicious = []
    if ratios['digits'] > 0.3:
        suspicious.append(f"HIGH_DIGIT_RATIO({ratios['digits']:.0%})")
    if ratios['base64_special'] > 0.05:
        suspicious.append(f"BASE64_CHARS({ratios['base64_special']:.0%})")
    if ratios['hex'] / total_chars > 0.8:
        suspicious.append("HEX_ENCODING")
    
    return {
        'ratios': ratios,
        'suspicious': suspicious,
        'total_chars': total_chars
    }
```

### 3. Анализ последовательностей в subdomain'ах

**Новый метод:**
```python
def analyze_subdomain_sequences(domain):
    """
    Анализирует последовательности в subdomain'ах.
    Туннели часто используют последовательные subdomain'ы для передачи данных.
    """
    parts = domain.split('.')
    if len(parts) < 3:
        return {}
    
    subdomains = parts[:-2]  # Все кроме последних двух (base domain)
    
    # Анализ последовательностей
    # 1. Длина subdomain'ов (туннели часто используют фиксированную длину)
    lengths = [len(s) for s in subdomains]
    avg_length = statistics.mean(lengths) if lengths else 0
    length_variance = statistics.variance(lengths) if len(lengths) > 1 else 0
    
    # 2. Паттерны в subdomain'ах
    # - Base64 паттерн
    # - Hex паттерн
    # - Случайные символы
    
    patterns = {
        'base64': sum(1 for s in subdomains if re.match(r'^[A-Za-z0-9+/=]+$', s)),
        'hex': sum(1 for s in subdomains if re.match(r'^[0-9a-fA-F]+$', s)),
        'random': sum(1 for s in subdomains if calculate_entropy(s) > 4.0),
    }
    
    # Подозрительно:
    # - Много subdomain'ов с одинаковой длиной (фиксированный размер блока)
    # - Много Base64/Hex паттернов
    suspicious = []
    if length_variance < 5 and len(subdomains) > 10:
        suspicious.append(f"FIXED_LENGTH_SUBDOMAINS(avg={avg_length:.1f})")
    if patterns['base64'] > len(subdomains) * 0.5:
        suspicious.append(f"BASE64_PATTERN({patterns['base64']}/{len(subdomains)})")
    if patterns['hex'] > len(subdomains) * 0.5:
        suspicious.append(f"HEX_PATTERN({patterns['hex']}/{len(subdomains)})")
    
    return {
        'subdomain_count': len(subdomains),
        'avg_length': avg_length,
        'length_variance': length_variance,
        'patterns': patterns,
        'suspicious': suspicious
    }
```

### 4. Корреляция запросов/ответов

**Новый метод:**
```python
class QueryResponseCorrelator:
    """
    Коррелирует DNS запросы и ответы для детекции туннелей.
    Туннели часто имеют специфичные паттерны в ответах.
    """
    
    def __init__(self):
        self.pending_queries = {}  # dns_id -> query_event
        self.query_response_pairs = []  # (query, response) pairs
        self.TIMEOUT_NS = 10 * 1e9  # 10 секунд
    
    def add_query(self, event):
        """Добавляет запрос в ожидание ответа"""
        dns_id = event.get('dns_id', 0)
        self.pending_queries[dns_id] = {
            'event': event,
            'timestamp': event.get('timestamp_ns', 0),
        }
    
    def add_response(self, event):
        """Обрабатывает ответ и коррелирует с запросом"""
        dns_id = event.get('dns_id', 0)
        
        if dns_id not in self.pending_queries:
            return None
        
        query = self.pending_queries.pop(dns_id)
        
        # Проверяем timeout
        elapsed = event.get('timestamp_ns', 0) - query['timestamp']
        if elapsed > self.TIMEOUT_NS:
            return None
        
        # Коррелируем
        pair = {
            'query': query['event'],
            'response': event,
            'elapsed_ns': elapsed,
        }
        
        self.query_response_pairs.append(pair)
        
        # Анализ пары
        return self.analyze_pair(pair)
    
    def analyze_pair(self, pair):
        """
        Анализирует пару запрос/ответ на признаки туннелирования.
        """
        query = pair['query']
        response = pair['response']
        
        suspicious = []
        
        # 1. Большой ответ на маленький запрос (данные в ответе)
        query_len = len(query.get('domain', ''))
        response_answers = response.get('dns_answers', 0)
        
        if response_answers > 5 and query_len < 50:
            suspicious.append(f"LARGE_RESPONSE({response_answers} answers)")
        
        # 2. TXT ответы с данными (C2 команды)
        if response.get('dns_type') == 16:  # TXT
            suspicious.append("TXT_RESPONSE_WITH_DATA")
        
        # 3. NULL ответы (iodine)
        if response.get('dns_type') == 10:  # NULL
            suspicious.append("NULL_RESPONSE(iodine)")
        
        # 4. Быстрый ответ (может быть локальный туннель)
        elapsed_ms = pair['elapsed_ns'] / 1e6
        if elapsed_ms < 10:  # <10ms
            suspicious.append(f"FAST_RESPONSE({elapsed_ms:.1f}ms)")
        
        return suspicious if suspicious else None
```

### 5. Экспорт в Elasticsearch (опционально)

**Новый модуль:**
```python
class ElasticsearchExporter:
    """
    Экспортирует DNS события в Elasticsearch для долгосрочного анализа.
    Основано на подходе из статьи.
    """
    
    def __init__(self, es_host='localhost', es_port=9200, index='dns-events'):
        try:
            from elasticsearch import Elasticsearch
            self.es = Elasticsearch([{'host': es_host, 'port': es_port}])
            self.index = index
            self.enabled = True
        except ImportError:
            print("Warning: elasticsearch module not installed. Export disabled.")
            self.enabled = False
    
    def export_event(self, event, is_suspicious=False, threat_type=None, reasons=None):
        """Экспортирует событие в Elasticsearch"""
        if not self.enabled:
            return
        
        doc = {
            '@timestamp': datetime.utcnow().isoformat(),
            'pid': event.get('pid', 0),
            'comm': event.get('comm', ''),
            'domain': event.get('domain', ''),
            'dns_type': event.get('dns_type', 1),
            'dns_id': event.get('dns_id', 0),
            'protocol': 'TCP' if event.get('protocol') == 6 else 'UDP',
            'direction': 'RESPONSE' if event.get('direction') == 2 else 'QUERY',
            'saddr': event.get('saddr', ''),
            'daddr': event.get('daddr', ''),
            'suspicious': is_suspicious,
            'threat_type': threat_type,
            'reasons': reasons or [],
        }
        
        # Kubernetes метаданные
        if 'pod_info' in event:
            doc['kubernetes'] = event['pod_info']
        
        try:
            self.es.index(index=self.index, body=doc)
        except Exception as e:
            print(f"Error exporting to Elasticsearch: {e}")
```

---

## Сравнение: Статья vs Наш модуль

| Метод детекции | Статья | Наш модуль | Статус |
|----------------|--------|------------|--------|
| **Shannon Entropy** | ✅ | ✅ | ✅ Есть |
| **Длина доменов** | ✅ | ✅ | ✅ Есть |
| **Частота запросов** | ✅ | ✅ | ✅ Есть |
| **Регулярность (C2)** | ✅ | ✅ | ⚠️ Можно улучшить |
| **Base64/Hex паттерны** | ✅ | ✅ | ✅ Есть |
| **TXT/NULL записи** | ✅ | ✅ | ✅ Есть |
| **Количество ответов** | ✅ | ✅ | ✅ Есть |
| **Распределение символов** | ✅ | ❌ | ⚠️ Можно добавить |
| **Последовательности** | ✅ | ❌ | ⚠️ Можно добавить |
| **Корреляция Q/R** | ✅ | ❌ | ⚠️ Можно добавить |
| **Elastic Stack** | ✅ | ❌ | ⚠️ Опционально |

---

## Рекомендации

### Высокий приоритет (для ВКР):

1. ✅ **Улучшенный анализ регулярности** - более точная детекция C2
2. ✅ **Анализ распределения символов** - дополнительная эвристика
3. ✅ **Корреляция запросов/ответов** - детекция по парам Q/R

### Средний приоритет:

4. ⚠️ **Анализ последовательностей** - полезно, но сложнее
5. ⚠️ **Экспорт в Elasticsearch** - для долгосрочного анализа (опционально)

### Низкий приоритет:

6. ❌ **Kibana дашборды** - не критично для ВКР
7. ❌ **Logstash pipeline** - избыточно для нашей задачи

---

## Вывод

**Статья очень полезна для userspace части!**

**Что мы уже делаем хорошо:**
- ✅ Все основные методы детекции (entropy, длина, частота, типы записей)
- ✅ Хорошая структура детекторов (C2, Exfil, IP-over-DNS)

**Что можно улучшить:**
- ⚠️ **Более точный анализ регулярности** (статистические методы)
- ⚠️ **Анализ распределения символов** (дополнительная эвристика)
- ⚠️ **Корреляция запросов/ответов** (детекция по парам)

**Для ВКР:**
- Можно упомянуть статью как источник методов детекции
- Показать, что мы используем современные подходы
- Добавить улучшения из статьи для повышения точности

---

## Ссылки

- **Статья**: Salat, L.; Davis, M.; Khan, N. DNS Tunnelling, Exfiltration and Detection over Cloud Environments. Sensors 2023, 23, 2760. https://doi.org/10.3390/s23052760
- **Elastic Stack**: https://www.elastic.co/elastic-stack
- **Iodine**: https://code.kryo.se/iodine/
- **DNScat2**: https://github.com/iagox86/dnscat2

