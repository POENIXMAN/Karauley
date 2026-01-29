#!/usr/bin/env python3
"""
DNS Analyzer - Улучшенная версия
================================

Работает с dns_ebpf_improved.bpf.c

Изменения:
- Поддержка TCP DNS
- Корректное получение ответов (kretprobe)
- Идентификация пода (cgroup_id, netns_id)
- Полный DNS заголовок
- Kernel timestamp
"""

from bcc import BPF
import ctypes
import socket
import struct
import time
import os
import signal
import sys
from datetime import datetime
from collections import defaultdict
import math
import re
import resource
import threading
import traceback

# HTTP сервер для метрик и health checks
try:
    from flask import Flask
    from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("[WARNING] Flask/prometheus_client не установлены. HTTP endpoints недоступны.")

# ===== ЗАГРУЗКА eBPF ПРОГРАММЫ =====

BPF_SOURCE_FILE = os.path.join(os.path.dirname(__file__), "dns_ebpf_improved.bpf.c")

# ===== HTTP СЕРВЕР ДЛЯ МЕТРИК =====

# Prometheus метрики
if FLASK_AVAILABLE:
    dns_queries_total = Counter('dns_queries_total', 'Total DNS queries', ['protocol', 'direction'])
    dns_responses_total = Counter('dns_responses_total', 'Total DNS responses', ['protocol'])
    dns_suspicious_total = Counter('dns_suspicious_total', 'Total suspicious DNS queries', ['threat_type'])
    dns_domains_unique = Gauge('dns_domains_unique', 'Number of unique domains')
    dns_events_by_process = Counter('dns_events_by_process', 'DNS events by process (and pod for pinpointing)', ['process', 'pod'])
    dns_events_by_pod = Counter('dns_events_by_pod', 'DNS events by pod', ['pod'])
    
    # Flask приложение
    app = Flask(__name__)
    
    @app.route('/healthz')
    def healthz():
        """Liveness probe endpoint"""
        return 'OK', 200
    
    @app.route('/ready')
    def ready():
        """Readiness probe endpoint"""
        # Проверяем, что eBPF загружен и работает
        return 'OK', 200
    
    @app.route('/metrics')
    def metrics():
        """Prometheus metrics endpoint"""
        return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
    
    def start_http_server(port=9999, host='0.0.0.0'):
        """Запускает HTTP сервер в отдельном потоке"""
        app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)

# ===== СТРУКТУРА СОБЫТИЯ (должна совпадать с C) =====

class DNSEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        # Метаданные процесса
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        
        # Идентификация пода
        ("cgroup_id", ctypes.c_uint64),
        ("netns_id", ctypes.c_uint32),
        
        # Сетевые данные
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        
        # DNS метаданные
        ("protocol", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("dns_id", ctypes.c_uint16),
        ("dns_flags", ctypes.c_uint16),
        ("dns_questions", ctypes.c_uint16),
        ("dns_answers", ctypes.c_uint16),
        
        # Timestamp
        ("timestamp_ns", ctypes.c_uint64),
        
        # DNS данные
        ("data_len", ctypes.c_uint16),
        ("dns_data", ctypes.c_uint8 * 256),
    ]

# ===== ЦВЕТА ДЛЯ ВЫВОДА =====

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ===== МАППИНГ CGROUP -> POD =====

class PodResolver:
    """Определяет pod name по cgroup_id; в K8s может разрешать UID -> namespace/name для удобства."""
    
    def __init__(self):
        self.cgroup_cache = {}
        self.netns_cache = {}
        self._uid_to_ns_name = {}  # pod_uid (12 chars) -> "namespace/name"
        self._k8s_resolve_enabled = None  # lazy: check once
    
    def _in_cluster(self):
        if self._k8s_resolve_enabled is None:
            self._k8s_resolve_enabled = bool(os.environ.get("KUBERNETES_SERVICE_HOST"))
        return self._k8s_resolve_enabled
    
    def _resolve_uid_to_namespace_name(self, uid_12):
        """Опционально: по pod UID (12 символов) получить namespace/name через K8s API. Кэшируем."""
        if uid_12 in self._uid_to_ns_name:
            return self._uid_to_ns_name[uid_12]
        if not self._in_cluster():
            return None
        try:
            token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            if not host or not os.path.exists(token_path):
                return None
            with open(token_path, "r") as f:
                token = f.read().strip()
            import ssl
            import urllib.request
            ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
            ctx = ssl.create_default_context(cafile=ca) if os.path.exists(ca) else ssl.create_default_context()
            url = f"https://{host}:{port}/api/v1/pods?limit=500"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                data = __import__("json").loads(resp.read().decode())
            for item in data.get("items", []):
                meta = item.get("metadata", {})
                uid = meta.get("uid", "")
                if uid.startswith(uid_12) or uid[:12] == uid_12:
                    ns = meta.get("namespace", "default")
                    name = meta.get("name", "")
                    result = f"{ns}/{name}"
                    self._uid_to_ns_name[uid_12] = result
                    return result
            self._uid_to_ns_name[uid_12] = None  # not found, don't retry every time
        except Exception:
            pass
        return None
    
    def get_pod_info(self, pid, cgroup_id, netns_id):
        """Получает информацию о поде (cgroup -> uid; в K8s опционально namespace/name)."""
        
        if cgroup_id in self.cgroup_cache:
            return self.cgroup_cache[cgroup_id]
        
        pod_info = self._resolve_from_cgroup(pid)
        
        if pod_info and pod_info.get("type") == "kubernetes":
            uid = pod_info.get("pod_uid", "")
            if uid:
                ns_name = self._resolve_uid_to_namespace_name(uid)
                if ns_name:
                    pod_info["namespace_name"] = ns_name
        if pod_info:
            self.cgroup_cache[cgroup_id] = pod_info
        
        return pod_info
    
    def _resolve_from_cgroup(self, pid):
        """Читает cgroup файл процесса для определения пода"""
        try:
            cgroup_path = f"/proc/{pid}/cgroup"
            if not os.path.exists(cgroup_path):
                return None
            
            with open(cgroup_path, 'r') as f:
                for line in f:
                    # Kubernetes cgroup format:
                    # 0::/kubepods/burstable/pod<uid>/container<id>
                    # или
                    # 0::/system.slice/containerd.service/kubepods-...
                    
                    if 'kubepods' in line or 'docker' in line or 'containerd' in line:
                        parts = line.strip().split('/')
                        
                        # Ищем pod UID
                        for i, part in enumerate(parts):
                            if part.startswith('pod'):
                                pod_uid = part[3:]  # Убираем 'pod'
                                container_id = parts[i+1] if i+1 < len(parts) else None
                                return {
                                    'type': 'kubernetes',
                                    'pod_uid': pod_uid[:12],  # Короткий UID
                                    'container_id': container_id[:12] if container_id else None,
                                    'full_path': line.strip()
                                }
                        
                        # Docker container
                        for part in parts:
                            if len(part) == 64:  # Container ID
                                return {
                                    'type': 'docker',
                                    'container_id': part[:12],
                                    'full_path': line.strip()
                                }
            
            return None
            
        except (IOError, PermissionError):
            return None

# ===== DNS ПАРСИНГ =====

def parse_dns_name(data, offset=12):
    """Парсит DNS имя с поддержкой compression pointers"""
    labels = []
    i = offset
    max_jumps = 10
    jumps = 0
    
    while i < len(data) and data[i] != 0 and jumps < max_jumps:
        length = data[i]
        
        # Compression pointer
        if (length & 0xC0) == 0xC0:
            if i + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[i + 1]
            # Рекурсивно парсим по указателю
            if pointer < len(data):
                sub_labels = parse_dns_name(data, pointer)
                if sub_labels:
                    labels.extend(sub_labels.split('.'))
            break
        
        if length > 63 or i + length + 1 > len(data):
            break
        
        label = bytes(data[i+1:i+1+length]).decode('utf-8', errors='ignore')
        labels.append(label)
        i += length + 1
    
    return '.'.join(labels) if labels else None

def get_dns_type_name(qtype):
    """Возвращает имя типа DNS записи"""
    types = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
        10: "NULL", 12: "PTR", 15: "MX", 16: "TXT",
        28: "AAAA", 33: "SRV", 35: "NAPTR", 255: "ANY"
    }
    return types.get(qtype, f"TYPE{qtype}")

def parse_dns_type(data):
    """Извлекает тип DNS запроса из данных"""
    # После доменного имени идут QTYPE (2 bytes) и QCLASS (2 bytes)
    i = 12  # Пропускаем заголовок
    
    # Ищем конец доменного имени
    while i < len(data) and data[i] != 0:
        length = data[i]
        if (length & 0xC0) == 0xC0:
            i += 2
            break
        i += length + 1
    else:
        i += 1  # Нулевой байт
    
    # QTYPE
    if i + 2 <= len(data):
        qtype = (data[i] << 8) | data[i + 1]
        return qtype
    
    return 1  # Default: A

# ===== АНАЛИЗ =====

def calculate_entropy(s):
    """Вычисляет энтропию Шеннона"""
    if not s:
        return 0.0
    
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy

# ===== ДЕТЕКТОРЫ ТУННЕЛЕЙ =====

class C2Detector:
    """
    Детектор C2 (Command & Control) каналов.
    
    Признаки C2:
    - Регулярные запросы (каждые N секунд)
    - TXT записи для получения команд
    - Один и тот же домен
    """
    
    def __init__(self):
        self.query_history = defaultdict(list)  # (pid, base_domain) -> [timestamps]
        self.MAX_HISTORY = 20
        self.MIN_SAMPLES = 5
        self.REGULARITY_THRESHOLD = 0.15  # 15% вариация = регулярность
    
    def check(self, event):
        """Проверяет событие на C2 паттерн"""
        reasons = []
        
        # Извлекаем базовый домен (последние 2 уровня)
        parts = event.get('domain', '').split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else event.get('domain', '')
        
        key = (event.get('pid', 0), base_domain)
        timestamp = event.get('timestamp_ns', 0)
        
        # Добавляем в историю
        self.query_history[key].append(timestamp)
        
        # Ограничиваем размер истории
        if len(self.query_history[key]) > self.MAX_HISTORY:
            self.query_history[key] = self.query_history[key][-self.MAX_HISTORY:]
        
        timestamps = self.query_history[key]
        
        # Проверяем регулярность (нужно минимум 5 запросов)
        if len(timestamps) >= self.MIN_SAMPLES:
            intervals = [(timestamps[i+1] - timestamps[i]) / 1e9 
                        for i in range(len(timestamps)-1)]
            
            avg_interval = sum(intervals) / len(intervals)
            
            if avg_interval > 0:
                variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                cv = std_dev / avg_interval  # Коэффициент вариации
                
                if cv < self.REGULARITY_THRESHOLD and avg_interval > 5:  # >5 сек интервал
                    reasons.append(f"C2_BEACON(interval={avg_interval:.1f}s, regularity={1-cv:.0%})")
        
        # TXT запросы подозрительны для C2
        dns_type = event.get('dns_type', 1)
        if dns_type == 16:  # TXT
            # Проверяем не whitelist
            if not any(base_domain.endswith(w) for w in ['.google.com', '.microsoft.com', '.cloudflare.com']):
                reasons.append(f"C2_TXT_REQUEST")
        
        return len(reasons) > 0, reasons


class ExfiltrationDetector:
    """
    Детектор Data Exfiltration через DNS.
    
    Признаки:
    - Base64/Hex кодирование в subdomain
    - Высокая entropy (>4.0)
    - Длинные домены (>60 символов)
    - Много уникальных subdomain'ов
    """
    
    def __init__(self):
        self.subdomain_counts = defaultdict(set)  # base_domain -> set(subdomains)
        self.ENTROPY_THRESHOLD = 4.0
        self.LENGTH_THRESHOLD = 60
        self.DIGIT_RATIO_THRESHOLD = 0.3
        self.SUBDOMAIN_COUNT_THRESHOLD = 20
    
    def check(self, event):
        """Проверяет событие на exfiltration паттерн"""
        reasons = []
        domain = event.get('domain', '')
        
        if not domain or domain.startswith('<'):
            return False, reasons
        
        # Удаляем точки для анализа
        domain_clean = domain.replace('.', '')
        
        # 1. Высокая entropy
        entropy = calculate_entropy(domain_clean)
        if entropy > self.ENTROPY_THRESHOLD:
            reasons.append(f"HIGH_ENTROPY({entropy:.2f})")
        
        # 2. Длинный домен
        if len(domain) > self.LENGTH_THRESHOLD:
            reasons.append(f"LONG_DOMAIN({len(domain)})")
        
        # 3. Много цифр (hex encoding)
        if len(domain_clean) > 0:
            digit_ratio = sum(c.isdigit() for c in domain_clean) / len(domain_clean)
            if digit_ratio > self.DIGIT_RATIO_THRESHOLD:
                reasons.append(f"HIGH_DIGIT_RATIO({digit_ratio:.0%})")
        
        # 4. Base64 паттерн в первом subdomain
        parts = domain.split('.')
        if len(parts) > 2:
            first_subdomain = parts[0]
            if len(first_subdomain) > 20:
                # Base64 паттерн
                if re.match(r'^[A-Za-z0-9+/=]+$', first_subdomain):
                    reasons.append("BASE64_SUBDOMAIN")
                # Hex паттерн
                elif re.match(r'^[0-9a-fA-F]+$', first_subdomain):
                    reasons.append("HEX_SUBDOMAIN")
        
        # 5. Много уникальных subdomain'ов к одному домену
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
            
            self.subdomain_counts[base_domain].add(subdomain)
            
            if len(self.subdomain_counts[base_domain]) > self.SUBDOMAIN_COUNT_THRESHOLD:
                reasons.append(f"MANY_SUBDOMAINS({len(self.subdomain_counts[base_domain])})")
        
        return len(reasons) > 0, reasons


class IPOverDNSDetector:
    """
    Детектор IP-Over-DNS туннелей (iodine, dns2tcp).
    
    Признаки:
    - NULL (type 10) записи
    - Очень высокая частота запросов (>50/сек)
    - Большие ответы
    """
    
    def __init__(self):
        self.request_counts = defaultdict(int)  # (pid, base_domain) -> count
        self.window_start = 0
        self.WINDOW_NS = 10 * 1e9  # 10 секунд в наносекундах
        self.RATE_THRESHOLD = 50  # >50 req/sec = подозрительно
    
    def check(self, event):
        """Проверяет событие на IP-Over-DNS паттерн"""
        reasons = []
        
        timestamp = event.get('timestamp_ns', 0)
        
        # Сброс окна
        if self.window_start == 0:
            self.window_start = timestamp
        elif timestamp - self.window_start > self.WINDOW_NS:
            self.request_counts.clear()
            self.window_start = timestamp
        
        # Извлекаем базовый домен
        domain = event.get('domain', '')
        parts = domain.split('.')
        base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        
        key = (event.get('pid', 0), base_domain)
        self.request_counts[key] += 1
        
        # Проверяем rate
        elapsed_sec = (timestamp - self.window_start) / 1e9
        if elapsed_sec > 1:
            rate = self.request_counts[key] / elapsed_sec
            if rate > self.RATE_THRESHOLD:
                reasons.append(f"HIGH_RATE({rate:.1f}/sec)")
        
        # NULL тип записи (iodine signature)
        dns_type = event.get('dns_type', 1)
        if dns_type == 10:  # NULL
            reasons.append("NULL_RECORD(iodine)")
        
        # Большое количество ответов (данные в ответе)
        dns_answers = event.get('dns_answers', 0)
        if dns_answers > 5:
            reasons.append(f"MANY_ANSWERS({dns_answers})")
        
        return len(reasons) > 0, reasons


class TunnelDetector:
    """Объединяет все детекторы"""
    
    def __init__(self):
        self.c2_detector = C2Detector()
        self.exfil_detector = ExfiltrationDetector()
        self.ipodns_detector = IPOverDNSDetector()
    
    def analyze(self, event):
        """
        Анализирует событие всеми детекторами.
        
        Returns:
            tuple: (is_suspicious, threat_type, reasons)
        """
        all_reasons = []
        threat_types = []
        
        # C2 детекция
        is_c2, c2_reasons = self.c2_detector.check(event)
        if is_c2:
            threat_types.append("C2")
            all_reasons.extend(c2_reasons)
        
        # Exfiltration детекция
        is_exfil, exfil_reasons = self.exfil_detector.check(event)
        if is_exfil:
            threat_types.append("EXFIL")
            all_reasons.extend(exfil_reasons)
        
        # IP-Over-DNS детекция
        is_ipodns, ipodns_reasons = self.ipodns_detector.check(event)
        if is_ipodns:
            threat_types.append("TUNNEL")
            all_reasons.extend(ipodns_reasons)
        
        is_suspicious = len(all_reasons) > 0
        threat_type = '+'.join(threat_types) if threat_types else None
        
        return is_suspicious, threat_type, all_reasons


# Глобальный детектор
tunnel_detector = TunnelDetector()

# ===== СТАТИСТИКА =====

stats = {
    'total': 0,
    'udp_queries': 0,
    'udp_responses': 0,
    'tcp_queries': 0,
    'tcp_responses': 0,
    'by_process': defaultdict(int),
    'by_pod': defaultdict(int),
    'suspicious': 0,
    'domains': set()
}

pod_resolver = PodResolver()
domain_history = defaultdict(list)

# ===== ОБРАБОТКА СОБЫТИЙ =====

def handle_event(cpu, data, size):
    """Обработчик событий из eBPF (Perf Buffer: cpu, data, size)"""
    global stats
    
    event = ctypes.cast(data, ctypes.POINTER(DNSEvent)).contents
    
    # Парсим домен (используем data_len, иначе парсим мусор и домены не считаются)
    raw = event.dns_data
    data_len = event.data_len or len(raw)
    if data_len >= 12:
        domain = parse_dns_name(list(raw)[:data_len], offset=12)
    else:
        domain = None
    if not domain:
        domain = "<unparseable>"
    
    # Тип DNS (тот же срез по data_len)
    dns_payload = list(raw)[:data_len] if data_len else list(raw)
    dns_type = parse_dns_type(dns_payload)
    dns_type_name = get_dns_type_name(dns_type)
    
    # Направление
    is_response = (event.direction == 2)
    direction = "RESPONSE" if is_response else "QUERY"
    
    # Протокол
    protocol = "TCP" if event.protocol == 6 else "UDP"
    
    # Процесс
    comm = event.comm.decode('utf-8', errors='ignore').rstrip('\x00')
    
    # Pod информация (по возможности namespace/name для быстрого поиска "какой под")
    pod_info = pod_resolver.get_pod_info(event.pid, event.cgroup_id, event.netns_id)
    pod_str = ""
    if pod_info:
        if pod_info.get("namespace_name"):
            pod_str = pod_info["namespace_name"]  # e.g. default/dns-suspicious-exfil
        elif pod_info['type'] == 'kubernetes':
            pod_str = f"pod:{pod_info['pod_uid']}"
        else:
            pod_str = f"container:{pod_info['container_id']}"
    
    # IP адреса
    saddr = socket.inet_ntoa(struct.pack('I', event.saddr)) if event.saddr else "0.0.0.0"
    daddr = socket.inet_ntoa(struct.pack('I', event.daddr)) if event.daddr else "0.0.0.0"
    
    # Timestamp - используем KERNEL timestamp (исправление 8.2.2)
    if event.timestamp_ns > 0:
        # Kernel timestamp - наносекунды с момента загрузки
        # Конвертируем в относительное время
        boot_time = time.time() - (time.monotonic())
        ts_seconds = boot_time + (event.timestamp_ns / 1e9)
        ts = datetime.fromtimestamp(ts_seconds).strftime('%H:%M:%S.%f')[:-3]
    else:
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    
    # DNS Header info (исправление 8.2.1)
    dns_id = event.dns_id
    dns_flags = event.dns_flags
    
    # Статистика
    stats['total'] += 1
    stats['by_process'][comm] += 1
    if pod_str:
        stats['by_pod'][pod_str] += 1
    
    if protocol == "UDP":
        if is_response:
            stats['udp_responses'] += 1
            if FLASK_AVAILABLE:
                dns_responses_total.labels(protocol='UDP').inc()
        else:
            stats['udp_queries'] += 1
            if FLASK_AVAILABLE:
                dns_queries_total.labels(protocol='UDP', direction='query').inc()
    else:
        if is_response:
            stats['tcp_responses'] += 1
            if FLASK_AVAILABLE:
                dns_responses_total.labels(protocol='TCP').inc()
        else:
            stats['tcp_queries'] += 1
            if FLASK_AVAILABLE:
                dns_queries_total.labels(protocol='TCP', direction='query').inc()
    
    if domain and not domain.startswith("<"):
        stats['domains'].add(domain)
        if FLASK_AVAILABLE:
            dns_domains_unique.set(len(stats['domains']))
    
    # Prometheus метрики: process+pod вместе — чтобы в Grafana видеть "какой под какой процесс"
    pod_label = pod_str or "host"
    if FLASK_AVAILABLE:
        dns_events_by_process.labels(process=comm or "unknown", pod=pod_label).inc()
        dns_events_by_pod.labels(pod=pod_label).inc()
    
    # Анализ подозрительности через детекторы туннелей
    event_data = {
        'domain': domain,
        'dns_type': dns_type,
        'dns_answers': event.dns_answers,
        'timestamp_ns': event.timestamp_ns,
        'pid': event.pid,
        'comm': comm,
    }
    
    is_suspicious, threat_type, threat_reasons = tunnel_detector.analyze(event_data)
    
    # Entropy для отображения
    entropy = calculate_entropy(domain.replace('.', ''))
    
    if is_suspicious:
        stats['suspicious'] += 1
        if FLASK_AVAILABLE:
            # Обновляем Prometheus метрики для подозрительных запросов
            threat_label = threat_type if threat_type else 'UNKNOWN'
            dns_suspicious_total.labels(threat_type=threat_label).inc()
    
    # Вывод
    color = RED if is_suspicious else (BLUE if is_response else GREEN)
    pod_display = f" [{CYAN}{pod_str}{RESET}]" if pod_str else ""
    
    # Форматирование IP (исправление - показываем IP)
    if is_response:
        ip_info = f"{daddr}←{saddr}"
    else:
        ip_info = f"{saddr}→{daddr}"
    
    # Основная строка
    print(f"[{ts}] {color}{protocol:3} {direction:8}{RESET} | "
          f"ID:{dns_id:04x} | "
          f"PID:{event.pid:>6} {comm:>15}{pod_display} | "
          f"{dns_type_name:>5} | {domain}")
    
    if is_suspicious:
        threat_label = f"[{threat_type}]" if threat_type else ""
        print(f"         {RED}⚠ SUSPICIOUS {threat_label}: {', '.join(threat_reasons)}{RESET}")
        print(f"         {YELLOW}   IP: {ip_info} | Entropy: {entropy:.2f} | Flags: 0x{dns_flags:04x}{RESET}")

def print_stats():
    """Выводит статистику"""
    print("\n" + "=" * 80)
    print(f"{BOLD}                    СТАТИСТИКА (УЛУЧШЕННАЯ ВЕРСИЯ){RESET}")
    print("=" * 80)
    
    print(f"""
  Всего событий:           {stats['total']}
  
  UDP:
    Запросов:              {stats['udp_queries']}
    Ответов:               {stats['udp_responses']}
  
  TCP:
    Запросов:              {stats['tcp_queries']}
    Ответов:               {stats['tcp_responses']}
  
  Подозрительных:          {RED}{stats['suspicious']}{RESET}
  Уникальных доменов:      {len(stats['domains'])}
""")
    
    print("  По процессам:")
    for proc, count in sorted(stats['by_process'].items(), key=lambda x: -x[1])[:10]:
        print(f"    {proc:<20} {count:>5}")
    
    if stats['by_pod']:
        print("\n  По подам/контейнерам:")
        for pod, count in sorted(stats['by_pod'].items(), key=lambda x: -x[1])[:10]:
            print(f"    {pod:<30} {count:>5}")
    
    print("=" * 80)

def signal_handler(sig, frame):
    print_stats()
    sys.exit(0)

def main():
    print("=" * 80)
    print(f"{BOLD}       DNS TUNNEL DETECTOR v2.1 (Ring Buffer){RESET}")
    print("=" * 80)
    print(f"  Детекция типов туннелей:")
    print(f"    ✓ {CYAN}C2{RESET}     - Command & Control (регулярность, TXT)")
    print(f"    ✓ {CYAN}EXFIL{RESET}  - Data Exfiltration (entropy, Base64)")
    print(f"    ✓ {CYAN}TUNNEL{RESET} - IP-Over-DNS (iodine, NULL records)")
    print(f"  Возможности:")
    print(f"    ✓ UDP + TCP DNS")
    print(f"    ✓ Kubernetes pod идентификация")
    print(f"    ✓ Kernel timestamp (для анализа частоты)")
    print(f"    ✓ {GREEN}Perf Buffer{RESET} (совместимость при ограничениях памяти)")
    print("=" * 80)
    
    # Лимит memlock у этого процесса (тот же, что будет выделять BPF)
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        soft_s = "unlimited" if soft == -1 else f"{soft} bytes"
        hard_s = "unlimited" if hard == -1 else f"{hard} bytes"
        print(f"\n[DEBUG] RLIMIT_MEMLOCK: soft={soft_s}, hard={hard_s}")
    except (ValueError, OSError, AttributeError) as e:
        print(f"\n[DEBUG] RLIMIT_MEMLOCK: N/A ({e})")
    
    # Загружаем eBPF по шагам для отладки
    print(f"\n[*] Загрузка eBPF из {BPF_SOURCE_FILE}...")
    
    try:
        print(f"[*] Шаг 1/3: чтение файла...")
        with open(BPF_SOURCE_FILE, 'r') as f:
            bpf_text = f.read()
        print(f"[*] Шаг 1/3: OK ({len(bpf_text)} байт)")
    except Exception as e:
        print(f"{RED}[!] Ошибка на шаге 1 (чтение файла): {e}{RESET}")
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print(f"[*] Шаг 2/3: BPF(text=...) — компиляция и загрузка в ядро...")
        bpf = BPF(text=bpf_text)
        print(f"{GREEN}[+] Шаг 2/3: OK — eBPF программа загружена{RESET}")
    except Exception as e:
        print(f"{RED}[!] Ошибка на шаге 2 (BPF load): {e}{RESET}")
        traceback.print_exc()
        sys.exit(1)
    
    try:
        print(f"[*] Шаг 3/3: открытие perf buffer (map 'events')...")
        bpf["events"].open_perf_buffer(handle_event)
        print(f"{GREEN}[+] Шаг 3/3: OK — perf buffer открыт{RESET}")
    except Exception as e:
        print(f"{RED}[!] Ошибка на шаге 3 (open_perf_buffer): {e}{RESET}")
        traceback.print_exc()
        sys.exit(1)
    
    # Запускаем HTTP сервер для метрик и health checks
    metrics_port = int(os.getenv('METRICS_PORT', '9999'))
    if FLASK_AVAILABLE:
        http_thread = threading.Thread(
            target=start_http_server,
            args=(metrics_port,),
            daemon=True,
            name='HTTP-Server'
        )
        http_thread.start()
        print(f"{GREEN}[+] HTTP сервер запущен на порту {metrics_port}{RESET}")
        print(f"    - /healthz - liveness probe")
        print(f"    - /ready - readiness probe")
        print(f"    - /metrics - Prometheus metrics")
    else:
        print(f"{YELLOW}[!] HTTP сервер недоступен (Flask не установлен){RESET}")
    
    # Обработка Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    print(f"\n[*] Мониторинг активен (Ctrl+C для статистики)...")
    print(f"[*] Используется Perf Buffer")
    print("-" * 80)
    
    while True:
        try:
            bpf.perf_buffer_poll(300)  # timeout ms
        except KeyboardInterrupt:
            break
    
    print_stats()

if __name__ == "__main__":
    main()
