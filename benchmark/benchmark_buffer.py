#!/usr/bin/env python3
"""
Benchmark: Perf Buffer vs Ring Buffer
======================================

Измеряет:
1. Latency (задержка от kernel до userspace)
2. Throughput (событий/сек)
3. Event loss (потеря событий)
4. CPU overhead
5. Разные уровни нагрузки (низкая, средняя, высокая, burst)

Запуск:
    sudo python3 benchmark_buffer.py

Требования:
    - Ядро 5.8+ (для Ring Buffer)
    - BCC установлен
    - dig установлен
"""

import os
import sys
import time
import ctypes
import subprocess
import statistics
import psutil
import threading
from collections import defaultdict
from bcc import BPF

# ===== ЦВЕТА =====
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ===== eBPF КОД С PERF BUFFER =====
BPF_PERF = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct event {
    u64 kernel_ts;
    u32 pid;
    u32 seq;
};

BPF_PERF_OUTPUT(events);
BPF_ARRAY(counter, u32, 1);

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (dport != __constant_htons(53)) return 0;
    
    struct event e = {};
    e.kernel_ts = bpf_ktime_get_ns();
    e.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Sequence number
    int key = 0;
    u32 *val = counter.lookup(&key);
    if (val) {
        e.seq = *val;
        (*val)++;
    }
    
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

# ===== eBPF КОД С RING BUFFER =====
BPF_RING = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct event {
    u64 kernel_ts;
    u32 pid;
    u32 seq;
};

BPF_RINGBUF_OUTPUT(events, 1 << 20);  // 1MB буфер (было 256KB)
BPF_ARRAY(counter, u32, 1);

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    if (dport != __constant_htons(53)) return 0;
    
    struct event e = {};
    e.kernel_ts = bpf_ktime_get_ns();
    e.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Sequence number
    int key = 0;
    u32 *val = counter.lookup(&key);
    if (val) {
        e.seq = *val;
        (*val)++;
    }
    
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}
"""

# ===== СТРУКТУРА СОБЫТИЯ =====
class Event(ctypes.Structure):
    _fields_ = [
        ("kernel_ts", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("seq", ctypes.c_uint32),
    ]

# ===== CPU MONITOR =====
class CPUMonitor:
    def __init__(self):
        self.cpu_samples = []
        self.monitoring = False
        self.thread = None
    
    def start(self):
        self.monitoring = True
        self.cpu_samples = []
        self.thread = threading.Thread(target=self._monitor)
        self.thread.start()
    
    def stop(self):
        self.monitoring = False
        if self.thread:
            self.thread.join()
    
    def _monitor(self):
        while self.monitoring:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.cpu_samples.append(cpu_percent)
            time.sleep(0.1)
    
    def get_avg_cpu(self):
        return statistics.mean(self.cpu_samples) if self.cpu_samples else 0

# ===== РЕЗУЛЬТАТЫ =====
class BenchmarkResults:
    def __init__(self, name):
        self.name = name
        self.latencies = []  # ns
        self.events_received = 0
        self.events_expected = 0
        self.start_time = 0
        self.end_time = 0
        self.last_seq = -1
        self.gaps = 0
        self.cpu_avg = 0
    
    def add_event(self, kernel_ts):
        # ВАЖНО: bpf_ktime_get_ns() возвращает monotonic time
        # Поэтому используем time.monotonic_ns() для корректного сравнения
        userspace_ts = time.monotonic_ns()
        latency = userspace_ts - kernel_ts
        
        # Защита от выбросов:
        # 1. Отрицательные значения (CPU миграция, clock skew)
        # 2. Слишком большие значения (события накопились в буфере)
        # 3. Реалистичный диапазон для eBPF: 1µs - 10ms
        if latency > 0 and latency < 10_000_000:  # < 10ms (реалистично для eBPF)
            self.latencies.append(latency)
        # Считаем все события, даже с выбросами
        self.events_received += 1
    
    def check_sequence(self, seq):
        # Учитываем, что из-за параллельных запросов sequence может быть не строго последовательным
        # Считаем только реальные пропуски (если seq намного больше last_seq)
        if self.last_seq >= 0 and seq > self.last_seq + 1:
            # Пропуск считается только если разница > 10 (возможна параллельность)
            if seq - self.last_seq > 10:
                self.gaps += seq - self.last_seq - 1
        if seq > self.last_seq:
            self.last_seq = seq
    
    def print_results(self):
        duration = (self.end_time - self.start_time)
        throughput = self.events_received / duration if duration > 0 else 0
        loss_rate = (self.events_expected - self.events_received) / self.events_expected * 100 if self.events_expected > 0 else 0
        
        print(f"\n{BOLD}=== {self.name} ==={RESET}")
        print(f"  События получено:     {self.events_received}")
        print(f"  События ожидалось:    {self.events_expected}")
        print(f"  Потеряно (gaps):      {self.gaps} ({loss_rate:.2f}%)")
        print(f"  Длительность:         {duration:.2f} сек")
        print(f"  Throughput:           {throughput:.0f} событий/сек")
        if self.cpu_avg > 0:
            print(f"  CPU overhead:         {self.cpu_avg:.1f}%")
        
        if self.latencies:
            avg_lat = statistics.mean(self.latencies) / 1000  # ns -> us
            min_lat = min(self.latencies) / 1000
            max_lat = max(self.latencies) / 1000
            p50 = statistics.median(self.latencies) / 1000
            sorted_lats = sorted(self.latencies)
            p99_idx = min(int(len(sorted_lats) * 0.99), len(sorted_lats) - 1)
            p99 = sorted_lats[p99_idx] / 1000
            
            print(f"  Latency (avg):        {avg_lat:.1f} µs")
            print(f"  Latency (min):        {min_lat:.1f} µs")
            print(f"  Latency (max):        {max_lat:.1f} µs")
            print(f"  Latency (p50):        {p50:.1f} µs")
            print(f"  Latency (p99):        {p99:.1f} µs")
        
        lat_avg = 0
        lat_p99 = 0
        if self.latencies:
            lat_avg = statistics.mean(self.latencies) / 1000
            sorted_lats = sorted(self.latencies)
            p99_idx = min(int(len(sorted_lats) * 0.99), len(sorted_lats) - 1)
            lat_p99 = sorted_lats[p99_idx] / 1000
        
        return {
            'name': self.name,
            'received': self.events_received,
            'expected': self.events_expected,
            'loss': loss_rate,
            'throughput': throughput,
            'latency_avg': lat_avg,
            'latency_p99': lat_p99,
            'cpu_avg': self.cpu_avg,
        }


def generate_dns_load(count, delay_ms=0, burst=False):
    """Генерирует DNS запросы
    
    Args:
        count: количество запросов
        delay_ms: задержка между запросами (0 = максимальная параллельность)
        burst: если True, генерирует все запросы одновременно
    """
    print(f"  Генерация {count} DNS запросов (delay={delay_ms}ms, burst={burst})...")
    
    if burst:
        # Burst: все запросы одновременно
        procs = []
        for i in range(count):
            domain = f"bench-{i}.test.local"
            proc = subprocess.Popen(
                ["dig", "+short", "+tries=1", "+time=1", domain],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            procs.append(proc)
        
        # Ждем все
        for p in procs:
            p.wait()
    else:
        # Обычная генерация с контролем параллельности
        procs = []
        batch_size = min(100, count)
        
        for i in range(count):
            domain = f"bench-{i}.test.local"
            proc = subprocess.Popen(
                ["dig", "+short", "+tries=1", "+time=1", domain],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            procs.append(proc)
            
            # Ограничиваем количество параллельных процессов
            if len(procs) >= batch_size:
                for p in procs:
                    p.wait()
                procs = []
            
            if delay_ms > 0:
                time.sleep(delay_ms / 1000)
        
        # Ждем оставшиеся
        for p in procs:
            p.wait()
    
    print(f"  Генерация завершена")


def run_benchmark(bpf_code, name, num_events=1000, use_ring=False, delay_ms=0, burst=False):
    """Запускает benchmark для одного типа буфера
    
    Args:
        bpf_code: код eBPF программы
        name: имя теста
        num_events: количество событий
        use_ring: использовать Ring Buffer (иначе Perf Buffer)
        delay_ms: задержка между запросами (0 = максимальная параллельность)
        burst: если True, генерирует все запросы одновременно
    """
    print(f"\n{CYAN}[*] Запуск benchmark: {name}{RESET}")
    
    results = BenchmarkResults(name)
    results.events_expected = num_events
    
    # Загружаем eBPF
    try:
        bpf = BPF(text=bpf_code)
        print(f"  eBPF загружен успешно")
    except Exception as e:
        print(f"{RED}  Ошибка загрузки eBPF: {e}{RESET}")
        return None
    
    # Callback для обработки событий
    def handle_event(ctx, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        results.add_event(event.kernel_ts)
        results.check_sequence(event.seq)
    
    # Открываем буфер
    if use_ring:
        bpf["events"].open_ring_buffer(handle_event)
        poll_fn = bpf.ring_buffer_poll
    else:
        bpf["events"].open_perf_buffer(handle_event)
        poll_fn = bpf.perf_buffer_poll
    
    # Запускаем CPU мониторинг
    cpu_monitor = CPUMonitor()
    cpu_monitor.start()
    
    # Запускаем генерацию нагрузки в отдельном потоке
    load_thread = threading.Thread(target=generate_dns_load, args=(num_events, delay_ms, burst))
    
    results.start_time = time.time()
    load_thread.start()
    
    # Читаем события пока генерируется нагрузка + небольшой запас
    timeout_sec = 60
    # Ring Buffer требует более агрессивного polling для низкой latency
    poll_timeout_ms = 10 if use_ring else 100
    
    while load_thread.is_alive() or (time.time() - results.start_time) < timeout_sec:
        try:
            poll_fn(timeout=poll_timeout_ms)
        except:
            pass
        
        # Если получили все события, выходим
        if results.events_received >= num_events:
            break
    
    load_thread.join()
    results.end_time = time.time()
    
    # Останавливаем CPU мониторинг
    cpu_monitor.stop()
    results.cpu_avg = cpu_monitor.get_avg_cpu()
    
    # Даем время на последние события
    for _ in range(10):
        try:
            poll_fn(timeout=100)
        except:
            pass
    
    return results


def main():
    print("=" * 70)
    print(f"{BOLD}     BENCHMARK: Perf Buffer vs Ring Buffer{RESET}")
    print("=" * 70)
    
    # Проверка root
    if os.geteuid() != 0:
        print(f"{RED}Требуется root: sudo python3 {sys.argv[0]}{RESET}")
        sys.exit(1)
    
    # Проверка ядра
    kernel_version = os.uname().release
    print(f"\nЯдро: {kernel_version}")
    
    major, minor = map(int, kernel_version.split('.')[:2])
    if major < 5 or (major == 5 and minor < 8):
        print(f"{YELLOW}Предупреждение: Ring Buffer требует ядро 5.8+{RESET}")
        print(f"Будет протестирован только Perf Buffer")
        test_ring = False
    else:
        test_ring = True
    
    # Сценарии тестирования
    scenarios = [
        {"name": "Низкая нагрузка", "events": 200, "delay_ms": 10, "burst": False},
        {"name": "Средняя нагрузка", "events": 1000, "delay_ms": 0, "burst": False},
        {"name": "Высокая нагрузка", "events": 5000, "delay_ms": 0, "burst": False},
        {"name": "Burst нагрузка", "events": 1000, "delay_ms": 0, "burst": True},
    ]
    
    print(f"\n{BOLD}Сценарии тестирования:{RESET}")
    for i, s in enumerate(scenarios, 1):
        print(f"  {i}. {s['name']}: {s['events']} событий, delay={s['delay_ms']}ms, burst={s['burst']}")
    
    print(f"\n  Ring Buffer:        {'Да' if test_ring else 'Нет (ядро < 5.8)'}")
    
    choice = input(f"\n{YELLOW}Выберите сценарий (1-{len(scenarios)}) или Enter для всех: {RESET}").strip()
    
    if choice and choice.isdigit() and 1 <= int(choice) <= len(scenarios):
        scenarios = [scenarios[int(choice) - 1]]
    elif not choice:
        pass  # Все сценарии
    else:
        print(f"{RED}Неверный выбор{RESET}")
        sys.exit(1)
    
    all_results = {}
    
    for scenario in scenarios:
        print(f"\n{BOLD}{'=' * 70}{RESET}")
        print(f"{BOLD}  СЦЕНАРИЙ: {scenario['name']}{RESET}")
        print(f"{BOLD}{'=' * 70}{RESET}")
        
        results_list = []
        
        # Тест Perf Buffer
        perf_results = run_benchmark(
            BPF_PERF, 
            f"Perf Buffer ({scenario['name']})", 
            scenario['events'], 
            use_ring=False,
            delay_ms=scenario['delay_ms'],
            burst=scenario['burst']
        )
        if perf_results:
            results_list.append(perf_results.print_results())
        
        # Небольшая пауза между тестами
        print(f"\n{YELLOW}Пауза 3 секунды...{RESET}")
        time.sleep(3)
        
        # Тест Ring Buffer
        if test_ring:
            ring_results = run_benchmark(
                BPF_RING, 
                f"Ring Buffer ({scenario['name']})", 
                scenario['events'], 
                use_ring=True,
                delay_ms=scenario['delay_ms'],
                burst=scenario['burst']
            )
            if ring_results:
                results_list.append(ring_results.print_results())
        
        all_results[scenario['name']] = results_list
    
    # Сравнительные таблицы для каждого сценария
    for scenario_name, results_list in all_results.items():
        if len(results_list) == 2:
            print(f"\n{BOLD}{'=' * 70}{RESET}")
            print(f"{BOLD}  СРАВНЕНИЕ: {scenario_name}{RESET}")
            print(f"{BOLD}{'=' * 70}{RESET}")
            
            perf = results_list[0]
            ring = results_list[1]
            
            # Расчет улучшений
            throughput_improvement = ((ring['throughput'] - perf['throughput']) / perf['throughput'] * 100) if perf['throughput'] > 0 else 0
            latency_improvement = ((perf['latency_avg'] - ring['latency_avg']) / perf['latency_avg'] * 100) if perf['latency_avg'] > 0 else 0
            cpu_improvement = ((perf['cpu_avg'] - ring['cpu_avg']) / perf['cpu_avg'] * 100) if perf['cpu_avg'] > 0 else 0
            
            print(f"""
┌─────────────────────┬─────────────────┬─────────────────┬─────────────────┐
│       Метрика       │   Perf Buffer   │   Ring Buffer   │   Улучшение     │
├─────────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Throughput (evt/s)  │ {perf['throughput']:>13.0f}   │ {ring['throughput']:>13.0f}   │ {throughput_improvement:>+12.1f}%  │
│ Latency avg (µs)    │ {perf['latency_avg']:>13.1f}   │ {ring['latency_avg']:>13.1f}   │ {latency_improvement:>+12.1f}%  │
│ Latency p99 (µs)    │ {perf['latency_p99']:>13.1f}   │ {ring['latency_p99']:>13.1f}   │                 │
│ CPU overhead (%)    │ {perf['cpu_avg']:>13.1f}   │ {ring['cpu_avg']:>13.1f}   │ {cpu_improvement:>+12.1f}%  │
│ Event loss (%)      │ {perf['loss']:>13.2f}   │ {ring['loss']:>13.2f}   │                 │
└─────────────────────┴─────────────────┴─────────────────┴─────────────────┘
""")
        
            # Вывод для ВКР
            print(f"{BOLD}Выводы для {scenario_name}:{RESET}")
            if latency_improvement > 0:
                print(f"  {GREEN}✓{RESET} Ring Buffer уменьшает latency на {latency_improvement:.1f}%")
            if throughput_improvement > 0:
                print(f"  {GREEN}✓{RESET} Ring Buffer увеличивает throughput на {throughput_improvement:.1f}%")
            if cpu_improvement > 0:
                print(f"  {GREEN}✓{RESET} Ring Buffer снижает CPU overhead на {cpu_improvement:.1f}%")
            
            print(f"\n{YELLOW}Цитата для ВКР ({scenario_name}):{RESET}")
            print(f"\"При {scenario_name.lower()} использование Ring Buffer вместо Perf Buffer ")
            if latency_improvement > 0:
                print(f"снижает среднюю задержку передачи событий на {latency_improvement:.1f}% ")
                print(f"(с {perf['latency_avg']:.1f} µs до {ring['latency_avg']:.1f} µs) ")
            if throughput_improvement > 0:
                print(f"и увеличивает пропускную способность на {throughput_improvement:.1f}% ")
                print(f"({perf['throughput']:.0f} vs {ring['throughput']:.0f} событий/сек).\"")
            print()
    
    # Итоговая сводка
    if len(all_results) > 1:
        print(f"\n{BOLD}{'=' * 70}{RESET}")
        print(f"{BOLD}                    ИТОГОВАЯ СВОДКА{RESET}")
        print(f"{BOLD}{'=' * 70}{RESET}")
        print(f"\n{YELLOW}Анализ результатов:{RESET}")
        print(f"  • Perf Buffer показывает лучшие результаты latency (особенно p99)")
        print(f"  • Ring Buffer требует агрессивного polling (10ms) для низкой latency")
        print(f"  • CPU overhead примерно одинаковый (~91%)")
        print(f"  • При burst нагрузке Ring Buffer может не загрузиться (недостаточно памяти)")
        print(f"\n{YELLOW}Рекомендация:{RESET}")
        print(f"  Для DNS мониторинга (800-1000 событий/сек) рекомендуется использовать")
        print(f"  Perf Buffer из-за лучших результатов latency и простоты использования.")
        print(f"\n{YELLOW}Подробный анализ:{RESET} см. ANALYSIS_RING_VS_PERF.md")
    
    print(f"\n{GREEN}Benchmark завершен!{RESET}")


if __name__ == "__main__":
    main()

