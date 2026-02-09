# Инструменты для сравнения: DNS Tunnel Detection

## Обзор

Этот документ содержит анализ инструментов, которые можно использовать для сравнения с нашим eBPF DNS tunnel detector. Включает инструкции по настройке и тестированию.

---

## 1. Сравнительная таблица инструментов

| Инструмент | Технология | DNS Tunnel Detection | Kubernetes Support | Open Source | Примечания |
|------------|-----------|---------------------|-------------------|-------------|------------|
| **Наш модуль** | eBPF (BCC) | ✅ Да (специализированный) | ✅ Да (DaemonSet) | ✅ Да | Специализированный детектор |
| **Tetragon** | eBPF (libbpf) | ⚠️ Частично (через события) | ✅ Да (нативный) | ✅ Да | Security observability, не специализирован на DNS |
| **Falco** | eBPF/kernel module | ⚠️ Через правила | ✅ Да | ✅ Да | Runtime security, требует кастомных правил |
| **Suricata** | IDS/IPS (не eBPF) | ✅ Да (правила) | ⚠️ Через DaemonSet | ✅ Да | Традиционный IDS, не eBPF |
| **dnc.py** | eBPF (BCC) | ❌ Нет (только мониторинг) | ❌ Нет | ✅ Да | Простой монитор без детекции |

---

## 2. Tetragon (Cilium)

### 2.1 Описание

**Tetragon** — это eBPF-based security observability platform от Cilium. Использует libbpf (не BCC), работает на уровне kernel events.

**Возможности для DNS**:
- ✅ Перехват DNS запросов через kprobe
- ✅ Связь процесса с DNS запросами
- ⚠️ Нет встроенной детекции туннелей (только события)
- ✅ Kubernetes-native (DaemonSet)

### 2.2 Установка

```bash
# 1. Установка через Helm
helm repo add cilium https://helm.cilium.io/
helm repo update

# 2. Установка Tetragon
helm install tetragon cilium/tetragon -n kube-system

# 3. Проверка
kubectl get pods -n kube-system | grep tetragon
```

### 2.3 Настройка для DNS мониторинга

**Tetragon TracingPolicy для DNS**:

```yaml
# dns-tracing-policy.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "dns-monitoring"
spec:
  kprobes:
    # UDP DNS queries
    - call: "udp_sendmsg"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchArgs:
          - index: 0
            type: "sock"
            operator: "Equal"
            values:
            - "dport:53"
          matchActions:
          - action: FollowFD
            argFd: 0
            argName: "dns-socket"
          - action: SigKill
    
    # TCP DNS queries
    - call: "tcp_sendmsg"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchArgs:
          - index: 0
            type: "sock"
            operator: "Equal"
            values:
            - "dport:53"
```

**Применение**:
```bash
kubectl apply -f dns-tracing-policy.yaml
```

### 2.4 Тестирование

```bash
# 1. Просмотр событий в реальном времени
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -f

# 2. Фильтрация DNS событий
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon | grep -i dns

# 3. Использование tetragon CLI (если установлен)
tetragon observe --namespace default
```

### 2.5 Ограничения для DNS Tunnel Detection

- ❌ **Нет встроенной детекции туннелей** — только события
- ❌ **Нет анализа DNS payload** — только метаданные
- ❌ **Нет эвристик** (entropy, length, frequency)
- ⚠️ **Требуется userspace обработка** для детекции

**Вывод**: Tetragon хорош для мониторинга, но не для специализированной детекции DNS туннелей.

---

## 3. Falco

### 3.1 Описание

**Falco** — runtime security tool, может использовать eBPF или kernel module. Имеет систему правил для детекции аномалий.

**Возможности для DNS**:
- ✅ Перехват системных вызовов (sendmsg, recvmsg)
- ✅ Кастомные правила для DNS
- ⚠️ Требует написания правил для детекции туннелей
- ✅ Kubernetes support

### 3.2 Установка

```bash
# 1. Установка через Helm
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# 2. Установка Falco
helm install falco falcosecurity/falco \
  --set driver.enabled=true \
  --set ebpf.enabled=true \
  -n falco-system --create-namespace

# 3. Проверка
kubectl get pods -n falco-system
```

### 3.3 Настройка правил для DNS Tunnel Detection

**Кастомное правило Falco** (`dns-tunnel-rules.yaml`):

```yaml
# DNS Tunnel Detection Rules for Falco
- rule: DNS Tunnel Suspicious Domain Length
  desc: Detect DNS queries with unusually long domain names (potential tunneling)
  condition: >
    evt.type = sendmsg and
    evt.dir = < and
    fd.sport = 53 and
    evt.args.data contains "dns" and
    evt.args.len > 200
  output: >
    DNS tunnel suspected - long domain name
    (user=%user.name process=%proc.name pid=%proc.pid
     domain=%evt.args.data)
  priority: WARNING
  tags: [network, dns, tunnel]

- rule: DNS Tunnel High Frequency Queries
  desc: Detect high frequency DNS queries from single process (C2/exfiltration)
  condition: >
    evt.type = sendmsg and
    evt.dir = < and
    fd.sport = 53 and
    evt.count > 100 in 10s
  output: >
    DNS tunnel suspected - high frequency queries
    (user=%user.name process=%proc.name pid=%proc.pid
     count=%evt.count)
  priority: CRITICAL
  tags: [network, dns, tunnel, c2]

- rule: DNS Tunnel TXT or NULL Records
  desc: Detect suspicious DNS record types (TXT, NULL) used in tunneling
  condition: >
    evt.type = sendmsg and
    evt.dir = < and
    fd.sport = 53 and
    (evt.args.data contains "TXT" or evt.args.data contains "NULL")
  output: >
    DNS tunnel suspected - suspicious record type
    (user=%user.name process=%proc.name pid=%proc.pid
     record_type=%evt.args.data)
  priority: WARNING
  tags: [network, dns, tunnel]
```

**Применение**:
```bash
# 1. Создать ConfigMap с правилами
kubectl create configmap falco-rules -n falco-system \
  --from-file=dns-tunnel-rules.yaml

# 2. Обновить Falco deployment для использования правил
# (добавить volume mount в values.yaml или через helm upgrade)
helm upgrade falco falcosecurity/falco \
  --set customRules.dns-tunnel-rules.yaml.enabled=true \
  -n falco-system
```

### 3.4 Тестирование

```bash
# 1. Просмотр событий
kubectl logs -n falco-system -l app=falco -f | grep -i "dns tunnel"

# 2. Генерация тестового DNS трафика
dig @8.8.8.8 test.example.com TXT

# 3. Проверка алертов
kubectl logs -n falco-system -l app=falco | grep "DNS tunnel"
```

### 3.5 Ограничения

- ⚠️ **Ограниченный доступ к DNS payload** — Falco работает на уровне syscalls
- ⚠️ **Сложность анализа DNS данных** — нужно парсить payload в правилах
- ⚠️ **Производительность** — правила выполняются для каждого события
- ❌ **Нет специализированных DNS эвристик** — нужно писать самому

**Вывод**: Falco может детектировать DNS туннели, но требует значительной настройки и менее эффективен, чем специализированный детектор.

---

## 4. Suricata

### 4.1 Описание

**Suricata** — IDS/IPS система, не использует eBPF, работает на уровне сетевых пакетов (libpcap/DPDK).

**Возможности для DNS**:
- ✅ Полный анализ DNS пакетов
- ✅ Встроенные правила для DNS tunneling
- ✅ Поддержка ET Open rules
- ⚠️ Не eBPF (традиционный IDS)

### 4.2 Установка

```bash
# 1. Установка Suricata (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y suricata suricata-update

# 2. Обновление правил
sudo suricata-update

# 3. Для Kubernetes (DaemonSet)
# Используйте официальный образ: jasonish/suricata
```

### 4.3 Настройка правил для DNS Tunnel Detection

**Кастомные правила Suricata** (`dns-tunnel.rules`):

```suricata
# DNS Tunnel Detection Rules

# Long domain names (potential tunneling)
alert dns any any -> any 53 (msg:"DNS Tunnel - Long Domain Name"; \
  dns.query; content:"."; distance:0; within:200; \
  threshold: type limit, track by_src, count 10, seconds 60; \
  sid:1000001; rev:1;)

# High frequency DNS queries (C2/exfiltration)
alert dns any any -> any 53 (msg:"DNS Tunnel - High Frequency Queries"; \
  threshold: type threshold, track by_src, count 100, seconds 10; \
  sid:1000002; rev:1;)

# Suspicious record types (TXT, NULL)
alert dns any any -> any 53 (msg:"DNS Tunnel - TXT Record"; \
  dns.query; content:"TXT"; nocase; \
  threshold: type limit, track by_src, count 5, seconds 60; \
  sid:1000003; rev:1;)

alert dns any any -> any 53 (msg:"DNS Tunnel - NULL Record"; \
  dns.query; content:"NULL"; nocase; \
  threshold: type limit, track by_src, count 5, seconds 60; \
  sid:1000004; rev:1;)

# Large DNS responses (IP-over-DNS)
alert dns any 53 -> any any (msg:"DNS Tunnel - Large Response"; \
  dns.answers; dsize:>512; \
  threshold: type limit, track by_dst, count 10, seconds 60; \
  sid:1000005; rev:1;)
```

**Применение**:
```bash
# 1. Добавить правила в Suricata
sudo cp dns-tunnel.rules /etc/suricata/rules/

# 2. Обновить suricata.yaml для включения правил
# В /etc/suricata/suricata.yaml:
# default-rule-path: /etc/suricata/rules
# rule-files:
#   - dns-tunnel.rules

# 3. Перезапустить Suricata
sudo systemctl restart suricata
```

### 4.4 Тестирование

```bash
# 1. Просмотр алертов
sudo tail -f /var/log/suricata/fast.log | grep "DNS Tunnel"

# 2. Генерация тестового трафика
dig @8.8.8.8 test.example.com TXT

# 3. Проверка статистики
sudo suricatasc -c "stats"
```

### 4.5 Ограничения

- ❌ **Не eBPF** — традиционный IDS, выше overhead
- ❌ **Нет связи с процессами** — только сетевой уровень
- ⚠️ **Сложность в Kubernetes** — требует host network или специальной настройки
- ⚠️ **Производительность** — может быть узким местом при высокой нагрузке

**Вывод**: Suricata эффективен для детекции DNS туннелей, но не использует eBPF и менее интегрирован с Kubernetes.

---

## 5. dnc.py — Анализ

### 5.1 Описание

**dnc.py** — простой DNS монитор на eBPF (BCC), перехватывает DNS трафик и логирует запросы/ответы.

**Архитектура**:
- Использует **kprobe** на `udp_sendmsg` и `tcp_sendmsg`
- Использует **socket filter** для перехвата пакетов
- Парсит DNS через `dnslib`
- Логирует в файл и stdout

### 5.2 Сравнение с нашим модулем

| Функция | dnc.py | Наш модуль |
|---------|--------|------------|
| **eBPF технология** | BCC | BCC |
| **Перехват DNS** | ✅ UDP + TCP | ✅ UDP + TCP |
| **Парсинг DNS** | ✅ (dnslib) | ✅ (встроенный) |
| **Детекция туннелей** | ❌ Нет | ✅ Да (C2, Exfil, IP-over-DNS) |
| **Kubernetes support** | ❌ Нет | ✅ Да (cgroup_id, netns_id) |
| **Ring Buffer** | ❌ Perf Buffer | ✅ Ring Buffer |
| **Эвристики** | ❌ Нет | ✅ Entropy, length, frequency |
| **Метрики** | ❌ Нет | ✅ Prometheus |
| **Логирование** | ✅ Файл | ✅ JSON + файл |

### 5.3 Полезность для ВКР

**Что можно использовать**:
- ✅ **Подход к перехвату** — комбинация kprobe + socket filter
- ✅ **Парсинг DNS** — использование `dnslib` (можно сравнить с нашим парсингом)
- ✅ **Структура кода** — как пример простого монитора

**Что не подходит**:
- ❌ **Нет детекции** — только мониторинг
- ❌ **Нет Kubernetes интеграции**
- ❌ **Устаревший подход** — Perf Buffer вместо Ring Buffer

**Вывод**: `dnc.py` полезен как **базовая референсная реализация** для сравнения подхода к перехвату, но не для детекции туннелей.

---

## 6. Анализ статей

### 6.1 2507.10267v1.pdf — "DNS Tunneling: Threat Landscape and Improved Detection Solutions"

**Авторы**: Baran Işık, Bilal İhsan Tuncer, Novruz Amirov, Şerif Bahtiyar (Istanbul Technical University)

**Ключевые моменты**:

1. **Machine Learning подход**:
   - Используют Random Forest, SVM, K-means
   - Создали "DNS Sentinel" framework
   - Точность выше традиционных методов

2. **Методы детекции**:
   - Анализ длины доменных имен
   - Частота запросов
   - Типы записей (TXT, NULL)
   - Энтропия данных

3. **Полезность для ВКР**:
   - ✅ **Теоретическая база** — обоснование ML подхода
   - ✅ **Эвристики** — можно сравнить с нашими
   - ✅ **Метрики** — accuracy, precision, recall для сравнения
   - ⚠️ **Не eBPF** — они используют традиционный анализ трафика

**Как использовать**:
- Сравнить наши эвристики с их ML features
- Использовать их метрики для оценки нашего детектора
- Цитировать как современный подход к детекции

### 6.2 sensors-23-02760.pdf — (нужно прочитать)

**Статус**: Требуется чтение для полного анализа.

**Предположения** (на основе названия):
- Статья из журнала Sensors (MDPI)
- Вероятно про DNS security или tunneling
- Может содержать практические методы детекции

**Рекомендация**: Прочитать статью и добавить анализ в этот документ.

---

## 7. Выводы и рекомендации

### 7.1 Инструменты для сравнения

**Рекомендуемые для сравнения**:

1. **Suricata** (основной конкурент):
   - ✅ Специализированные правила для DNS tunneling
   - ✅ Полный анализ DNS пакетов
   - ⚠️ Не eBPF (можно подчеркнуть преимущество нашего подхода)

2. **Falco** (с кастомными правилами):
   - ✅ eBPF-based (как наш)
   - ⚠️ Требует настройки правил
   - ⚠️ Менее эффективен для DNS

3. **Tetragon** (для мониторинга):
   - ✅ eBPF-based, Kubernetes-native
   - ❌ Нет детекции (только события)

### 7.2 Уникальность нашего подхода

**Преимущества**:
- ✅ **Специализированный eBPF детектор** для DNS tunneling
- ✅ **Kubernetes-native** (cgroup_id, netns_id)
- ✅ **Комбинация эвристик** (entropy, length, frequency, record types)
- ✅ **Низкий overhead** (Ring Buffer, kernel-level фильтрация)
- ✅ **Open source** и готов к production

**Для ВКР**:
- ✅ **Новизна** — специализированный eBPF детектор (не найдено в open source)
- ✅ **Практичность** — готов к использованию в Kubernetes
- ✅ **Эффективность** — сравнение с Suricata покажет преимущества eBPF

### 7.3 План тестирования

1. **Бенчмарки**:
   - Сравнить overhead (CPU, memory) с Suricata
   - Измерить latency детекции
   - Протестировать на реальном трафике

2. **Точность**:
   - Использовать датасет из статьи 2507.10267v1.pdf
   - Сравнить precision/recall с Suricata
   - Протестировать на известных туннелях (iodine, dnscat2)

3. **Kubernetes**:
   - Развернуть в тестовом кластере
   - Сравнить с Falco/Tetragon по интеграции
   - Измерить влияние на производительность кластера

---

## 8. Быстрый старт для тестирования

### 8.1 Установка всех инструментов (для сравнения)

```bash
#!/bin/bash
# install_all_tools.sh

# 1. Suricata
sudo apt-get install -y suricata suricata-update
sudo suricata-update

# 2. Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco --set ebpf.enabled=true

# 3. Tetragon
helm repo add cilium https://helm.cilium.io/
helm install tetragon cilium/tetragon

# 4. Наш модуль
cd prototype_improved
kubectl apply -f k8s/daemonset.yaml
```

### 8.2 Генерация тестового трафика

```bash
# 1. Нормальный DNS трафик
dig @8.8.8.8 google.com
dig @8.8.8.8 yandex.ru AAAA

# 2. Подозрительный трафик (длинные домены)
dig @8.8.8.8 $(python3 -c "print('a'*100 + '.example.com')") TXT

# 3. Высокая частота
for i in {1..100}; do dig @8.8.8.8 test$i.example.com; done
```

### 8.3 Сравнение результатов

```bash
# 1. Наш модуль
kubectl logs -l app=dns-detector | grep "TUNNEL"

# 2. Suricata
sudo tail -f /var/log/suricata/fast.log | grep "DNS Tunnel"

# 3. Falco
kubectl logs -n falco-system -l app=falco | grep "DNS tunnel"

# 4. Tetragon
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon | grep -i dns
```

---

## 9. Ссылки

- **Tetragon**: https://github.com/cilium/tetragon
- **Falco**: https://github.com/falcosecurity/falco
- **Suricata**: https://github.com/OISF/suricata
- **dnc.py**: (локальный файл)
- **Статья 2507.10267v1.pdf**: https://arxiv.org/abs/2507.10267

---

## 10. Заключение

**Главный вывод**: В open source **нет специализированного eBPF детектора DNS туннелей** для Kubernetes. Это подтверждает **новизну и актуальность** нашего подхода для ВКР.

**Рекомендации**:
1. Использовать **Suricata** как основной benchmark (традиционный подход)
2. Сравнить с **Falco** по overhead (оба eBPF)
3. Подчеркнуть **специализацию** нашего модуля vs. общие инструменты
4. Использовать статьи для **теоретического обоснования** эвристик

