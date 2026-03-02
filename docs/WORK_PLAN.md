# План работ — DNS Tunnel Monitor (ВКР)

Дата: 2026-03-01

---

## 0. Статус по приоритетам (ANALYSIS.md)

| Приоритет | Задача | Статус |
|-----------|--------|--------|
| Высокий | Добавить `timestamp_ns` в событие (loader) и в `event_data` (event_handler) | **Готово** |
| Высокий | Передавать в детекторы timestamp_ns + direction | **Готово** (в event_data передаются timestamp_ns, direction, domain, dns_type, dns_answers, cgroup_id) |
| Средний | Конфигурируемые пороги детекторов (config/env) | В плане (Фаза 1) |
| Средний | Ограничение роста памяти в детекторах (TTL/LRU) | В плане (Фаза 1: BUG-11, 16, 26) |
| Средний | Смягчить C2_TXT (whitelist/комбинация с другими признаками) | В плане (ISSUE-12, Фаза 1) |
| Низкий | Юнит-тесты для парсинга и детекторов | **Частично готово** (tests/test_timestamp_detection.py — C2 beacon, IP-over-DNS rate/NULL); парсинг и exfil — в Фазе 2 |
| Низкий | Опционально: timestamp в BPF (bpf_ktime_get_ns) | Не в приоритете |

---

## 1. Готовность проекта

### Общая оценка: **~55%**

| Компонент | Готовность | Комментарий |
|-----------|:----------:|-------------|
| BPF-программа (cgroup_skb, захват UDP/53) | 80% | Работает, но payload 64 байта — мало; direction по egress/ingress, не по QR-биту |
| Парсинг DNS (domain, type, flags) | 75% | Работает для коротких доменов; нет bounds check в parse_dns_type |
| Детектор C2 (beacon + TXT) | 55% | **Готово:** timestamp_ns в loader + event_data; beacon только по query. TXT whitelist слишком узкий |
| Детектор Exfil (entropy, length, encoding, subdomains) | 35% | LONG_DOMAIN мёртв (BPF limit); HEX_SUBDOMAIN мёртв (regex order); энтропия по полному домену; subdomain_counts утекает |
| Детектор IP-over-DNS (rate, NULL, answers) | 50% | **Готово:** timestamp_ns передаётся — окно и rate считаются. Rate занижается (BUG-19); tumbling window (BUG-18) — в плане |
| Pod resolution (cgroup_id → ns/pod) | 70% | Работает, но кэш не инвалидируется; K8s API limit=500 |
| Prometheus метрики + Grafana | 75% | Работают, но label cardinality explosion при масштабе |
| Helm chart + DaemonSet деплой | 90% | Полный набор: DaemonSet, RBAC, ServiceMonitor, probes |
| Dockerfile | 90% | Рабочий, python:3.11-slim + bpfcc-tools |
| Тестирование (unit, integration) | 20% | **Готово:** tests/test_timestamp_detection.py (C2 beacon, IP-over-DNS rate/NULL, timestamp=0). Остальное — Фаза 2 |
| Валидация на реальном трафике (TP/FP) | 0% | Не проводилась |
| Сравнение с другими инструментами | 0% | Не проводилось |
| Документация (README, алгоритмы) | 70% | Хорошая, но не отражает текущие баги |

### Что работает сквозь (end-to-end):

```
BPF cgroup_skb → perf buffer → Python парсинг → 3 детектора → Prometheus → Grafana
       ✓              ✓              ✓             частично         ✓          ✓
```

Сквозной pipeline работает. Основная проблема — **качество детекции**: часть эвристик мертва, часть занижает/завышает.

---

## 2. Критические баги: исправить ДО всего остального

Эти баги напрямую влияют на корректность детекции. Без их исправления любое тестирование TP/FP бессмысленно.

### Приоритет 1: Блокеры валидации

| # | Баг | Суть | Влияние | Оценка трудозатрат |
|---|-----|------|---------|--------------------|
| **BUG-02** | PAYLOAD_SAMPLE = 64 | Домен обрезается до ~45 символов | LONG_DOMAIN мёртв, энтропия занижена | 1ч — изменить BPF struct + event_struct.py |
| **BUG-14** | Regex order: base64 перед hex | HEX_SUBDOMAIN никогда не сработает | Целая ветка детекции мертва | 10мин — поменять if/elif |
| **BUG-19** | Rate = count / window_elapsed | Занижение rate в N раз | IP-over-DNS пропускает всплески | 30мин — per-key first_seen |
| **BUG-18** | Tumbling window: global clear | Сброс всех ключей при смене окна | Потеря данных для ключей, начавших mid-window | 30мин — per-key windows или sliding |
| **BUG-03** | direction по egress/ingress | query/response инвертированы для DNS-серверов | C2 beacon считает интервалы по ответам | 15мин — использовать QR-бит из dns_flags |

### Приоритет 2: False Positives

| # | Баг | Суть | Влияние | Оценка |
|---|-----|------|---------|----|
| **ISSUE-12** | TXT whitelist = 3 домена | SPF/DKIM/ACME/cert-manager → FP | Шквал алертов в кластере | 30мин — расширить или убрать |
| **ISSUE-22** | Бинарный OR | 1 причина = suspicious | Любой TXT = алерт | 1-2ч — ввести scoring |
| **K8S** | Нет whitelist cluster DNS | `.svc.cluster.local` → FP | Core feature для ВКР | 30мин — whitelist в конфиг |

### Приоритет 3: Стабильность (OOM)

| # | Баг | Суть | Оценка |
|---|-----|------|--------|
| **BUG-11** | query_history keys ∞ | 1-2ч — LRU или TTL dict |
| **BUG-16** | subdomain_counts ∞ | 30мин — TTL или max size |
| **BUG-26** | PodResolver cache stale | 1ч — TTL-кэш |

**Суммарно на все критические фиксы: ~8-10 часов работы.**

---

## 3. Валидация: метрики и методология тестирования TP/FP

### 3.1 Метрики качества детекции

| Метрика | Формула | Что показывает |
|---------|---------|----------------|
| **True Positive Rate (Recall)** | TP / (TP + FN) | Какую долю реальных туннелей обнаруживаем |
| **False Positive Rate** | FP / (FP + TN) | Какую долю легитимного трафика ошибочно помечаем |
| **Precision** | TP / (TP + FP) | Какая доля алертов — настоящие туннели |
| **F1-score** | 2 × (Precision × Recall) / (Precision + Recall) | Баланс precision/recall |
| **Detection Latency** | Время от первого пакета туннеля до срабатывания | Скорость реакции (важно для C2 beacon) |
| **Resource overhead** | CPU/Memory delta с монитором и без | Стоимость мониторинга |

### 3.2 Тестовый стенд

```
┌──────────────────────────────────────────────────────┐
│  Kubernetes кластер (minikube / kind / 3-node)       │
│                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐ │
│  │ legitimate   │  │  iodine     │  │  dnscat2     │ │
│  │ workload     │  │  (tunnel)   │  │  (C2)        │ │
│  │ (curl, wget, │  │             │  │              │ │
│  │  nginx, etc) │  │             │  │              │ │
│  └──────┬───────┘  └──────┬──────┘  └──────┬───────┘ │
│         │                 │                │         │
│         └────────┬────────┴────────┬───────┘         │
│                  │                 │                  │
│          ┌───────▼─────────────────▼──────┐          │
│          │   dns-tunnel-monitor (DaemonSet)│          │
│          │   → Prometheus → Grafana        │          │
│          └────────────────────────────────┘          │
└──────────────────────────────────────────────────────┘
```

### 3.3 Инструменты для генерации tunnel-трафика (Ground Truth)

| Инструмент | Тип туннеля | Что тестирует | Установка |
|------------|-------------|---------------|-----------|
| **iodine** | IP-over-DNS (NULL/CNAME) | IP-over-DNS detector: rate, NULL record, many answers | `apt install iodine` / Docker image |
| **dnscat2** | C2 over DNS (TXT/CNAME/MX) | C2 detector: beacon regularity, TXT requests; Exfil: entropy, encoding | Ruby gem / Docker image |
| **dns2tcp** | TCP-over-DNS (TXT/KEY) | Exfil detector: high entropy, long domains, encoded subdomains | `apt install dns2tcp` |
| **DNSExfiltrator** | Data exfil (Base64 in subdomains) | Exfil detector: BASE64_SUBDOMAIN, MANY_SUBDOMAINS, entropy | Python tool, GitHub |
| **Sliver C2** | C2 framework (DNS transport) | C2 + Exfil: beacon + data channel | Go binary |

### 3.4 Инструменты для генерации легитимного трафика (Baseline)

| Инструмент | Что генерирует |
|------------|----------------|
| **dnsperf** / **queryperf** | Массовые DNS-запросы к заданным доменам (BIND utils) |
| **curl / wget в подах** | Обычный HTTP (→ DNS lookup) |
| **Kubernetes Jobs** | Service discovery, headless services, DNS-based routing |
| **CoreDNS query log** | Запись реального легитимного трафика кластера для replay |

### 3.5 Процедура тестирования

```
Шаг 1: Деплой кластера + dns-tunnel-monitor
Шаг 2: Прогреть легитимный трафик (5-10 мин baseline)
Шаг 3: Записать лог монитора (все события + все алерты)
Шаг 4: Запустить каждый tunnel tool по очереди (5 мин каждый)
Шаг 5: Собрать confusion matrix:
        - Пометить каждое событие: labeled_malicious / labeled_benign
        - Сопоставить с detected_suspicious / detected_clean
Шаг 6: Рассчитать метрики
Шаг 7: Повторить после fix'ов / тюнинга порогов
```

**Формат результата для ВКР:**

| Детектор | Tunnel tool | TP | FP | TN | FN | Precision | Recall | F1 |
|----------|-------------|----|----|----|----|-----------|--------|----|
| C2 | dnscat2 | ? | ? | ? | ? | ? | ? | ? |
| Exfil | DNSExfiltrator | ? | ? | ? | ? | ? | ? | ? |
| IP-over-DNS | iodine | ? | ? | ? | ? | ? | ? | ? |
| Combined | all | ? | ? | ? | ? | ? | ? | ? |

---

## 4. Сравнение с другими инструментами

### 4.1 eBPF-based (прямые конкуренты)

| Инструмент | Тип | DNS tunnel detection | Плюсы | Минусы | Как сравнить |
|------------|-----|---------------------|-------|--------|--------------|
| **Cilium Tetragon** | eBPF security observability | Нет встроенного DNS tunnel detection; есть DNS visibility (TracingPolicy) | Production-ready, мощный policy engine, перехват syscalls | Нужно писать свои правила для tunnel detection; тяжёлый | Деплой рядом, сравнить: (1) overhead CPU/memory, (2) можно ли воспроизвести детекцию через TracingPolicy |
| **Falco** | eBPF/module runtime security | Нет DNS tunnel detection; есть правила на syscalls, file access | Широкое community, rich rule language | DNS detection потребует custom plugin; overhead выше | Деплой рядом, сравнить overhead; показать что ваш модуль закрывает gap |
| **Pixie (px.dev)** | eBPF full-stack observability | DNS monitoring (протокол трassировка), нет tunnel detection | Авто-трassировка без инструментации | Проект заморожен (New Relic); нет детекции аномалий | Теоретическое сравнение |

### 4.2 Network-based (классические IDS/NSM)

| Инструмент | Тип | DNS tunnel detection | Как сравнить |
|------------|-----|---------------------|--------------|
| **Zeek (Bro)** | Network Security Monitor | Есть скрипты для DNS anomaly (entropy, frequency, length); community scripts для tunnel detection | Деплой в том же кластере (mirror traffic), прогнать те же tunnel tools, сравнить TP/FP |
| **Suricata** | IDS/IPS | Есть DNS rules (ET Open, OISF); сигнатурный подход + некоторая аналитика | Аналогично: деплой, те же тесты, сравнить |
| **Arkime (Moloch)** | Full packet capture | Нет встроенного detection, но полный PCAP для ретроспективного анализа | Использовать для ground truth (записать весь трафик, сверить с алертами монитора) |

### 4.3 Рекомендуемая матрица сравнения для ВКР

| Критерий | dns-tunnel-monitor (ваш) | Tetragon | Falco | Zeek | Suricata |
|----------|:------------------------:|:--------:|:-----:|:----:|:--------:|
| CNI-agnostic | ✓ | ✓ | ✓ | ✗ (нужен mirror) | ✗ (нужен mirror) |
| Не требует привилегированного CNI | ✓ | ✓ | ✓ | ✓ | ✓ |
| DNS tunnel detection из коробки | ✓ | ✗ | ✗ | Частично | Частично |
| Атрибуция до пода (pod name) | ✓ (cgroup) | ✓ (cgroup) | ✓ (cgroup) | ✗ | ✗ |
| Prometheus метрики | ✓ | ✓ | ✓ | Через exporter | Через exporter |
| Overhead (CPU) | Низкий (BPF cgroup_skb) | Средний | Средний | Высокий | Высокий |
| Overhead (Memory) | Низкий* (с фиксами) | Средний | Средний | Высокий (буферы) | Высокий |
| Зрелость / production-ready | PoC | Production | Production | Production | Production |

**Ключевой аргумент для ВКР:** ваш модуль — единственный, который совмещает (1) CNI-agnostic eBPF подход, (2) атрибуцию до пода через cgroups, и (3) DNS tunnel detection в одном лёгком DaemonSet. Tetragon/Falco дают visibility, но не detection. Zeek/Suricata дают detection, но не pod attribution и требуют mirror.

---

## 5. ML как дополнительный сервис детекции

### 5.1 Зачем

Текущие детекторы — rule-based (пороги, regex, CV). Их сильная сторона — интерпретируемость и скорость. Слабая — ручная настройка порогов, неспособность адаптироваться к новым паттернам. ML-модель может:

- Ловить паттерны, которые эвристики пропускают (novel tunneling techniques)
- Адаптироваться к конкретному кластеру (baseline learning)
- Снизить FP за счёт учёта комбинаций признаков

### 5.2 Готовые решения и модели

| Решение | Тип | Применимость |
|---------|-----|-------------|
| **Статьи с открытым кодом** | | |
| Nadler et al. 2019 «Detection of Malicious DNS over HTTPS» | Random Forest на lexical features | Feature extraction переносим; модель нужно дообучить |
| Homem et al. 2018 «Entropy-based DNS tunnel detection» | Ensemble (RF + SVM) | Близко к вашему подходу, расширяет энтропийный анализ |
| Ahmed et al. 2019 «Real-time DNS exfiltration detection» | XGBoost на 15 features | Хороший feature set, переносим |
| **Фреймворки** | | |
| scikit-learn (RF/XGBoost) | Классический ML | Легко обучить и задеплоить |
| ONNX Runtime | Inference engine | Лёгкий inference в отдельном контейнере |
| BentoML / MLflow | ML serving | Production-ready serving из коробки |
| **Коммерческие (для сравнения в тексте ВКР)** | | |
| Cisco Umbrella | DNS Security with ML | Облачный, не self-hosted |
| Infoblox BloxOne | DNS Firewall + ML | Enterprise, не open-source |
| Azure Sentinel DNS Analytics | Cloud SIEM + ML | Azure-only |

### 5.3 Архитектура интеграции

```
┌─────────────────────────────────────────────────────┐
│                 Kubernetes Node                      │
│                                                     │
│  ┌───────────────────────────────────┐              │
│  │  dns-tunnel-monitor (DaemonSet)   │              │
│  │                                   │              │
│  │  BPF → Parser → Feature Extract ──┼─── REST/gRPC │
│  │         │                         │      │       │
│  │    Rule-based detectors           │      │       │
│  │    (C2, Exfil, IP-over-DNS)       │      │       │
│  │         │                         │      │       │
│  │    Score aggregator ◄─────────────┼──────┘       │
│  │         │                         │   ML score   │
│  │    Final decision + metrics       │              │
│  └───────────────────────────────────┘              │
│                                                     │
└──────────────────────┬──────────────────────────────┘
                       │ REST/gRPC
                       ▼
          ┌────────────────────────┐
          │  ml-dns-scorer         │
          │  (Deployment, 1-3 pod) │
          │                        │
          │  FastAPI + scikit-learn │
          │  или ONNX Runtime      │
          │                        │
          │  GET /predict           │
          │  Body: feature vector   │
          │  Response: {score: 0.87,│
          │   label: "tunnel"}      │
          └────────────────────────┘
```

### 5.4 Feature-вектор для ML-модели

На основе литературы (Nadler, Ahmed, Homem), рекомендуемые features:

| # | Feature | Источник | Уже есть |
|---|---------|----------|:--------:|
| 1 | Shannon entropy домена | calculate_entropy | ✓ |
| 2 | Длина домена (chars) | len(domain) | ✓ |
| 3 | Число поддоменов (labels) | domain.split('.') | ✓ |
| 4 | Длина наибольшего label | max(len(l) for l in labels) | ✗ |
| 5 | Доля цифр | digit_ratio | ✓ |
| 6 | Доля согласных | consonant_ratio | ✗ |
| 7 | DNS record type (one-hot) | dns_type | ✓ |
| 8 | Query rate (per cgroup per domain) | rate | Частично |
| 9 | N-gram frequency score (bigram/trigram) | сравнение с моделью английского | ✗ |
| 10 | Средняя длина label | avg label length | ✗ |
| 11 | Наличие спецсимволов (-/_) | regex | ✗ |
| 12 | Число уникальных символов | len(set(domain)) | ✗ |
| 13 | Является ли домен cluster-internal | .svc.cluster.local check | ✗ |
| 14 | Interval CV (beacon regularity) | cv from c2 detector | ✓ |
| 15 | dns_answers count | dns_answers | ✓ |

### 5.5 Минимальный ML pipeline для ВКР

```
1. Собрать labeled dataset:
   - Легитимный трафик кластера (label=0)
   - Трафик от iodine/dnscat2/dns2tcp (label=1)

2. Extract features (15 features выше) → CSV/Parquet

3. Обучить Random Forest (scikit-learn):
   - train/test split 80/20
   - cross-validation 5-fold
   - метрики: Precision, Recall, F1, ROC-AUC

4. Экспорт модели: joblib → ONNX

5. Деплой: FastAPI pod с /predict endpoint

6. Интеграция: dns-tunnel-monitor отправляет feature vector,
   получает score, использует в score aggregator наряду
   с rule-based детекторами
```

### 5.6 Интеграция — отдельный Deployment (не sidecar)

**Почему Deployment, а не sidecar:**
- ML-модель одна на кластер (stateless, одинаковая на всех нодах)
- DaemonSet уже привилегированный и тяжёлый (BPF, hostPID)
- Отдельный Deployment позволяет независимо скалить/обновлять модель
- Graceful degradation: если ML pod недоступен, rule-based детекторы продолжают работать

**Helm values расширение:**
```yaml
mlScorer:
  enabled: false           # по умолчанию выключен
  image: ml-dns-scorer:v1
  replicas: 1
  port: 8080
  resources:
    limits:
      memory: 256Mi
      cpu: 200m
```

---

## 6. Полный план работ (roadmap)

### Фаза 1: Исправление критических багов (8-10 часов)

| Задача | Файлы | Оценка |
|--------|-------|--------|
| BUG-02: Увеличить PAYLOAD_SAMPLE до 196 | bpf/dns_cgroup.bpf.c, event_struct.py | 1ч |
| BUG-14: Поменять порядок hex/base64 | detectors/exfil.py | 10мин |
| BUG-19: Per-key first_seen для rate | detectors/ip_over_dns.py | 30мин |
| BUG-18: Per-key sliding window | detectors/ip_over_dns.py | 30мин |
| BUG-03: QR-бит вместо egress/ingress | loader.py | 15мин |
| ISSUE-12 + K8S: Whitelist cluster DNS + расширить TXT | detectors/c2.py, config.py | 30мин |
| BUG-15: Энтропия только по поддомену | detectors/exfil.py | 20мин |
| Memory fixes (BUG-11, 16, 26): TTL/LRU | c2.py, exfil.py, pod_resolver.py | 2-3ч |
| ISSUE-22: Базовый scoring (weighted sum) | detectors/tunnel.py | 1-2ч |
| Обновить документацию (DETECTION_ALGORITHMS.md) | docs/ | 1ч |
| (Опционально) Передавать полный `event` в `tunnel_detector.analyze()` вместо урезанного `event_data` — единый контракт для детекторов | event_handler.py | 30мин |

### Фаза 2: Тестирование (5-8 часов)

| Задача | Оценка |
|--------|--------|
| Unit-тесты детекторов (мок-события) | 3ч |
| Unit-тесты dns_parsing | 1ч |
| Интеграционный тест: end-to-end pipeline с мок-данными | 2ч |
| CI (GitHub Actions): запуск тестов на push | 1ч |

### Фаза 3: Валидация TP/FP на реальном кластере (8-12 часов)

| Задача | Оценка |
|--------|--------|
| Развернуть тестовый кластер (kind / minikube) | 1ч |
| Деплой iodine server + client в подах | 2ч |
| Деплой dnscat2 server + client | 2ч |
| Деплой dns2tcp / DNSExfiltrator | 1ч |
| Генерация легитимного трафика (dnsperf + curl-pods) | 1ч |
| Сбор данных, confusion matrix, метрики | 2ч |
| Тюнинг порогов на основе результатов | 1-2ч |

### Фаза 4: Сравнение с инструментами (4-6 часов)

| Задача | Оценка |
|--------|--------|
| Деплой Tetragon рядом, замер overhead | 2ч |
| Деплой Zeek/Suricata, прогон тех же тестов | 2ч |
| Таблица сравнения для текста ВКР | 1ч |

### Фаза 5 (опционально): ML scorer (10-15 часов)

| Задача | Оценка |
|--------|--------|
| Feature extraction модуль (15 features) | 2ч |
| Сбор labeled dataset из фазы 3 | 1ч |
| Обучение RF/XGBoost, валидация | 3ч |
| FastAPI pod с /predict | 2ч |
| Helm chart для ml-scorer | 1ч |
| Интеграция в tunnel.py (async call + fallback) | 2ч |
| Сравнение: rule-only vs rule+ML (F1 delta) | 2ч |

### Итого

| Фаза | Часы | Необходимость |
|-------|:----:|:-------------:|
| 1. Critical fixes | 8-10 | Обязательно |
| 2. Тесты | 5-8 | Обязательно |
| 3. Валидация TP/FP | 8-12 | Обязательно |
| 4. Сравнение | 4-6 | Очень желательно |
| 5. ML scorer | 10-15 | Опционально (сильно усилит ВКР) |
| **Итого** | **35-51** | |

---

## 7. Что сделает ВКР более крепкой

### Обязательно для защиты

1. **Таблицы TP/FP/Precision/Recall** по каждому детектору на реальных tunnel tools — это основа «экспериментальной части»
2. **Сравнение overhead** (CPU/mem) с Tetragon/Falco — доказательство что ваш подход легче
3. **Раздел «ограничения»** — честно описать UDP-only, payload truncation, эвристические пороги
4. **Архитектурная диаграмма** — BPF → userspace → detectors → metrics → Grafana с атрибуцией cgroup → pod

### Сильно усилит

5. **ML как дополнительный слой** — показать delta F1 (rule-only vs rule+ML)
6. **N-gram frequency analysis** — ещё один feature в exfil-детекторе, ссылка на Nadler et al.
7. **ROC-кривые** для каждого детектора при разных порогах — наглядно показывает trade-off sensitivity vs specificity
8. **Тестирование на нескольких CNI** (Calico, Flannel, Cilium) — доказать «CNI-agnostic» из темы ВКР

### Бонус (если время есть)

9. **TCP DNS support** — второй BPF hook для TCP/53
10. **Real-time Grafana dashboard** со скриншотами для презентации
11. **Alertmanager integration** — webhook на Slack/Telegram при срабатывании
