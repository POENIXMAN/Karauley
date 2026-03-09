# План тестирования детекторов DNS Tunnel Monitor

Дата: 2026-03-03  
Версия: 2.0

---

## 1. Цель и критерии успеха

**Цель:** объективно измерить качество детекции (TP/FP/FN) каждого детектора и combined-скоринга на известном ground truth в трёх режимах нагрузки.

**Три фазы тестирования:**

| Фаза | Трафик | Что проверяем |
|-------|--------|---------------|
| **A — Чистый** | Только легитимный | FP: сколько ложных алертов на «нормальном» трафике |
| **B — Грязный** | Только атака (по одному tool) | TP/FN: ловит ли детектор туннель без «шума» |
| **C — Смешанный** | Легитимный + атака одновременно | Реалистичный режим: не пропускает ли атаку на фоне шума, не пугается ли легитимного |

Фаза C — ключевая: если в фазе B детектор ловит атаку, но в фазе C пропускает (FN растёт) или начинает маркировать легитимный трафик (FP растёт) — это проблема.

**Критерии успеха:**

| Метрика | Целевое значение | Комментарий |
|---------|-----------------|-------------|
| Precision (фаза C) | ≥ 0.85 | Алерты преимущественно верные |
| Recall (фаза C) | ≥ 0.80 | Ловим большинство атак |
| F1 (фаза C) | ≥ 0.82 | Баланс |
| FP rate (фаза A) | < 1% от общего числа событий | Минимум ложных |
| Latency (детекция) | < 60 с от начала атаки до первого алерта | Скорость реакции |

---

## 2. Архитектура сбора данных

### 2.1 Structured JSON logging (реализовано в коде)

Каждое DNS-событие пишется в **stderr** в формате JSON:

```json
{
  "ts": 1709472000000000000,
  "domain": "aGVsbG8.evil.com",
  "direction": "query",
  "dns_type": 1,
  "pod": "default/curl-pod",
  "process": "curl",
  "suspicious": true,
  "score": 4,
  "threat_type": "EXFIL",
  "reasons": ["HIGH_ENTROPY(4.32)", "BASE64_SUBDOMAIN"]
}
```

Поле `score` — числовая оценка от scoring-системы (порог = 2). Это позволяет:
- Строить confusion matrix автоматически (парсинг JSON → фильтр по `suspicious`)
- Анализировать распределение score для тюнинга порога
- Сопоставлять ground truth label с вердиктом

### 2.2 Ground truth labeling

Каждое событие получает label **по принадлежности пода**:

| Label | Как определяем | Примеры |
|-------|----------------|---------|
| `legit` | Pod из baseline-namespace или известный легитимный Pod | `default/curl-pod`, `default/dnsperf-job` |
| `attack:<tool>` | Pod из attack-namespace, имя содержит tool | `attack/iodine-client`, `attack/dnscat2-client` |

**Правило:** каждый attack tool деплоится в namespace `attack` (или `attack-<tool>`). Все остальные поды — легитимные. Это делает labeling тривиальным: `pod.startswith("attack/")` → attack, иначе → legit.

### 2.3 Confusion matrix — определения

| | Детектор: suspicious=true | Детектор: suspicious=false |
|---|---|---|
| **Label: attack** | **TP** (верно поймал) | **FN** (пропустил) |
| **Label: legit** | **FP** (ложный алерт) | **TN** (верно пропустил) |

Считается **по событиям** (каждая строка JSON-лога = одно событие).

---

## 3. Инструменты

### 3.1 Кластер и инфраструктура

| Компонент | Назначение |
|-----------|------------|
| **kind / minikube** (1–3 ноды) | Тестовый кластер |
| **Helm** | Деплой dns-tunnel-monitor (DaemonSet) + тестовых workloads |
| **Prometheus** | Сбор метрик `/metrics` (scrape 15 с) |
| **kubectl logs** | Сбор structured JSON из stderr DaemonSet-пода |

### 3.2 Генерация легитимного трафика

| Инструмент | Namespace | Что генерирует |
|------------|-----------|----------------|
| **dnsperf** | `default` | Массовые A/AAAA запросы к списку из 1000+ реальных доменов |
| **curl/wget pods** | `default` | HTTP-запросы → DNS lookup (google.com, github.com, cdn-ы) |
| **K8s Jobs** | `default` | Service discovery (`svc.cluster.local`), headless services, `ndots` |
| **TXT-генератор** | `default` | Легитимные TXT-запросы: SPF, DKIM, DMARC, `_acme-challenge` |

TXT-генератор важен: без него мы не проверим, что TXT-whitelist работает и `C2_TXT_REQUEST` не стреляет на легитимных TXT.

### 3.3 Tunnel tools (attack ground truth)

| Tool | Тип атаки | Namespace | Что проверяем |
|------|-----------|-----------|---------------|
| **iodine** | IP-over-DNS | `attack` | `HIGH_RATE`, `NULL_RECORD`, `MANY_ANSWERS` |
| **dnscat2** | C2 over DNS | `attack` | `C2_BEACON`, `C2_TXT_REQUEST`, `HIGH_ENTROPY` |
| **DNSExfiltrator** | Data exfil | `attack` | `BASE64_SUBDOMAIN`, `MANY_SUBDOMAINS`, `HIGH_ENTROPY` |
| **dns2tcp** (опц.) | TCP-over-DNS | `attack` | `HIGH_ENTROPY`, encoded subdomains |

Для каждого tool — отдельный Helm values или manifest в `k8s/tests/`.

---

## 4. Три фазы тестирования

### Фаза A: Чистый трафик (baseline)

```
┌──────────────────────────────────────────────────────────────┐
│  Только легитимный трафик │ 10 мин │ namespace: default      │
│                                                              │
│  dnsperf ──→ DNS ←── curl pods ←── K8s jobs ←── TXT queries │
│                          ↓                                   │
│              dns-tunnel-monitor (stderr → baseline.jsonl)     │
└──────────────────────────────────────────────────────────────┘
```

**Длительность:** 10 минут (даёт ~100k+ событий для статистической значимости).

**Шаги:**
1. Кластер поднят, dns-tunnel-monitor задеплоен.
2. Запустить легитимные workloads в `default`.
3. Собирать stderr монитора: `kubectl logs -f ds/dns-tunnel-monitor -c monitor 2>baseline.jsonl`.
4. Через 10 мин остановить генераторы, сохранить `baseline.jsonl` + snapshot метрик Prometheus.

**Ожидаемый результат:**
- Все события имеют label `legit`.
- `suspicious=true` → FP. Цель: < 1% событий.
- Список FP-доменов и reasons для тюнинга.

### Фаза B: Грязный трафик (только атака)

```
┌──────────────────────────────────────────────────────────────┐
│  Только один attack tool │ 10 мин │ namespace: attack        │
│                                                              │
│  iodine-client ──→ DNS ──→ iodine-server (внешний)          │
│                          ↓                                   │
│              dns-tunnel-monitor (stderr → attack_iodine.jsonl)│
└──────────────────────────────────────────────────────────────┘
```

**Длительность:** 10 минут на каждый tool.

**Шаги (для каждого tool):**
1. Убедиться, что легитимные workloads **остановлены** (или отфильтровать потом по namespace).
2. Деплой attack tool в namespace `attack`.
3. Прогрев 2 мин (установление туннеля/сессии).
4. Активный трафик 10 мин (передача данных, beacon, etc).
5. Остановить, сохранить `attack_<tool>.jsonl`.

**Ожидаемый результат:**
- Все события от `attack/*` пода.
- `suspicious=true` → TP. `suspicious=false` → FN.
- Recall должен быть высоким: если детектор не ловит атаку в чистом виде — проблема с порогами/логикой.

### Фаза C: Смешанный трафик (легитимный + атака)

```
┌──────────────────────────────────────────────────────────────────┐
│  Легитимный (default) + Атака (attack) одновременно │ 10 мин    │
│                                                                  │
│  dnsperf ──→ DNS ←── curl ←── K8s jobs     (namespace: default) │
│  iodine ──→  DNS ──→ iodine-server          (namespace: attack) │
│                          ↓                                       │
│              dns-tunnel-monitor (stderr → mixed_iodine.jsonl)    │
└──────────────────────────────────────────────────────────────────┘
```

**Длительность:** 10 минут на каждый tool.

**Шаги (для каждого tool):**
1. Запустить легитимные workloads в `default`.
2. Деплой attack tool в namespace `attack`.
3. Прогрев 2 мин, затем 10 мин одновременной нагрузки.
4. Остановить, сохранить `mixed_<tool>.jsonl`.

**Ожидаемый результат:**
- События от `default/*` → label `legit`.
- События от `attack/*` → label `attack:<tool>`.
- TP, FP, FN, TN считаются из этого файла.
- **Ключевая проверка**: Recall не упал по сравнению с фазой B? FP не вырос по сравнению с фазой A?

---

## 5. Матрица тестов (полная)

| # | Фаза | Tool | Файл лога | Что извлекаем |
|---|-------|------|-----------|---------------|
| 1 | A (чистый) | — | `baseline.jsonl` | FP, TN, FP rate, FP-домены |
| 2 | B (грязный) | iodine | `attack_iodine.jsonl` | TP, FN, Recall |
| 3 | B (грязный) | dnscat2 | `attack_dnscat2.jsonl` | TP, FN, Recall |
| 4 | B (грязный) | DNSExfiltrator | `attack_exfil.jsonl` | TP, FN, Recall |
| 5 | C (смешанный) | iodine | `mixed_iodine.jsonl` | TP, FP, FN, TN, Precision, Recall, F1 |
| 6 | C (смешанный) | dnscat2 | `mixed_dnscat2.jsonl` | TP, FP, FN, TN, Precision, Recall, F1 |
| 7 | C (смешанный) | DNSExfiltrator | `mixed_exfil.jsonl` | TP, FP, FN, TN, Precision, Recall, F1 |

Итого: 7 прогонов × 10 мин ≈ 70 мин чистого тестового времени + прогревы.

---

## 6. Скрипт анализа (`analyze.py`)

Автоматический парсинг JSONL-логов и расчёт метрик.

### 6.1 Алгоритм

```python
import json, sys
from collections import Counter

def analyze(jsonl_path, attack_namespace="attack"):
    tp = fp = fn = tn = 0
    fp_domains = Counter()
    fn_domains = Counter()
    score_dist = {"tp": [], "fp": [], "tn": [], "fn": []}

    for line in open(jsonl_path):
        ev = json.loads(line)
        is_attack = ev["pod"].startswith(f"{attack_namespace}/")
        is_suspicious = ev["suspicious"]
        score = ev["score"]

        if is_attack and is_suspicious:
            tp += 1; score_dist["tp"].append(score)
        elif is_attack and not is_suspicious:
            fn += 1; score_dist["fn"].append(score)
            fn_domains[ev["domain"]] += 1
        elif not is_attack and is_suspicious:
            fp += 1; score_dist["fp"].append(score)
            fp_domains[ev["domain"]] += 1
        else:
            tn += 1; score_dist["tn"].append(score)

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "fp_domains": fp_domains.most_common(20),
        "fn_domains": fn_domains.most_common(20),
        "score_dist": score_dist,
    }
```

### 6.2 Дополнительные вычисления

- **Score distribution** по категориям (TP/FP/FN/TN) → гистограмма. Позволяет понять, нужно ли сдвинуть `SCORE_THRESHOLD`.
- **Per-detector breakdown**: из поля `reasons` извлечь, какие причины сработали → таблица «причина × tool → частота». Показывает, какой именно детектор ловит какой tool.
- **Detection latency**: время от первого события `attack/*` до первого `suspicious=true` от того же пода.
- **Threat type accuracy**: сравнить `threat_type` с ожидаемым (iodine → TUNNEL, dnscat2 → C2, DNSExfiltrator → EXFIL).

---

## 7. Формулы и метрики

| Метрика | Формула | Когда считаем |
|---------|---------|---------------|
| **Precision** | TP / (TP + FP) | Фазы B, C |
| **Recall (TPR)** | TP / (TP + FN) | Фазы B, C |
| **F1** | 2 × Precision × Recall / (Precision + Recall) | Фазы B, C |
| **FPR** | FP / (FP + TN) | Фазы A, C |
| **Detection Latency** | t(first alert) − t(first attack event) | Фазы B, C |
| **Score mean (TP)** | avg(score) для TP-событий | Все |
| **Score mean (FP)** | avg(score) для FP-событий | Все |

Сравнение **фаза B vs фаза C** для каждого tool:

| Сравнение | Что значит |
|-----------|------------|
| Recall(B) > Recall(C) | Легитимный шум мешает детекции — проблема |
| Recall(B) ≈ Recall(C) | Детектор устойчив к шуму — хорошо |
| FPR(A) ≈ FPR(C) | FP не растёт от присутствия атаки рядом — хорошо |
| FPR(A) < FPR(C) | Атака «заражает» соседние события — проблема |

---

## 8. Итоговая таблица для ВКР

Результат всех прогонов сводится в таблицу:

| Tool | Фаза | Events | TP | FP | FN | TN | Precision | Recall | F1 | FPR | Latency |
|------|-------|--------|----|----|----|-----|-----------|--------|----|-----|---------|
| — | A (чистый) | N | 0 | ? | 0 | ? | — | — | — | ? | — |
| iodine | B (грязный) | N | ? | 0 | ? | 0 | 1.0 | ? | ? | 0 | ? s |
| iodine | C (смешанный) | N | ? | ? | ? | ? | ? | ? | ? | ? | ? s |
| dnscat2 | B (грязный) | N | ? | 0 | ? | 0 | 1.0 | ? | ? | 0 | ? s |
| dnscat2 | C (смешанный) | N | ? | ? | ? | ? | ? | ? | ? | ? | ? s |
| DNSExfiltrator | B (грязный) | N | ? | 0 | ? | 0 | 1.0 | ? | ? | 0 | ? s |
| DNSExfiltrator | C (смешанный) | N | ? | ? | ? | ? | ? | ? | ? | ? | ? s |

Эта таблица — центральный артефакт раздела «Экспериментальная оценка» ВКР.

---

## 9. Артефакты тестирования

| Артефакт | Формат | Содержимое |
|----------|--------|------------|
| `baseline.jsonl` | JSONL | Все события фазы A |
| `attack_<tool>.jsonl` | JSONL | Все события фазы B для tool |
| `mixed_<tool>.jsonl` | JSONL | Все события фазы C для tool |
| `results/<tool>_confusion.json` | JSON | TP/FP/FN/TN + метрики |
| `results/<tool>_fp_domains.csv` | CSV | Домены с ложными алертами |
| `results/<tool>_fn_domains.csv` | CSV | Домены с пропущенными атаками |
| `results/<tool>_score_dist.json` | JSON | Распределение score по категориям |
| `results/summary_table.md` | Markdown | Итоговая таблица (раздел 8) |
| `results/reason_heatmap.csv` | CSV | Причина × tool → частота срабатывания |
| `metrics_snapshots/` | JSON | Prometheus snapshots после каждой фазы |

---

## 10. Порядок работ

### Этап 1: Подготовка (1–2 дня)

1. Поднять кластер (kind/minikube), задеплоить dns-tunnel-monitor через Helm.
2. Подготовить манифесты для легитимных workloads:
   - `dnsperf` Job с файлом 1000+ доменов
   - `curl-loop` Deployment (curl к популярным сайтам каждые 2 с)
   - `k8s-discovery` Job (nslookup сервисов, headless, SRV)
   - `txt-queries` Job (dig TXT для SPF/DKIM/DMARC/ACME доменов)
3. Подготовить манифесты attack tools в namespace `attack`:
   - `iodine`: client Pod + внешний DNS server (или Pod)
   - `dnscat2`: client Pod + server
   - `DNSExfiltrator`: Python Pod + server
4. Написать `analyze.py` для парсинга JSONL и расчёта метрик.
5. Написать shell-скрипт `run_test.sh` для автоматизации прогонов.

### Этап 2: Фаза A — Baseline (30 мин)

1. Запустить легитимные workloads.
2. Собирать `baseline.jsonl` 10 мин.
3. Запустить `analyze.py baseline.jsonl` → FP rate, список FP-доменов.
4. Если FP > 1%: тюнинг (whitelist, пороги), повторить.

### Этап 3: Фаза B — Грязный трафик (1–2 часа)

Для каждого tool:
1. Остановить легитимные workloads (или деплоить в изолированном режиме).
2. Деплой attack tool → прогрев 2 мин → 10 мин активного трафика.
3. Собрать `attack_<tool>.jsonl`.
4. Запустить `analyze.py attack_<tool>.jsonl` → Recall, FN-домены.
5. Если Recall < 0.80: анализ FN, тюнинг детекторов, повторить.

### Этап 4: Фаза C — Смешанный трафик (1–2 часа)

Для каждого tool:
1. Запустить легитимные workloads + attack tool одновременно.
2. Собрать `mixed_<tool>.jsonl` за 10 мин.
3. Запустить `analyze.py mixed_<tool>.jsonl` → полная confusion matrix.
4. Сравнить Recall(B) vs Recall(C), FPR(A) vs FPR(C).

### Этап 5: Сводка и отчёт (1 день)

1. Заполнить итоговую таблицу (раздел 8).
2. Построить score distributions, reason heatmap.
3. Зафиксировать выводы: что работает, что нет, рекомендации по тюнингу.
4. Сохранить все артефакты в `results/`.

---

## 11. Чек-лист перед запуском

- [ ] dns-tunnel-monitor деплоится и пишет JSON в stderr
- [ ] Prometheus скрейпит `/metrics`
- [ ] Namespace `attack` создан, RBAC не мешает DNS-трафику
- [ ] Легитимные workloads генерируют разнообразный DNS (A, AAAA, TXT, SRV, CNAME)
- [ ] Каждый attack tool проверен вручную (туннель устанавливается, данные идут)
- [ ] `analyze.py` протестирован на синтетическом JSONL
- [ ] Достаточно дискового пространства для логов (~100MB на прогон)
- [ ] Время на каждый прогон: 10 мин трафик + 2 мин прогрев + 2 мин пауза
