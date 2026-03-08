# Результаты Прогона 3 (2026-03)

## Контекст

После Прогона 2 (direct access BPF) были выявлены три проблемы:
1. **MANY_SUBDOMAINS на `cluster.local`** — все K8s сервисы группируются под base_domain=`cluster.local`, вызывая ~42K FP
2. **Проверка кодировки только в parts[0]** — пропускала chunked exfil типа `1.base64data.exfil.test`
3. **Порог кодировки > 20 символов** — пропускал 20-символьные base64 данные

## Сырые метрики (до фиксов)

### GT by pod (namespace)

| Threshold | TP | FN | FP | TN | Precision | Recall | FPR |
|-----------|------|-----|-------|--------|-----------|--------|-----|
| 2 | 5720 | 399 | 49049 | 469061 | 0.1044 | 0.9348 | 9.467% |

### GT by domain (`--gt-by-domain --attack-domain attack.test`)

| Threshold | TP | FN | FP | TN | Precision | Recall | F1 | FPR |
|-----------|-------|-----|-------|--------|-----------|--------|-------|------|
| 2 | 11837 | 0 | 42932 | 469460 | 0.2161 | **1.0000** | 0.3554 | 8.379% |
| **3** | **11477** | **360** | **20** | **512372** | **0.9983** | **0.9696** | **0.9837** | **0.004%** |

## Анализ проблем

### Проблема 1: MANY_SUBDOMAINS на cluster.local (~42K FP)

Детектор считает `base_domain = '.'.join(parts[-2:])` → для всего K8s DNS это `cluster.local`. Уникальные "subdomains":
- `kube-dns.svc` (от `kube-dns.svc.cluster.local`)
- `pod-0.headless-svc.default.svc` (от headless pod)
- `_dns._udp.kube-dns.kube-system.svc` (SRV records)
- ...и т.д.

Результат: >50 уникальных subdomains → `MANY_SUBDOMAINS(50)` → score=2 → FP на легитимном трафике.

**Top FP домены (th=2, GT by pod):**
```
kube-dns.svc.cluster.local                          3840
localhost.svc.cluster.local                         3840
pod-0.headless-svc.default.svc.cluster.local        3836
pod-1.headless-svc.default.svc.cluster.local        3836
kubernetes.svc.cluster.local                        3836
_dns-tcp._tcp.kube-dns.kube-system.svc.cluster.local 1918
```

### Проблема 2: Кодировка проверялась только в parts[0]

Exfil-домен `1.ldF90b2tlbl8xMjM0NQo.exfil.attack.test.lan`:
- `parts[0]` = `1` (chunk number) — не срабатывает
- `parts[1]` = `ldF90b2tlbl8xMjM0NQo` (base64 данные, 20 символов) — не проверялся!

### Проблема 3: Порог > 20 вместо >= 16

`ldF90b2tlbl8xMjM0NQo` = 20 символов. Порог `len > 20` требовал 21+. Результат: BASE64_SUBDOMAIN не срабатывал.

**Top FN домены (th=3, GT by domain):**
```
1.ldF90b2tlbl8xMjM0NQo.exfil.attack.test.lan        360
```

## Внесённые исправления

| Файл | Исправление |
|------|-------------|
| `config.py` | Добавлен `CLUSTER_BASE_DOMAINS = {"cluster.local", ...}` |
| `exfil.py` | Пропуск `MANY_SUBDOMAINS` для `base_domain in CLUSTER_BASE_DOMAINS` |
| `exfil.py` | Проверка кодировки во **всех** `parts[:-2]`, не только `parts[0]` |
| `exfil.py` | Порог кодировки снижен до `>= 16` символов |

## Ожидаемые улучшения после фиксов

| Метрика | До (th=2) | После (ожид.) | Изменение |
|---------|-----------|---------------|-----------|
| FP (GT by pod) | 49049 | ~78 | −99.8% |
| FN (GT by domain, th=3) | 360 | ~0 | −100% |
| Precision | 0.1044 | ~0.99 | +90% |
| Recall | 0.9348 | ~1.00 | +7% |

## Выводы

1. **Threshold=3 + GT by domain** даёт отличные метрики уже сейчас: **F1=0.984, FPR=0.004%**
2. **После фиксов** ожидается: **FN→0, FP→~0 при threshold=2**
3. **Требуется повторный прогон Phase C** для подтверждения

## Следующие шаги

1. ✅ Фикс MANY_SUBDOMAINS для cluster.local
2. ✅ Фикс проверки кодировки во всех поддоменах
3. ✅ Снижение порога кодировки до >= 16
4. ⏳ **Повторный прогон Phase C**
5. ⏳ **Обновление VALIDATION_FINDINGS.md с итоговыми метриками**
