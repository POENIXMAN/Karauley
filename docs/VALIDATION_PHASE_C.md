# Результаты Phase C (смешанный трафик)

Результаты одного прогона по плану тестирования: сбор логов DNS Tunnel Monitor в течение 10 минут при одновременной работе baseline-трафика и атак (iodine, dnscat2, DNSExfiltrator).

---

## Параметры сбора

- **Метка:** phase_C  
- **Длительность:** 10 мин  
- **Выходной файл:** `k8s/tests/results/phase_C.jsonl`  
- **DaemonSet:** default/dns-tunnel-monitor  
- **Поды:** 3 (worker1, k8s-master, worker2)  
- **Всего событий:** 437 343  
- **Suspicious:** 12 544  
- **Clean:** 424 799  

---

## Анализ 1: порог по умолчанию (suspicious из лога), GT по поду

```
Events: 437343  (parse errors: 0)

Confusion Matrix
               Suspicious    Clean
Attack (GT)    TP=5656       FN=641
Legit (GT)     FP=6888       TN=424158

Precision:  0.4509
Recall:     0.8982
F1:         0.6004
FPR:        0.015980 (1.598%)
```

- **FN:** 641 — все по домену `<unparseable>` (обрезанный payload / IPv6).  
- **FP:** при GT по поду много транзитного трафика через легитимные поды (в т.ч. CoreDNS).

---

## Анализ 2: threshold=3, GT по домену *.evil.lan

```
--gt-by-domain --threshold 3 --attack-domain evil.lan
```

- TP=0, FN=0 (атакующих доменов *.evil.lan в сценарии нет).  
- FP=12282, TN=425061, FPR ≈ 2.81%.  

Используется для проверки, что при несовпадении суффикса атаки с разметкой метрики ведут себя ожидаемо.

---

## Анализ 3: threshold=3, GT по домену *.attack.test (рекомендуемая методология)

```
python3 analyze.py results/phase_C.jsonl --gt-by-domain --threshold 3
```

```
Events: 437343  (parse errors: 0)

Confusion Matrix
               Suspicious    Clean
Attack (GT)    TP=11698      FN=0
Legit (GT)     FP=584        TN=425061

Precision:  0.9525
Recall:     1.0000
F1:         0.9756
FPR:        0.001372 (0.137%)

Score mean (TP): 4.80
Score mean (FP): 3.00
```

**Топ FP домены:** x.com, raw.githubusercontent.com, gitlab.com, stackoverflow.com, login.microsoftonline.com, office.com, outlook.com, bing.com, apple.com, icloud.com (по 10–11 событий).

**Детекторы (TP):** MANY_SUBDOMAINS(50), HEX_SUBDOMAIN, NULL_RECORD(iodine), BASE64_SUBDOMAIN, C2_TXT_REQUEST, HIGH_ENTROPY, HIGH_DIGIT_RATIO, LONG_DOMAIN.

**Threat types (TP):** EXFIL 5429, EXFIL+TUNNEL 4673, C2+EXFIL 1596.

---

## Выводы

1. При **GT по домену** (`*.attack.test`) и **threshold=3** метрики сильные: Precision ≈ 0.95, Recall = 1.0, F1 ≈ 0.98, FPR ≈ 0.14%.  
2. **FN=0** для распознанных доменов атаки; оставшиеся пропуски при GT по поду — только `<unparseable>`.  
3. **FP** при th=3 — в основном легитимные «шумные» домены с score=3; при необходимости их можно вынести в whitelist (документировать в ВКР как тюнинг).  
4. Для воспроизводимости в отчёте следует зафиксировать: **--gt-by-domain**, **--threshold 3**, суффикс атакующего домена **attack.test**.

Детальная интерпретация артефактов, ограничений и рекомендаций — в `docs_old/VALIDATION_FINDINGS.md`.
