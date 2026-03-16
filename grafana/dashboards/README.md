# Дашборды Grafana

## DNS Tunnel Monitor

Файл **`dns-tunnel-monitor.json`** — дашборд по метрикам DNS Tunnel Monitor (Prometheus).

### Импорт в Grafana

1. **Dashboards** → **New** → **Import** (или **Import dashboard**).
2. Нажмите **Upload JSON file** и выберите `dns-tunnel-monitor.json`, либо вставьте его содержимое в поле **Import via panel json**.
3. Выберите **Prometheus** в качестве источника данных (или тот, откуда скрейпятся метрики `dns_*`).
4. Нажмите **Import**.

Вверху дашборда есть переменная **Data source** — при необходимости можно переключить источник данных.

### Панели

| Панель | Метрика | Описание |
|--------|--------|----------|
| DNS queries (total) | `sum(dns_queries_total)` | Всего DNS-запросов |
| DNS responses (total) | `sum(dns_responses_total)` | Всего ответов |
| Suspicious DNS (total) | `sum(dns_suspicious_total)` | Всего подозрительных событий |
| Unique domains | `dns_domains_unique` | Число уникальных доменов |
| DNS query rate by instance | `rate(dns_queries_total[5m])` by instance | Запросы в секунду по нодам |
| Suspicious DNS rate by threat type | `rate(dns_suspicious_total[5m])` by threat_type | Подозрительный трафик по типу (C2, EXFIL, TUNNEL) |
| Unique domains over time | `dns_domains_unique` | Уникальные домены во времени |
| Top 10 pods by DNS event rate | `rate(dns_events_by_pod[5m])` by client_pod | Топ подов по активности |
| Suspicious total by threat type | `dns_suspicious_total` by threat_type | Накопленно по типам угроз |
