# Provisioning алертов Grafana для DNS Tunnel Monitor

Каталог содержит конфигурации для **Grafana Alerting**: кастомные шаблоны уведомлений и правила алертов по метрикам DNS Tunnel Monitor. Contact point (Telegram) вы уже настроили; здесь — правила и формат сообщений.

## Что лежит в каталоге

| Файл | Назначение |
|------|------------|
| `message-templates.yaml` | Кастомные шаблоны для уведомлений (Telegram): `dns_telegram`, `dns_telegram_short`. |
| `alert-rules-dns-tunnel.yaml` | Группа правил алертов по метрикам `dns_suspicious_total` и др. |

## Подключение в Grafana

### 1. Смонтировать provisioning

Убедитесь, что Grafana загружает алерты из каталога provisioning. Обычно это:

- **Локально:** каталог `provisioning/alerting` в [директории данных Grafana](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/#data).
- **Helm (kube-prometheus-stack / grafana):** в `values` задаётся `sidecar` или `extraConfigmapMounts`, монтирующий этот каталог как `provisioning/alerting`.

Пример для своего деплоя: скопировать содержимое этого каталога в тот путь, откуда Grafana читает `provisioning/alerting`, затем перезапустить Grafana или выполнить [reload provisioning](https://grafana.com/docs/grafana/latest/developers/http_api/admin/#reload-provisioning-configurations).

### 2. Включить кастомный шаблон в Telegram contact point

1. **Alerting** → **Contact points** → выберите ваш Telegram contact point.
2. В блоке **Optional settings** найдите **Custom template**.
3. В выпадающем списке выберите шаблон **`dns_telegram`** (полный) или **`dns_telegram_short`** (короткий).
4. Сохраните.

После этого все алерты, приходящие на этот contact point, будут форматироваться выбранным шаблоном (статус, тип угрозы, pod, ссылка на Grafana).

### 3. Правила алертов

В `alert-rules-dns-tunnel.yaml` задана группа **DNS Tunnel Monitor** с правилом по приросту подозрительных DNS-событий.

**Важно:** в файле используется плейсхолдер **`PROMETHEUS_UID`**. Его нужно заменить на реальный UID источника данных Prometheus:

1. **Connections** → **Data sources** → Prometheus → откройте источник и скопируйте поле **UID**.
2. В `alert-rules-dns-tunnel.yaml` замените `PROMETHEUS_UID` на это значение.

Если после подстановки UID правило не подхватывается или выдаёт ошибку (формат `data` в Grafana может отличаться версией), удобный вариант:

1. В Grafana создайте правило вручную: **Alerting** → **Alert rules** → **New** → выберите Prometheus, запрос например `sum(increase(dns_suspicious_total[5m])) by (threat_type, instance)`, условие «last value > 0», укажите нужный contact point (Telegram).
2. **Export** этой группы правил (YAML).
3. Подставьте экспортированный фрагмент в `alert-rules-dns-tunnel.yaml` или замените файл целиком и при необходимости оставьте аннотации/лейблы из текущего примера.

### 4. Notification policy (куда слать алерты)

Чтобы алерты DNS Tunnel Monitor уходили именно в Telegram:

- Либо в **Notification policies** настройте маршрут по лейблу (например `component = dns-tunnel-monitor`) на ваш Telegram contact point.
- Либо при создании/редактировании правила в разделе **Contact point** укажите напрямую ваш Telegram contact point.

## Метрики для алертов

- `dns_suspicious_total{threat_type}` — подозрительные события по типу (C2, EXFIL, TUNNEL).
- `dns_events_by_pod{client_pod,direction}` — события по поду (для детализации в дашбордах).
- `dns_queries_total` — общее число запросов (при необходимости можно алертить на аномальный рост).

Лейблы `threat_type`, `instance` (и при необходимости `client_pod` из других метрик) доступны в шаблонах уведомлений как `{{ .Labels.threat_type }}`, `{{ .Labels.instance }}` и т.д.
