# Как выяснить причину `<unparseable>`

События с `domain="<unparseable>"` возникают, когда из 64 байт payload не удаётся извлечь доменное имя (парсер возвращает пусто). Возможные причины:

| Причина | Как проявляется |
|--------|------------------|
| **IPv6** | Мы читаем payload с offset 28 (под IPv4). У IPv6 заголовок 40 байт → DNS с offset 48. С 28 читаем мусор → парсер не находит валидных labels. **Важно:** в текущем BPF протокол проверяется по offset 9 (IPv4); у IPv6 «next header» на offset 6, поэтому IPv6-пакеты отбрасываются в BPF и вообще не попадают в userspace — событий по IPv6 не будет, пока BPF не доработан. |
| **Короткий linear skb** | Редко для DNS over UDP; при прямом доступе мы и так отбрасываем пакет в BPF, если `data + 92 > data_end`. |
| **Парсер (Python)** | Валидный DNS, но compression pointer, длина label или граница буфера — парсер возвращает пусто. |

## Что добавлено для диагностики

1. **В BPF** в каждое событие пишется **IP-версия** пакета: первый байт пакета, верхние 4 бита (`4` или `6`). Поле `ip_version` в событии.
2. **В userspace** при `domain == "<unparseable>"` в событие добавляется **образец payload** — hex первых 12 байт (DNS-заголовок, если бы это был DNS).

Так можно понять:
- **`ip_version=6`** → пакет IPv6, читали с неверного offset → причина именно IPv6.
- **`ip_version=4`** и в `payload_sample_hex` не похоже на DNS (не ID + flags + counts) → либо редкий артефакт, либо очень короткий/битый пакет.
- **`ip_version=4`** и hex похож на DNS (например `00 00 01 00 00 01 ...`) → парсер не смог извлечь имя (compression, длина, границы).

## Как использовать

### 1. Включить вывод по каждому unparseable (stderr)

```bash
DEBUG_UNPARSEABLE=1 python -m dns_tunnel_monitor
```

В stderr появятся строки вида:
```
[unparseable] ip_version=6 payload_hex(12)=60000000... pod=default/curl-xxx dir=query
[unparseable] ip_version=4 payload_hex(12)=a3f1010000010000... pod=attack/iodine-xxx dir=query
```

- **ip_version=6** — почти наверняка причина: IPv6, offset 28 неверный.
- **ip_version=4** — смотреть на hex: если первые 2 байта — ID, байты 2–3 — флаги (часто `01 00` для query, `81 80` для response), то это DNS и проблема в парсере.

### 2. Агрегация по логам (JSONL)

При сборе логов в JSON теперь есть поля `ip_version` и при unparseable — `payload_sample_hex`. Можно отфильтровать и посчитать:

```bash
# Только unparseable
grep '"domain": "<unparseable>"' results/baseline.jsonl > unparseable.jsonl

# Сколько по ip_version (jq)
cat unparseable.jsonl | jq -r '.ip_version' | sort | uniq -c

# Примеры payload_hex для ip_version=6 и ip_version=4
cat unparseable.jsonl | jq -r 'select(.ip_version==6) | .payload_sample_hex' | sort -u | head -20
cat unparseable.jsonl | jq -r 'select(.ip_version==4) | .payload_sample_hex' | sort -u | head -20
```

Если большинство unparseable с **ip_version=6** — основная причина в IPv6 и нужна поддержка offset 48 в BPF. Если много **ip_version=4** — разбирать конкретные hex (формат DNS, compression) и при необходимости дорабатывать парсер. На локальной VM с текущим BPF IPv6-трафик не виден (отбрасывается по proto); для воспроизведения unparseable используйте тестер с `--sizes truncated` (см. `scripts/dns_query_tester.py`).

### 3. Интерпретация payload_sample_hex (12 байт)

- Байты 0–1: DNS ID (любые).
- Байты 2–3: флаги (query: часто `01 00` или `00 00`; response: `81 80` и т.п.).
- Байты 4–5: QDCOUNT (число вопросов), байты 6–7: ANCOUNT (ответов), 8–9: NSCOUNT, 10–11: ARCOUNT.

Если с байта 12 идёт длина label (1 байт) + метка, то это похоже на DNS и парсер мог отвалиться на сжатии или длине. Если 12 байт выглядят как заголовок IPv6 (`60 00 00 00...`) или мусор — это не DNS с нашего offset, т.е. IPv6 или артефакт.
