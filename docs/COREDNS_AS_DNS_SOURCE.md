# CNI-агностичный источник DNS: CoreDNS вместо TC

## Проблема

При использовании **TC (Traffic Control)** мы не CNI-агностичны:

- На интерфейсе (например `ens33`) уже висит **clsact** и BPF от **Cilium** (или другого CNI).
- Ошибка: `tc qdisc clsact: Exclusivity flag on, cannot modify.`
- Наш TC-фильтр нельзя повесить рядом с фильтрами CNI на том же устройстве.

**Итог:** получать DNS payload через TC на host-интерфейсе в кластере с Cilium (и аналогами) нельзя без конфликта с CNI.

---

## Решение: CoreDNS как единственный источник доменов (CNI-агностично)

**CoreDNS** — стандартный DNS в Kubernetes. Весь кластерный DNS так или иначе идёт через него (напрямую или через NodeLocal DNSCache). CNI тут не участвует: это уровень kube-dns, не сетевого интерфейса.

Значит домены для детекции туннелей можно брать **из логов CoreDNS**, а не из eBPF/TC.

---

## 1. CoreDNS Log Plugin (официально)

- Документация: https://coredns.io/plugins/log/
- В Corefile добавляется `log` — все запросы пишутся в **stdout** в Common Log Format.

**Формат по умолчанию:**

```text
{remote}:{port} - {>id} "{type} {class} {name} {proto} {size} {>do} {>bufsize}" {rcode} {>rflags} {rsize} {duration}
```

Пример строки:

```text
[INFO] [::1]:50759 - 29008 "A IN example.org. udp 41 false 4096" NOERROR qr,rd,ra,ad 68 0.037990251s
```

В этой строке есть:

- **{name}** — домен (qname), то что нам нужно для эвристик (энтропия, длина, частота).
- **{remote}** — IP клиента (под/узел).
- **{type}** — тип записи (A, AAAA, TXT и т.д.).
- **{proto}** — tcp/udp.
- **{rcode}** — ответ (NOERROR, NXDOMAIN и т.д.).

**Включение в кластере:**

```bash
kubectl edit cm coredns -n kube-system
```

В блоке `.:53 { ... }` добавить `log` (или кастомный формат):

```text
.:53 {
    log
    # или только то, что нужно под наш парсер:
    # log . "{remote} {name} {type} {proto} {rcode}"
    errors
    health
    kubernetes cluster.local in-addr.arpa ip6.arpa {
      ...
    }
    forward . /etc/resolv.conf
    cache 30
    loop
    reload
    loadbalance
}
```

После правки — перезапуск подов CoreDNS, чтобы применить конфиг.

---

## 2. Как получать логи CoreDNS в наш анализатор

Варианты (все без TC и без привязки к CNI):

| Способ | Описание |
|--------|----------|
| **A. Лог-коллектор** | Fluent Bit / Fluentd / Vector собирают логи подов `kube-system/kube-dns`. Наш сервис подписывается на поток (Kafka, HTTP, файл) и парсит строки CoreDNS → (domain, client_ip, type, rcode). Детекция туннелей — те же эвристики по домену. |
| **B. Kubernetes Log API** | Отдельный компонент (под/Job) читает логи CoreDNS через API (`kubectl logs` или клиент к API сервера). Парсит строки и шлёт "события" в наш анализатор (как сейчас события из eBPF). |
| **C. Sidecar рядом с CoreDNS** | Нестандартно: sidecar в поде CoreDNS читает stdout контейнера CoreDNS и пересылает на наш DaemonSet/сервис. Мало кто так делает, но технически возможно. |
| **D. NodeLocal DNSCache** | Если включён NodeLocal DNSCache — это тоже CoreDNS на каждой ноде. В его Corefile тоже можно включить `log`. Тогда источник доменов — логи DaemonSet'а node-local-dns (по нодам). |

Рекомендация: **A или B** — минимум изменений в кластере, только включить `log` в Corefile и доставить логи до нашего анализатора.

---

## 3. Формат "события" из CoreDNS под нашу детекцию

Текущий пайплайн ожидает события с полями: домен, тип, направление (query/response), метаданные (PID, IP и т.д.). Из CoreDNS лога мы получаем:

- **domain** ← `{name}` (qname).
- **client_ip** ← `{remote}` (можно мапить на под через K8s API по IP).
- **query_type** ← `{type}` (A, AAAA, TXT…).
- **protocol** ← `{proto}`.
- **response** ← `{rcode}` (для разделения query/success/denial).

Этого достаточно для:

- энтропии по домену;
- длины/количества меток;
- частоты запросов по домену/клиенту;
- выделения подозрительных доменов (туннели, C2).

Можно определить структуру "CoreDNS log event" и адаптер, который из строки лога строит такое событие и передаёт в существующий обработчик эвристик (как сейчас `event_handler` для eBPF-событий).

---

## 4. Дополнительно: плагины и Cilium

- **CoreDNS JSON-лог**: есть сторонний плагин [coredns-jsonlog](https://github.com/spr-networks/coredns-jsonlog) — вывод в JSON, удобнее парсить.
- **dnstun**: [netrack/dnstun](https://github.com/netrack/dnstun) — CoreDNS-плагин для детекции DNS-туннелей (через внешний ML runtime). Можно использовать вместо или вместе с нашей логикой по логам.
- **Cilium FQDN cache** (только если CNI = Cilium): `cilium-dbg fqdn cache list` и API GetFqdnCache дают список DNS-запросов по endpoint. Это не заменяет CoreDNS: даёт уже "увиденные" домены для политик, но не полный поток запросов как лог. Для CNI-агностичности опираться на CoreDNS надёжнее.

---

## 5. Итог

| Вопрос | Ответ |
|--------|--------|
| Почему не TC? | TC на host-интерфейсе занят CNI (Cilium и др.) — нет CNI-агностичности. |
| Откуда тогда брать домены? | **CoreDNS** — стандартный DNS в K8s, не зависит от CNI. |
| Как именно? | Включить **log** в Corefile CoreDNS, получать в логах поля `{name}`, `{remote}`, `{type}`, `{proto}`, `{rcode}`. |
| Как доставить до нашего кода? | Лог-коллектор (Fluent Bit и т.п.) или чтение логов CoreDNS через Kubernetes API, парсинг строки → событие (domain, client_ip, type, rcode) → те же эвристики детекции. |
| Нужен ли payload как в eBPF? | Нет. Для эвристик туннелей достаточно **домена (qname), типа, клиента, кода ответа**. Полный DNS payload из лога не извлекается, но для детекции по энтропии/длине/частоте этого хватает. |

**Практические шаги:**

1. Включить `log` (или кастомный формат) в CoreDNS ConfigMap, перезапустить CoreDNS.
2. Реализовать парсер строки лога CoreDNS → внутреннее событие (domain, client_ip, type, rcode).
3. Подключить источник: либо подписка на поток из лог-коллектора, либо отдельный процесс, читающий логи CoreDNS через K8s API.
4. Переиспользовать существующую логику детекции (энтропия, длина, частота) на этих событиях — без eBPF/TC, CNI-агностично.
