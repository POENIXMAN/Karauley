# Алгоритмы детекции DNS-туннелей: концепции, термины и ссылки

Документ описывает **типы DNS-туннелирования**, **алгоритмы детекции**, используемые в мониторе, и даёт **ссылки на статьи и ресурсы** для углублённого изучения.

---

## 1. Типы DNS-туннелирования (naming)

Под «DNS-туннелем» обычно понимают **злоупотребление протоколом DNS** для передачи данных, которые не являются обычным разрешением имён. В литературе и практике выделяют три основных сценария:

| Тип | Альтернативные названия | Суть | Типичные инструменты |
|-----|-------------------------|------|----------------------|
| **IP-over-DNS** | DNS tunneling (в узком смысле), DNS tunnel VPN, IPv4-over-DNS | Туннелирование IP-трафика поверх DNS: клиент и сервер эмулируют сетевой канал (часто TUN/TAP). Данные кодируются в запросах/ответах. | **iodine**, dns2tcp, OzymanDNS, NSTX |
| **C2 over DNS** | DNS C2, DNS beaconing, C&C over DNS | Канал управления (command & control): клиент периодически опрашивает сервер, получает команды; возможна передача данных. | **dnscat2**, Sliver (DNS transport), Cobalt Strike (DNS beacon) |
| **Data exfiltration over DNS** | DNS exfil, DNS data exfiltration, DNS covert channel | Вынос данных (кража) через DNS: фрагменты данных кодируются в поддоменах или в ответах. | **DNSExfiltrator**, Iodine (при передаче файлов), скрипты (base64 в subdomain) |

**Важно:** границы размыты. Один инструмент может сочетать C2 и exfil (например dnscat2); iodine — это IP-over-DNS, но при передаче файлов даёт и признаки exfil. Детекторы в мониторе привязаны к **сигналам** (высокий rate, NULL-запись, регулярность, энтропия, кодирование в поддомене), а не к одному «типу» туннеля.

---

## 2. Общая схема детекции в мониторе

```
DNS packet (payload sample 128 B) → парсинг (домен, type, answers) → 3 детектора:
  - C2 detector      → beacon regularity, TXT к недоверенным доменам
  - Exfil detector   → энтропия, длина, цифры, hex/base64 subdomain, много поддоменов
  - IP-over-DNS      → высокий rate, NULL-запись, много записей в ответе
       ↓
  Scoring-агрегатор (взвешенная сумма, порог 2) → suspicious / clean
```

Предварительно отфильтровываются: события без домена (`<unparseable>`), cluster-internal DNS (`.svc.cluster.local` и т.п.).

---

## 3. Детектор C2 (Command & Control over DNS)

**Файл:** `detectors/c2.py`  
**Цель:** выявить канал управления (beacon) и подозрительное использование TXT.

### 3.1 Beacon regularity (регулярность интервалов)

**Концепция:** C2-клиент «звонит домой» через равные промежутки времени. Интервалы между DNS-запросами к одному и тому же домену становятся **регулярными** (низкая вариация).

**Алгоритм:**
- Ключ: `(cgroup_id, base_domain)`. Храним до 20 последних **query** timestamps.
- Интервалы: `Δt[i] = (ts[i+1] − ts[i])` в секундах.
- **Coefficient of Variation:** `CV = σ / μ` (стандартное отклонение / среднее).
- Условие срабатывания: `CV < 0.15` и средний интервал `> 5` секунд.

**Обозначение в коде:** `C2_BEACON(interval=..., regularity=...)`  
**Вес в scoring:** 3.

**Ссылки:**
- **C2 and DNS Tunneling** (Lenny Zeltser): обзор C2 over DNS и как это детектировать —  
  https://zeltser.com/c2-dns-tunneling/
- **dnscat2** (protocol, poll-based C2):  
  https://github.com/iagox86/dnscat2  
  https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md
- **SANS — Detecting DNS Tunneling:** payload и traffic analysis —  
  https://www.sans.org/white-papers/34152/

---

### 3.2 TXT-запросы к недоверенным доменам (C2_TXT_REQUEST)

**Концепция:** Легитимные TXT-запросы — это в основном SPF, DKIM, DMARC, MTA-STS, ACME. Они идут к предсказуемым именам (`_dmarc.<domain>`, `selector._domainkey.<domain>` и т.д.) или к известным доменам. C2 (например dnscat2) использует TXT для передачи данных к произвольному домену атакующего.

**Алгоритм:**
- Если `dns_type == 16` (TXT): проверяем префиксы (`_dmarc.`, `_domainkey.`, `_mta-sts.`, `_acme-challenge.`, …) и whitelist доменов. Если ни то ни другое — сигнал `C2_TXT_REQUEST`.

**Обозначение в коде:** `C2_TXT_REQUEST`  
**Вес в scoring:** 1.

**Ссылки:**
- **dnscat2** — поддержка TXT (и других типов) для передачи:  
  https://github.com/iagox86/dnscat2
- **Sigma rule — Suspicious DNS Query with B64 Encoded String** (пример детекции аномальных DNS-запросов):  
  https://detection.fyi/sigmahq/sigma/network/dns/net_dns_susp_b64_queries/

---

### 3.3 Уклонение: редкий и медленный C2 (low-and-slow)

**Концепция:** Детекцию C2 по DNS можно затруднить, делая трафик **редким и медленным** (sparse and slow): мало запросов в единицу времени, большие интервалы между биконами. В литературе и практике это известный приём (low-and-slow DNS C2, slow beaconing).

**Почему это работает против детекторов:**
- **Rate-based детекция** (например HIGH_RATE в IP-over-DNS) срабатывает только при высокой частоте запросов. Редкий трафик не достигает порога и не детектируется.
- **Beacon-based детекция** (регулярность интервалов) по-прежнему может сработать, но только если за время наблюдения набирается достаточно запросов к одному домену.

**Как обрабатывается в мониторе:**
- **C2_BEACON** рассчитан на «медленный, но регулярный» бикон: срабатывает при среднем интервале **> 5 секунд** и низком коэффициенте вариации (CV < 0,15). То есть периодический C2 с интервалом в десятки секунд или минуты при достаточном числе сэмплов может быть обнаружен по регулярности.
- Ограничения: для срабатывания нужны минимум **5 запросов** к одному base_domain; хранится только последние **20** временных меток по ключу. При очень редком трафике (например один запрос в 10–60 минут) за разумное окно наблюдения не набирается 5 сэмплов — бикон не детектируется. Агрегация по домену на длинных окнах (часы) в текущей реализации не выполняется.

**Итог:** Редкий и медленный C2 — валидный способ усложнить детекцию. Монитор частично учитывает его за счёт C2_BEACON (регулярный бикон с интервалом > 5 с), но не покрывает **очень разреженный** трафик (редкие запросы при отсутствии длинных окон агрегации). Детекция по высокой частоте (HIGH_RATE) при таком трафике не срабатывает. В работе (диссертация/отчёт) это уместно упомянуть в разделе «Ограничения» или «Уклонение и развитие».

**Ссылки:**
- **C2 and DNS Tunneling (Zeltser):** обзор приёмов и детекции —  
  https://zeltser.com/c2-dns-tunneling/
- **SANS — Detecting DNS Tunneling:** анализ трафика и ограничения —  
  https://www.sans.org/white-papers/34152/

---

## 4. Детектор экфильтрации (Exfiltration)

**Файл:** `detectors/exfil.py`  
**Цель:** выявить передачу данных через кодирование в доменных именах (поддомены с высокой энтропией, base64/hex, много уникальных поддоменов).

### 4.1 Энтропия домена (Shannon entropy)

**Концепция:** Случайные или сжатые/зашифрованные данные дают равномерное распределение символов → высокая энтропия. Обычные домены (слова, бренды) — более низкая.

**Формула:**  
`H = −Σ p(c) · log₂(p(c))`, где `p(c)` — частота символа в строке (домен без точек).

**Порог в коде:** `ENTROPY_THRESHOLD = 4.0` → `HIGH_ENTROPY(…)`  
**Вес в scoring:** 2.

**Ссылки:**
- **Information-Entropy-Based DNS Tunnel Prediction** (Homem et al., Springer):  
  https://link.springer.com/chapter/10.1007/978-3-319-99277-8_8
- **Can We Detect Malicious Behaviours in Encrypted DNS Tunnels Using Network Flow Entropy?** (Khodjaeva, Zincir-Heywood):  
  https://gcris.ieu.edu.tr/handle/20.500.14365/3693
- **Detecting malicious and low throughput data exfiltration over the DNS protocol** (ScienceDirect):  
  https://www.sciencedirect.com/science/article/abs/pii/S0167404818304000
- **CyberDefenders — DNS Tunneling Detection:** практика для SOC —  
  https://cyberdefenders.org/blog/dns-tunneling-detection

---

### 4.2 Длина домена (LONG_DOMAIN)

**Концепция:** Экфильтрация часто упаковывает данные в длинные поддомены (до лимита DNS ~253 символа). Длинные имена — подозрительный признак.

**В коде:** `len(domain) > 60` → `LONG_DOMAIN`.  
**Ограничение:** при захвате 64 байта payload домен обрезается (~45 символов), поэтому эта проверка в текущем мониторе практически не срабатывает.  
**Вес в scoring:** 1.

**Ссылки:**
- **Akamai — Real-Time Detections for DNS Exfiltration:** длинные поддомены и объём —  
  https://www.akamai.com/blog/security/akamais-real-time-detections-for-dns-exfiltration
- **Using LogStream to Detect Data Exfil Over DNS:** длинные/random subdomain —  
  https://cribl.io/blog/using-cribl-to-detect-data-exfil-over-dns-logs-in-real-time

---

### 4.3 Доля цифр (HIGH_DIGIT_RATIO)

**Концепция:** В обычных доменах цифр мало. Hex/base64/числовые кодировки увеличивают долю цифр.

**В коде:** `digit_ratio = (число цифр) / len(domain без точек)`; порог `> 0.3` → `HIGH_DIGIT_RATIO`.  
**Вес в scoring:** 1.

---

### 4.4 Кодирование в первом поддомене (HEX_SUBDOMAIN, BASE64_SUBDOMAIN)

**Концепция:** Данные часто кодируют в первом компоненте имени: hex (`[0-9a-fA-F]+`) или Base64 (`[A-Za-z0-9+/=]+`). Детектор проверяет первый поддомен длиной > 20 символов; порядок проверок: сначала hex, потом base64 (hex — подмножество base64).

**Обозначения в коде:** `HEX_SUBDOMAIN`, `BASE64_SUBDOMAIN`  
**Вес в scoring:** по 2.

**Ссылки:**
- **Sigma — Suspicious DNS Query with B64 Encoded String:** base64 в DNS-запросах —  
  https://detection.fyi/sigmahq/sigma/network/dns/net_dns_susp_b64_queries/
- **DNSExfiltrator** (пример инструмента exfil через поддомены):  
  https://github.com/Arno0x/DNSExfiltrator

---

### 4.5 Много уникальных поддоменов (MANY_SUBDOMAINS)

**Концепция:** При экфильтрации один base domain используется для множества уникальных поддоменов (каждый поддомен — фрагмент данных). Легитимные CDN/сервисы тоже имеют много поддоменов, но обычно меньше, чем при массовой экфильтрации.

**В коде:** для каждого `base_domain` считаем уникальные поддомены (до 50 в списке, FIFO). Порог `> 40` → `MANY_SUBDOMAINS(n)`.  
**Вес в scoring:** 2.

**Ссылки:**
- **Detection of malicious and low throughput data exfiltration over the DNS protocol** — объём и разнообразие запросов —  
  https://www.sciencedirect.com/science/article/abs/pii/S0167404818304000
- **Akamai — DNS Exfiltration:** аномальный объём и частота —  
  https://www.akamai.com/blog/security/akamais-real-time-detections-for-dns-exfiltration

---

## 5. Детектор IP-over-DNS

**Файл:** `detectors/ip_over_dns.py`  
**Цель:** выявить туннели типа iodine: очень высокая частота запросов к одному домену, использование NULL-записей, много записей в ответе.

### 5.1 Высокий rate запросов (HIGH_RATE)

**Концепция:** IP-over-DNS передаёт поток данных через множество DNS-запросов/ответов в единицу времени. Частота запросов к одному домену (per cgroup, per base_domain) значительно выше типичного пользовательского или даже CDN-трафика.

**Алгоритм:**
- Ключ: `(cgroup_id, base_domain)`.
- Окно 10 секунд (per-key, sliding): при превышении окна — сброс счётчика для этого ключа.
- `rate = count / elapsed_sec`. Порог: `> 150` запросов/с → `HIGH_RATE(…/sec)`.

**Вес в scoring:** 3.

**Ссылки:**
- **iodine — IP-over-DNS:** официальная страница и README —  
  https://code.kryo.se/iodine/  
  https://code.kryo.se/iodine/README.html
- **Tunneling network traffic over DNS with Iodine and SSH SOCKS proxy:** как устроен туннель —  
  https://davidhamann.de/2019/05/12/tunnel-traffic-over-dns-ssh/
- **DNS NULL record tunneling (Mike Bommarito):** использование NULL для данных —  
  https://michaelbommarito.com/wiki/infosec/dns-null-record-tunneling/
- **SANS — Detecting DNS Tunneling:** traffic analysis, в т.ч. по объёму/частоте —  
  https://www.sans.org/white-papers/34152/

---

### 5.2 NULL-запись (NULL_RECORD)

**Концепция:** Тип записи DNS NULL (тип 10) редко используется в легитимном трафике. Iodine часто использует NULL для нисходящего канала (большой объём данных в одном ответе).

**В коде:** `dns_type == 10` → `NULL_RECORD(iodine)`.  
**Вес в scoring:** 2.

**Ссылки:**
- **iodine manpage** (поддерживаемые типы записей, включая NULL):  
  https://code.kryo.se/iodine/iodine_manpage.html
- **DNS NULL record tunneling:**  
  https://michaelbommarito.com/wiki/infosec/dns-null-record-tunneling/

---

### 5.3 Много записей в ответе (MANY_ANSWERS)

**Концепция:** В одном DNS-ответе IP-over-DNS может возвращать много записей (данные фрагментированы по записям). Обычный A/AAAA lookup даёт обычно 1–8 записей; туннель — больше.

**В коде:** `dns_answers > 10` → `MANY_ANSWERS(n)`.  
**Вес в scoring:** 2.

**Ссылки:**
- **iodine** — размер и структура ответов:  
  https://code.kryo.se/iodine/README.html
- **SANS — Detecting DNS Tunneling:** аномалии в ответах —  
  https://www.sans.org/white-papers/34152/

---

## 6. Scoring-агрегатор

**Файл:** `detectors/tunnel.py`

Все причины от трёх детекторов получают **вес** (см. таблицу ниже). Сумма весов даёт `score`. Если `score >= 2`, событие помечается как `suspicious`. Так один слабый сигнал (например только `C2_TXT_REQUEST`, вес 1) не даёт алерта; комбинация слабых или один сильный — даёт.

| Причина | Вес | Детектор |
|---------|:---:|----------|
| C2_BEACON | 3 | C2 |
| HIGH_RATE | 3 | IP-over-DNS |
| HIGH_ENTROPY | 2 | Exfil |
| HEX_SUBDOMAIN | 2 | Exfil |
| BASE64_SUBDOMAIN | 2 | Exfil |
| MANY_SUBDOMAINS | 2 | Exfil |
| NULL_RECORD | 2 | IP-over-DNS |
| MANY_ANSWERS | 2 | IP-over-DNS |
| C2_TXT_REQUEST | 1 | C2 |
| LONG_DOMAIN | 1 | Exfil |
| HIGH_DIGIT_RATIO | 1 | Exfil |

---

## 7. Обзорные и методологические источники

| Тема | Ссылка |
|------|--------|
| **Обзор детекции DNS-туннелей (survey)** | A comprehensive survey on DNS tunnel detection, Computer Networks 2021 — https://www.sciencedirect.com/science/article/abs/pii/S1389128621004149 (или по названию в Colab/Elsevier) |
| **IEEE Survey of DNS Tunnel Detection** | https://ieeexplore.ieee.org/document/9886602 |
| **SANS — Detecting DNS Tunneling** | https://www.sans.org/white-papers/34152/ |
| **SANS — Using Splunk to Detect DNS Tunneling** | https://www.sans.edu/cyber-research/37022/ |
| **C2 and DNS Tunneling (Zeltser)** | https://zeltser.com/c2-dns-tunneling/ |
| **CyberDefenders — DNS Tunneling Detection** | https://cyberdefenders.org/blog/dns-tunneling-detection |

---

## 8. Соответствие: алгоритм ↔ тип туннеля (упрощённо)

| Алгоритм / сигнал | Лучше всего ловит | Также может сработать на |
|-------------------|--------------------|---------------------------|
| C2_BEACON | C2 (dnscat2, DNS beacon) | — |
| C2_TXT_REQUEST | C2 (dnscat2, TXT C2) | Exfil через TXT |
| HIGH_ENTROPY, BASE64/HEX_SUBDOMAIN, MANY_SUBDOMAINS | Data exfiltration (DNSExfiltrator, скрипты) | C2 с кодированием в домене |
| HIGH_RATE, NULL_RECORD, MANY_ANSWERS | IP-over-DNS (iodine) | Другие туннели с высокой нагрузкой |
| LONG_DOMAIN, HIGH_DIGIT_RATIO | Exfil / длинные кодированные имена | Редкие легитимные случаи |

Этот документ можно использовать вместе с `DETECTION_ALGORITHMS.md` (детали формул и порогов в коде) и `TESTING_PLAN.md` (как проверять детекторы на iodine, dnscat2, DNSExfiltrator).
