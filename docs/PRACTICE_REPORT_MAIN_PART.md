# Основная часть отчёта по практике

Фрагменты для отчёта по производственной практике по теме «Разработка модуля обнаружения DNS-туннелирования в Kubernetes» (ВКР).

---

## Описание задачи

Основной задачей практики стало развитие и доработка прототипа модуля обнаружения DNS-туннелирования в кластерах Kubernetes. Проект направлен на создание **CNI-независимого** (CNI-agnostic) решения: перехват DNS-трафика в ядре на основе eBPF (cgroup_skb) без привязки к конкретной сетевой подсистеме кластера, атрибуция событий до пода (cgroup_id → namespace/podname), эвристическая детекция туннелей (C2, утечка данных, IP-over-DNS) и экспорт метрик в Prometheus для мониторинга и алертинга. В рамках практики дорабатывались ключевые компоненты, которые войдут в выпускную квалификационную работу: архитектура «пакет → детектор → лог/метрики», валидация качества детекции по фазам A/B/C и сравнительный анализ с существующими инструментами (Falco, Cilium, Tetragon, Suricata и др.).

---

## План работы

Практика включала следующие этапы:

1. **Анализ и уточнение требований** — формулирование критериев сравнения с альтернативными решениями (точка перехвата, зависимость от CNI, привязка к поду, готовность детекции DNS-туннелей, деплой в Kubernetes).
2. **Проектирование и описание архитектуры** — путь пакета и метаданных от DNS-запроса до эвристики и лога (cgroup_skb → ring buffer → парсинг → pod_resolver → детекторы → score → JSON/метрики); схема в draw.io.
3. **Разработка и доработка компонентов** — загрузчик BPF, парсинг DNS, разрешение cgroup_id → pod (PodResolver), эвристические детекторы (C2, Exfil, IP-over-DNS), модуль метрик (Prometheus), структурированное логирование (JSONL).
4. **Деплой и интеграция** — упаковка в образ, Helm-чарт, DaemonSet; настройка сбора метрик (ServiceMonitor, Grafana).
5. **Экспериментальная валидация** — методология фаз A (только baseline), B (только атака), C (baseline + атака); скрипты сбора логов и анализа (analyze.py), расчёт confusion matrix и метрик (Precision, Recall, F1, FPR); воспроизводимые сценарии (iodine, dnscat2, exfil).
6. **Сравнительный анализ** — таблица с инструментами (Falco, Cilium, Tetragon, Pixie, Suricata, Zeek, CoreDNS+SIEM, Calico, Tracee, Inspektor Gadget) по критериям: точка перехвата, зависимость от CNI, привязка к поду, готовность детекции туннелей, деплой в K8s.
7. **Фиксация ограничений и перспектив** — только UDP/IPv4, порт 53; ограничения по DoH/DoT, IPv6, медленной утечке; репрезентативность выбранных типов атак (C2, exfil, IP-over-DNS).

---

## Применяемые методы

В ходе практики применялись следующие методы:

- **Анализ научно-технической и нормативной литературы** — изучение подходов к обнаружению DNS-туннелирования, обзор eBPF (cgroup_skb, BCC), документации Kubernetes и существующих решений (Falco, Cilium, Suricata и др.) для формирования требований и критериев сравнения.
- **Проектирование архитектуры программного обеспечения** — выделение компонентов (BPF-программа, загрузчик, парсинг DNS, PodResolver, детекторы, метрики), описание потока данных от перехвата пакета до лога и метрик; использование схем (draw.io) для визуализации пути пакета и обоснования выбора точки перехвата (cgroup без зависимости от CNI).
- **Системное программирование и eBPF** — разработка программы в ядре (C, cgroup_skb), загрузка через BCC, работа с ring buffer и структурой событий; парсинг DNS в пользовательском пространстве (Python), разрешение cgroup_id через cgroup fs и API Kubernetes.
- **Эвристическое моделирование угроз** — реализация детекторов по признакам C2 (beacon, TXT), утечки данных (энтропия, длинные поддомены, hex/base64), IP-over-DNS (rate, NULL, число ответов); взвешенный балл подозрительности и порог срабатывания.
- **Экспериментальная валидация** — трёхфазная методология (A/B/C), задание ground truth по доменам и namespace атакующих подов, расчёт матрицы ошибок и метрик качества (Precision, Recall, F1, FPR); повторяемость экспериментов (несколько прогонов Phase C, mean ± std).
- **Сравнительный анализ** — табличное сопоставление инструментов по заданным критериям; формулирование дифференциаторов решения (перехват в ядре без CNI, привязка к поду, готовая детекция туннелей, штатный деплой DaemonSet).

---

## Используемые данные и технологии

**Технологический стек:**

- **eBPF (BCC)** — перехват DNS-трафика в ядре Linux на уровне cgroup (cgroup_skb), без привязки к CNI; язык C для BPF-программы, загрузка и работа с ring buffer через Python-библиотеку BCC.
- **Python 3** — пользовательское пространство: загрузчик BPF, парсинг DNS (домен, тип записи, энтропия), обработка событий, детекторы, HTTP-сервер метрик.
- **Kubernetes** — оркестрация: DaemonSet (один под на узел), RBAC (ServiceAccount, list/get pods для PodResolver), монтирование host cgroup в контейнер.
- **Helm** — упаковка манифестов (DaemonSet, ConfigMap, ServiceAccount, ServiceMonitor), управление переменными окружения и whitelist.
- **Prometheus / Grafana** — сбор метрик (dns_queries_total, dns_suspicious_total, dns_events_by_pod и др.), визуализация и алертинг.
- **Docker** — сборка образа монитора для запуска в кластере.

**Используемые данные:**

- **DNS-трафик (UDP, порт 53)** — сэмпл payload (до 128 байт) из ядра; домен, тип записи, флаги, число ответов; направление (query/response).
- **Метаданные cgroup и пода** — cgroup_id из BPF; путь cgroup (cgroup v2); UID пода из пути; namespace/name пода из API Kubernetes (при доступном RBAC).
- **События и логи** — структурированные JSON-строки (ts, domain, direction, pod, suspicious, score, threat_type, reasons) для последующего анализа (analyze.py).
- **Ground truth для валидации** — разметка «атака / легитим» по namespace и домену атакующих подов (например, \*.attack.test); манифесты baseline- и attack-нагрузок (iodine, dnscat2, exfil).
- **Метрики качества** — confusion matrix (TP, FP, TN, FN), Precision, Recall, F1, FPR по фазам A/B/C и порогу score.

---

## Этапы разработки

**Проектирование архитектуры.** Описана цепочка обработки от перехвата пакета до решения детектора и вывода:

- **Ядро:** BPF cgroup_skb (egress/ingress) → фильтр UDP:53 → сэмпл payload и cgroup_id → ring buffer.
- **Пользовательское пространство:** загрузчик (BCC) → парсинг DNS → PodResolver (cgroup_id → client_pod, process) → обработчик событий → детекторы (C2, Exfil, IP-over-DNS) → взвешенный score и порог → JSON в stderr, инкремент метрик Prometheus.

Схема пути пакета и метаданных оформлена для наглядности (в т.ч. в draw.io) и обоснования выбора точки перехвата без зависимости от CNI.

**Разработка компонентов перехвата и атрибуции.** Реализованы: BPF-программа (dns_cgroup.bpf.c), загрузчик и парсинг DNS (loader.py, dns_parsing.py), структура события (event_struct.py). Реализован PodResolver: разрешение cgroup_id через cgroup fs и при наличии доступа — через API Kubernetes (namespace/name пода, опционально имя процесса из cgroup.procs).

**Реализация детекторов.** Разработаны эвристические детекторы: C2 (регулярность beacon, подозрительные TXT-запросы с whitelist), Exfil (энтропия, длинные поддомены, hex/base64), IP-over-DNS (частота запросов, тип NULL, большое число ответов). Агрегатор (TunnelDetector) считает взвешенный балл и выдаёт вердикт suspicious/clean; порог настраивается.

**Метрики и деплой.** Реализован HTTP-сервер (Flask + prometheus_client): /healthz, /ready, /metrics. Настроен Helm-чарт: DaemonSet, переменные окружения (CGROUP_PATH, METRICS_PORT и др.), опциональный RBAC и ServiceMonitor для Prometheus. Обеспечена работа в кластере с монтированием host cgroup.

**Экспериментальная валидация.** Внедрена методология трёх фаз: A (только baseline — оценка ложных срабатываний), B (только атака — способность детектировать), C (baseline + атака — реалистичный сценарий). Реализованы скрипты сбора логов (collect.sh) и анализа (analyze.py): расчёт confusion matrix и метрик (Precision, Recall, F1, FPR) по ground truth (--gt-by-domain, порог score). Проведены прогоны с инструментами iodine, dnscat2 и сценарием exfil; для Phase C выполнены повторные прогоны (mean ± std).

**Сравнительный анализ.** Подготовлена таблица сравнения с инструментами (Falco, Cilium, Tetragon, Pixie, Suricata, Zeek, CoreDNS+SIEM, Calico, Tracee, Inspektor Gadget) по критериям: точка перехвата, зависимость от CNI, привязка к поду, готовность детекции DNS-туннелей, деплой в Kubernetes. Зафиксированы дифференциаторы решения и ограничения (UDP/IPv4, порт 53; DoH/DoT, IPv6 — перспективы развития).

**Тестирование.** Проведено функциональное тестирование: работа монитора на узле и в кластере, корректность разрешения pod, срабатывание детекторов на тестовых сценариях. Проверена воспроизводимость экспериментов и корректность расчёта метрик качества по фазам A/B/C.

---

## Заключение

В ходе прохождения практики была выполнена значительная часть практической работы, которая войдёт в выпускную квалификационную работу. Получен опыт проектирования и разработки модуля обнаружения DNS-туннелирования в Kubernetes с опорой на eBPF (cgroup_skb), без зависимости от сетевой подсистемы кластера (CNI), с атрибуцией событий до пода и эвристической детекцией туннелей (C2, утечка данных, IP-over-DNS). Работа над проектом позволила развить компетенции в области системного программирования (eBPF, BCC), оркестрации контейнеров (Kubernetes, Helm), экспериментальной валидации (методология фаз A/B/C, метрики качества) и сравнительного анализа решений в области обнаружения угроз в DNS-трафике.

---

## Список использованных источников

1. eBPF — Introduction to eBPF. — URL: https://ebpf.io/ (дата обращения: 2025).
2. BCC — BPF Compiler Collection. — URL: https://github.com/iovisor/bcc (дата обращения: 2025).
3. Kubernetes. Documentation — Pods, DaemonSet, RBAC. — URL: https://kubernetes.io/docs/ (дата обращения: 2025).
4. Helm. Documentation. — URL: https://helm.sh/docs/ (дата обращения: 2025).
5. Prometheus. Documentation. — URL: https://prometheus.io/docs/ (дата обращения: 2025).
6. SANS Institute. Detecting DNS Tunneling. — URL: https://www.sans.org/white-papers/34152/ (дата обращения: 2025).
7. Zeltser L. C2 and DNS Tunneling. — URL: https://zeltser.com/c2-dns-tunneling/ (дата обращения: 2025).
8. CyberDefenders. DNS Tunneling Detection. — URL: https://cyberdefenders.org/blog/dns-tunneling-detection (дата обращения: 2025).
9. Homem I. et al. Information-Entropy-Based DNS Tunnel Prediction // ICT Systems Security and Privacy Protection. Springer, 2015. — URL: https://link.springer.com/chapter/10.1007/978-3-319-99277-8_8 (дата обращения: 2025).
10. Boukham M. et al. Detecting malicious and low throughput data exfiltration over the DNS protocol // Computers & Security. 2018. — URL: https://www.sciencedirect.com/science/article/abs/pii/S0167404818304000 (дата обращения: 2025).
11. Falco. Documentation — Rules, Custom Rules. — URL: https://falco.org/ (дата обращения: 2025).
12. Cilium. Documentation — DNS policies (toFQDNs), L7 proxy. — URL: https://docs.cilium.io/ (дата обращения: 2025).
13. Tetragon. Documentation — TracingPolicy, eBPF. — URL: https://tetragon.io/ (дата обращения: 2025).
14. Pixie. Documentation — PxL scripts, observability. — URL: https://px.dev/ (дата обращения: 2025).
15. Suricata. Documentation — DNS keywords, rules. — URL: https://docs.suricata.io/ (дата обращения: 2025).
16. Zeek. Documentation — dns.log, DNS scripts. — URL: https://docs.zeek.org/ (дата обращения: 2025).
17. CoreDNS. Documentation — Plugins (log, prometheus). — URL: https://coredns.io/ (дата обращения: 2025).
18. Tracee. Documentation — Policies, Kubernetes. — URL: https://aquasecurity.github.io/tracee/ (дата обращения: 2025).
19. Inspektor Gadget. trace dns, trace network. — URL: https://inspektor-gadget.io/ (дата обращения: 2025).
20. iodine — IP over DNS. — URL: https://code.kryo.se/iodine/ (дата обращения: 2025).
21. dnscat2. Protocol, C2 over DNS. — URL: https://github.com/iagox86/dnscat2 (дата обращения: 2025).
22. Akamai. Real-Time Detections for DNS Exfiltration. — URL: https://www.akamai.com/blog/security/akamais-real-time-detections-for-dns-exfiltration (дата обращения: 2025).
23. Sigma. Suspicious DNS Query with B64 Encoded String. — URL: https://detection.fyi/sigmahq/sigma/network/dns/net_dns_susp_b64_queries/ (дата обращения: 2025).

*При включении в отчёт дату обращения можно заменить на актуальную или указать год; при необходимости добавить источники по ГОСТ (с издательством и годом для статей и книг).*

---

*Документ можно копировать в отчёт по практике с правкой формулировок под фактически выполненные этапы.*
