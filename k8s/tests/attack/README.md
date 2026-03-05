# Attack workloads (Фаза B и C)

Поды в namespace `attack` генерируют DNS-туннельный трафик для тестирования детекторов. **Серверы** (iodined, dnscat2, приёмник DNSExfiltrator) запускаются **внутри кластера** в namespace `attack-server` — по одному за раз. Домен `attack.test` форвардится в CoreDNS на ClusterIP сервиса `tunnel-dns`.

| Инструмент | Сервер (под в attack-server) | Домен по умолчанию |
|------------|------------------------------|--------------------|
| **iodine** | iodined, порт 53 | `t.attack.test` |
| **dnscat2** | dnscat2 (Ruby), порт 53 | `c2.attack.test` |
| **DNSExfiltrator** | приёмник DNS (Python + dnslib) | `exfil.attack.test` |

---

## Инструкция: тестирование Фазы B (по шагам)

Ниже — полная последовательность команд. Важно: **клиенты** деплоятся из каталога **attack/** скриптом **attack/deploy.sh**; **серверы** — из **attack/servers/** скриптом **servers/deploy.sh**. Сбор логов и анализ выполняются из каталога **k8s/tests/** (родительский к attack/).

### Шаг 0. Предположения

- Кластер доступен (`kubectl` настроен).
- Для сбора логов задеплоен DaemonSet `dns-tunnel-monitor` (отдельная настройка мониторинга).
- Пути в инструкции: от корня репозитория. Если вы уже в **k8s/tests**, вместо `k8s/tests/attack` используйте `attack`, а шаги 5–6 выполняйте из текущего каталога.

---

### Шаг 1. Один раз: namespace серверов и Service

Выполнять из каталога **k8s/tests/attack/**:

```bash
cd k8s/tests/attack
cd servers && ./deploy.sh setup && cd ..
```

Скрипт выведет **ClusterIP** сервиса `tunnel-dns` (например `10.43.29.98`). Он понадобится на следующем шаге.

---

### Шаг 2. Один раз: настройка CoreDNS

Запросы к `*.attack.test` должны уходить на ClusterIP из шага 1.

1. Открыть конфиг CoreDNS:
   ```bash
   kubectl edit configmap coredns -n kube-system
   ```

2. В блоке `Corefile` добавить **перед** блоком `.:53` (подставить свой ClusterIP вместо `10.43.29.98`):
   ```text
       attack.test:53 {
           forward . 10.43.29.98
           log
       }
   ```

3. Сохранить и перезапустить CoreDNS:
   ```bash
   kubectl rollout restart deployment coredns -n kube-system
   ```
   (Если CoreDNS установлен как DaemonSet: `kubectl rollout restart daemonset coredns -n kube-system`.)

---

### Шаг 3. Namespace для клиентов

Из каталога **k8s/tests/attack/**:

```bash
cd k8s/tests/attack
./deploy.sh ns
```

Создаётся namespace `attack`.

---

### Шаг 4. Запуск одного инструмента (пример: iodine)

Дальше — для **одного** инструмента за раз (iodine, dnscat2 или exfil). Ниже — вариант для **iodine**; для dnscat2 и exfil команды те же, с заменой имени инструмента и переменных окружения (см. таблицу в конце).

**4.1. Задеплоить клиента** (из **k8s/tests/attack/**):

```bash
cd k8s/tests/attack
./deploy.sh iodine
```

**4.2. Запустить сервер** (из **k8s/tests/attack/**):

```bash
cd k8s/tests/attack
cd servers && ./deploy.sh iodine && cd ..
```

Дождаться готовности пода сервера:

```bash
kubectl get pods -n attack-server -w
```

(Выйти: Ctrl+C.)

**4.3. Домен уже задан в манифесте** (`t.attack.test`). При необходимости переопределить и перезапустить клиента:

```bash
kubectl set env deployment/iodine-client ATTACK_DOMAIN=t.attack.test -n attack
kubectl rollout restart deployment/iodine-client -n attack
```

**4.4. Прогрев** — подождать ~2 минуты, чтобы клиент стабильно генерировал трафик.

---

### Шаг 5. Сбор логов

Команды выполнять из каталога **k8s/tests/** (не из attack/):

```bash
cd k8s/tests
./collect.sh attack_iodine 10m
```

Будет создан (или дополнен) файл **results/attack_iodine.jsonl**. Длительность можно изменить (например `5m`, `15m`).

Для других инструментов подставьте метку: `attack_dnscat2`, `attack_exfil`.

---

### Шаг 6. Анализ результатов

Из каталога **k8s/tests/**:

```bash
cd k8s/tests
python3 analyze.py results/attack_iodine.jsonl
```

Для других инструментов: `results/attack_dnscat2.jsonl`, `results/attack_exfil.jsonl`.

---

### Шаг 7. Остановка нагрузки

Остановить **клиента** (из **k8s/tests/attack/**):

```bash
cd k8s/tests/attack
./deploy.sh stop iodine
```

Остановить **сервер**:

```bash
cd k8s/tests/attack
cd servers && ./deploy.sh stop && cd ..
```

Для dnscat2 и exfil в шагах 4–7 заменить `iodine` на `dnscat2` или `exfil` и использовать соответствующие имена deployment и переменные (см. таблицу ниже).

---

### Сводка команд по инструментам

| Действие | iodine | dnscat2 | DNSExfiltrator (exfil) |
|----------|--------|---------|-------------------------|
| Клиент (attack/) | `./deploy.sh iodine` | `./deploy.sh dnscat2` | `./deploy.sh exfil` |
| Сервер (attack/servers/) | `./deploy.sh iodine` | `./deploy.sh dnscat2` | `./deploy.sh exfil` |
| Домен (уже в манифесте) | `t.attack.test` | `c2.attack.test` | `exfil.attack.test` |
| Переопределить домен | `kubectl set env deployment/iodine-client ATTACK_DOMAIN=t.attack.test -n attack` | `kubectl set env deployment/dnscat2-client ATTACK_DOMAIN=c2.attack.test -n attack` | `kubectl set env deployment/dnsexfiltrator-client EXFIL_DOMAIN=exfil.attack.test -n attack` |
| Метка для collect.sh | `attack_iodine` | `attack_dnscat2` | `attack_exfil` |
| Файл результатов | `results/attack_iodine.jsonl` | `results/attack_dnscat2.jsonl` | `results/attack_exfil.jsonl` |
| Остановить клиента | `./deploy.sh stop iodine` | `./deploy.sh stop dnscat2` | `./deploy.sh stop exfil` |

Сервер всегда останавливается одной командой: из **attack/servers/** выполнить `./deploy.sh stop` (останавливает текущий сервер; порт 53 один на все три).

---

## Файлы в attack/

| Файл / папка | Описание |
|--------------|----------|
| `00-namespace.yaml` | Namespace `attack` (клиенты) |
| `01-iodine-client.yaml` | Iodine client (IP-over-DNS, нужен /dev/net/tun) |
| `02-dnscat2-client.yaml` | dnscat2 client (C2 over DNS) |
| `03-dnsexfiltrator-client.yaml` | DNSExfiltrator client + ConfigMap payload |
| `deploy.sh` | Деплой/остановка **клиентов** (ns, iodine, dnscat2, exfil, stop, status) |
| `servers/` | Манифесты серверов: namespace `attack-server`, Service `tunnel-dns` |
| `servers/deploy.sh` | Деплой серверов (setup, iodine, dnscat2, exfil, stop, cleanup, status) |

Подробнее по настройке серверов и CoreDNS: см. **SERVER_SETUP.md** в этом каталоге (если есть).

---

## Переменные клиентов

- **iodine:** `ATTACK_DOMAIN` (по умолчанию `t.attack.test`), опционально `ATTACK_NAMESERVER`.
- **dnscat2:** `ATTACK_DOMAIN` (по умолчанию `c2.attack.test`), опционально `DNSCAT2_SECRET` если сервер с `--secret`.
- **DNSExfiltrator:** `EXFIL_DOMAIN` (по умолчанию `exfil.attack.test`). Payload — ConfigMap `exfil-payload`, ключ `payload.txt`.

Изменить домен без правки манифеста: `kubectl set env deployment/<имя>-client ... -n attack`, затем `kubectl rollout restart deployment/<имя>-client -n attack`.

---

## DNSExfiltrator: имя скрипта

В репозитории Arno0x/DNSExfiltrator клиентский скрипт может называться `dnsExfiltrator.py` или иначе. Если в логах пода ошибка «no such file», проверьте структуру репо после `git clone` и в манифесте в `args` укажите правильный путь к скрипту.
