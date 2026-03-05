# Attack workloads (Фаза B и C)

Поды в namespace `attack` генерируют DNS-туннельный трафик для тестирования детекторов. **Серверы** (iodined, dnscat2, приёмник DNSExfiltrator) запускаются **внутри кластера** в namespace `attack-server` — по одному за раз. Домен `attack.test` форвардится в CoreDNS на ClusterIP этого сервиса.

## Требования

1. **Серверы в кластере** — один раз: `servers/deploy.sh setup`, затем в CoreDNS добавить зону `attack.test` с `forward` на ClusterIP сервиса `tunnel-dns` (см. [SERVER_SETUP.md](SERVER_SETUP.md)).
2. Для каждого теста: поднять нужный сервер (`servers/deploy.sh iodine` / `dnscat2` / `exfil`), затем клиента в `attack`.

| Инструмент | Сервер (под в attack-server) | Домен |
|------------|------------------------------|--------|
| **iodine** | iodined, порт 53 | `t.attack.test` |
| **dnscat2** | dnscat2 (Ruby), порт 53 | `c2.attack.test` |
| **DNSExfiltrator** | приёмник DNS (Python + dnslib) | `exfil.attack.test` |

## Быстрый старт (Фаза B)

Все команды ниже — из каталога **attack/** (не из attack/servers/). Клиенты живут в namespace `attack`, серверы — в `attack-server`.

```bash
# 1) Один раз: серверы + CoreDNS (из attack/)
cd servers && bash deploy.sh setup
# Добавить в Corefile зону attack.test → forward . <ClusterIP>, перезапустить coredns
cd ..

# 2) Namespace для клиентов и деплой клиента (из attack/)
bash deploy.sh ns
bash deploy.sh iodine

# 3) Запустить сервер (из attack/)
cd servers && bash deploy.sh iodine
cd ..

# 4) Домен и перезапуск клиента
kubectl set env deployment/iodine-client ATTACK_DOMAIN=t.attack.test -n attack
kubectl rollout restart deployment/iodine-client -n attack

# 5) Прогрев ~2 мин, затем сбор логов (из корня k8s/tests)
bash collect.sh attack_iodine 10m

# 6) Анализ
python3 analyze.py results/attack_iodine.jsonl

# 7) Остановить клиент и сервер
bash deploy.sh stop iodine
cd servers && bash deploy.sh stop
```

## Файлы

| Файл / папка | Описание |
|--------------|----------|
| `00-namespace.yaml` | Namespace `attack` (клиенты) |
| `01-iodine-client.yaml` | Iodine client (IP-over-DNS) |
| `02-dnscat2-client.yaml` | dnscat2 client (C2 over DNS) |
| `03-dnsexfiltrator-client.yaml` | DNSExfiltrator client + ConfigMap payload |
| `deploy.sh` | Деплой/остановка **клиентов** по имени инструмента |
| `servers/` | Серверы в кластере: namespace `attack-server`, Service `tunnel-dns`, поды серверов |
| `servers/deploy.sh` | Деплой серверов (setup, iodine, dnscat2, exfil, stop, cleanup, status) |
| `SERVER_SETUP.md` | Настройка in-cluster серверов и CoreDNS |

## Переменные клиентов

- **iodine:** `ATTACK_DOMAIN` (обязательно, например `t.attack.test`), опционально `ATTACK_NAMESERVER`.
- **dnscat2:** `ATTACK_DOMAIN` (например `c2.attack.test`), опционально `DNSCAT2_SECRET` если сервер с `--secret`.
- **DNSExfiltrator:** `EXFIL_DOMAIN` (например `exfil.attack.test`). Payload — ConfigMap `exfil-payload`, ключ `payload.txt`.

Изменить домен без правки манифеста:

```bash
kubectl set env deployment/iodine-client ATTACK_DOMAIN=t.attack.test -n attack
kubectl rollout restart deployment/iodine-client -n attack
```

## DNSExfiltrator: имя скрипта

В репозитории Arno0x/DNSExfiltrator клиентский скрипт может называться `dnsExfiltrator.py` или иначе. Если в логах пода ошибка «no such file», проверьте структуру репо после `git clone` и в манифесте в `args` укажите правильный путь к скрипту.
