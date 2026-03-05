# Серверы attack-инструментов (в кластере)

Серверы для iodine, dnscat2 и DNSExfiltrator запускаются **внутри кластера** как поды в namespace `attack-server`. Один Service (`tunnel-dns`) даёт один ClusterIP; все три сервера используют порт 53, поэтому в один момент работает только один сервер.

## 1. Разовое создание namespace и сервиса

Из каталога `attack/`:

```bash
cd servers
./deploy.sh setup
```

Скрипт создаёт namespace `attack-server`, Service `tunnel-dns` (порт 53) и выводит его **ClusterIP**. Этот IP нужен для CoreDNS.

## 2. Настройка CoreDNS

Чтобы запросы к `*.attack.test` шли на наши серверы, нужно направить зону в CoreDNS на ClusterIP сервиса `tunnel-dns`.

**Узнать ClusterIP:**

```bash
kubectl get svc tunnel-dns -n attack-server -o jsonpath='{.spec.clusterIP}'
```

**Отредактировать конфиг CoreDNS:**

```bash
kubectl edit configmap coredns -n kube-system
```

В блоке `Corefile` добавьте **перед** блоком `.:53` (подставьте вместо `CLUSTER_IP` полученный IP):

```text
    attack.test:53 {
        forward . CLUSTER_IP
        log
    }
```

Пример фрагмента:

```text
  Corefile: |
    attack.test:53 {
        forward . 10.96.123.45
        log
    }
    .:53 {
        errors
        ...
    }
```

Сохраните и перезапустите CoreDNS:

```bash
kubectl rollout restart deployment coredns -n kube-system
# или для DaemonSet:
kubectl rollout restart daemonset coredns -n kube-system
```

## 3. Запуск серверов (по одному)

Из каталога `attack/servers/`:

| Команда | Сервер | Домен для клиента |
|---------|--------|--------------------|
| `./deploy.sh iodine` | iodined | `t.attack.test` |
| `./deploy.sh dnscat2` | dnscat2 | `c2.attack.test` |
| `./deploy.sh exfil` | приёмник DNSExfiltrator | `exfil.attack.test` |

Каждая команда останавливает предыдущий сервер и поднимает нужный. После деплоя дождитесь Ready пода:

```bash
kubectl get pods -n attack-server -w
```

**Клиенты** работают в namespace `attack`. Его создаёт и деплой клиентов делает скрипт **в каталоге attack/** (родительском к servers/), не servers/deploy.sh. Перед настройкой клиента выполните из каталога attack/:

```bash
./deploy.sh ns              # создать namespace attack
./deploy.sh iodine          # или dnscat2, или exfil — задеплоить клиента
```

Затем задайте домен и перезапустите клиента (см. README.md).

## 4. Проверка форварда

Убедиться, что запросы к `attack.test` уходят на сервер:

```bash
DNS_IP=$(kubectl get svc kube-dns -n kube-system -o jsonpath='{.spec.clusterIP}')
kubectl run -it --rm dig-test --image=busybox --restart=Never -- dig @${DNS_IP} +short test.attack.test
```

Перед проверкой должен быть запущен хотя бы один сервер в `attack-server` (например `./deploy.sh iodine`). Ответ (или пустая строка при успешном ответе от сервера) означает, что форвард и сервер работают.

## 5. Остановка и очистка

- **Остановить все серверы** (namespace и Service остаются):  
  `./deploy.sh stop`

- **Полная очистка** (удалить namespace, Service и поды):  
  `./deploy.sh cleanup`  
  После этого вручную удалите блок `attack.test:53` из Corefile и перезапустите CoreDNS.

## Внешний сервер (VM / VPS)

Для тестов достаточно in-cluster серверов. Если нужен сервер снаружи кластера (VM или VPS), в CoreDNS в блоке `attack.test:53` укажите `forward . IP_VM_или_VPS` вместо ClusterIP; на VM/VPS должен слушать порт 53 тот же iodined / dnscat2 / приёмник. Подробная инструкция по настройке на Windows/Docker или Alpine VM в этой документации не приводится.
