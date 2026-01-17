# Troubleshooting для k3s

## Проблема: "ctr: image might be filtered out"

Это предупреждение обычно не критично. Выполните следующие шаги:

### 1. Проверьте, что образ загружен

```bash
# Проверьте список образов
sudo ctr -n k8s.io images list | grep ebpfmodule

# Или
sudo k3s crictl images | grep ebpfmodule
```

### 2. Если образ не найден, попробуйте другой способ

```bash
# Способ 1: Использовать docker (если установлен)
docker load -i ebpf-module-for-dns-tunneling/ebpfmodule-v1.0.tar
docker tag localhost/ebpfmodule:v1.0 localhost/ebpfmodule:v1.0

# Способ 2: Использовать k3s crictl напрямую
sudo k3s crictl load -i ebpf-module-for-dns-tunneling/ebpfmodule-v1.0.tar

# Способ 3: Импорт с явным указанием имени
sudo ctr -n k8s.io images import ebpf-module-for-dns-tunneling/ebpfmodule-v1.0.tar \
  --base-name localhost/ebpfmodule:v1.0
```

### 3. Проверьте имя образа после загрузки

```bash
sudo ctr -n k8s.io images list
```

Обратите внимание на полное имя образа. Оно должно быть в формате:
- `localhost/ebpfmodule:v1.0` или
- `docker.io/localhost/ebpfmodule:v1.0`

### 4. Если имя образа отличается, переименуйте его

```bash
# Пример: если образ называется по-другому
sudo ctr -n k8s.io images tag <старое-имя> localhost/ebpfmodule:v1.0

# Или удалите и переимпортируйте с правильным именем
sudo ctr -n k8s.io images rm localhost/ebpfmodule:v1.0
sudo ctr -n k8s.io images import ebpf-module-for-dns-tunneling/ebpfmodule-v1.0.tar \
  --base-name localhost/ebpfmodule:v1.0
```

### 5. Альтернатива: Использовать полное имя образа в Helm

Если образ загружен с другим именем, обновите Helm values:

```bash
# Сначала проверьте точное имя
sudo ctr -n k8s.io images list | grep ebpfmodule

# Затем используйте это имя в Helm
helm install dns-monitor ./helm \
  --set image.repository=<точное-имя-без-тега> \
  --set image.tag=<тег> \
  --set image.pullPolicy=Never
```

## Проверка работы образа

После загрузки образа проверьте:

```bash
# 1. Проверьте, что образ виден в k3s
sudo ctr -n k8s.io images list | grep ebpfmodule

# 2. Установите Helm chart
helm install dns-monitor ./helm \
  --set image.repository=localhost/ebpfmodule \
  --set image.tag=v1.0 \
  --set image.pullPolicy=Never \
  --namespace dns-monitor \
  --create-namespace

# 3. Проверьте статус подов
kubectl get pods -n dns-monitor

# 4. Если под не запускается, проверьте события
kubectl describe pod -n dns-monitor -l app.kubernetes.io/name=dns-monitor

# 5. Проверьте логи
kubectl logs -n dns-monitor -l app.kubernetes.io/name=dns-monitor
```

## Частые ошибки

### Ошибка: "ImagePullBackOff" или "ErrImagePull"

Это означает, что k3s не может найти образ. Решения:

1. Убедитесь, что используете `pullPolicy: Never`:
   ```bash
   helm upgrade dns-monitor ./helm \
     --set image.pullPolicy=Never
   ```

2. Проверьте точное имя образа:
   ```bash
   sudo ctr -n k8s.io images list | grep ebpfmodule
   ```

3. Переименуйте образ, если нужно:
   ```bash
   sudo ctr -n k8s.io images tag <текущее-имя> localhost/ebpfmodule:v1.0
   ```

### Ошибка: "Failed to pull image"

Убедитесь, что:
- Образ загружен: `sudo ctr -n k8s.io images list | grep ebpfmodule`
- Используется `pullPolicy: Never`
- Имя образа в Helm совпадает с загруженным

### Образ загружен, но под не запускается

Проверьте:
1. Логи пода: `kubectl logs -n dns-monitor <pod-name>`
2. События: `kubectl describe pod -n dns-monitor <pod-name>`
3. Права доступа (privileged режим должен быть включен)
