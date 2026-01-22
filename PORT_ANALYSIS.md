# Анализ использования порта в DNS Monitor

## Текущая ситуация

### ❌ ПРОБЛЕМА: HTTP сервер не реализован в коде

**Код приложения (`dns_analyzer_improved.py`):**
- ❌ Нет Flask/HTTP сервера
- ❌ Нет Prometheus метрик endpoint
- ❌ Нет `/healthz` и `/ready` endpoints
- ✅ Только вывод в консоль через eBPF

**Но Kubernetes ожидает:**
- ✅ HTTP сервер на порту 8080
- ✅ `/healthz` для liveness probe
- ✅ `/ready` для readiness probe  
- ✅ `/metrics` для Prometheus

**Результат:** Probes будут падать (connection refused / 404)

---

## Где используется порт 8080

### 1. **Код приложения** (НЕ РЕАЛИЗОВАНО)
```
dns_analyzer_improved.py
├── ❌ Нет HTTP сервера
├── ❌ Нет Flask app
└── ❌ Нет prometheus_client.start_http_server()
```

### 2. **Dockerfile**
```dockerfile
EXPOSE 8080  # ← Нужно изменить на 9999
```

### 3. **Kubernetes манифесты (k8s/)**

#### daemonset.yaml
- `containerPort: 8080` (строка 54)
- `livenessProbe.port: 8080` (строка 103)
- `readinessProbe.port: 8080` (строка 110)
- `prometheus.io/port: "8080"` (строка 24)

#### service.yaml
- `port: 8080` (строка 12)
- `targetPort: 8080` (строка 13)

#### configmap.yaml
- `prometheus.port: 8080` (строка 45)

### 4. **Helm Chart (helm/)**

#### values.yaml
- `service.port: 9999` ✅ (уже изменено)
- `service.targetPort: 9999` ✅ (уже изменено)
- `prometheus.port: 9999` ✅ (уже изменено)
- `daemonset.livenessProbe.port: 9999` ✅ (уже изменено)
- `daemonset.readinessProbe.port: 9999` ✅ (уже изменено)
- `config.prometheus.port: 9999` ✅ (уже изменено)

#### templates/ (используют переменные из values.yaml)
- ✅ Все шаблоны используют `{{ .Values.service.port }}` - автоматически обновятся

#### Dockerfile
- `EXPOSE 9999` ✅ (уже изменено)

---

## Что нужно исправить

### ✅ УЖЕ ИСПРАВЛЕНО (Helm)
- [x] `helm/values.yaml` - все порты на 9999
- [x] `Dockerfile` - EXPOSE 9999
- [x] `helm/README.md` - документация

### ❌ НУЖНО ИСПРАВИТЬ

#### 1. **Код приложения** (КРИТИЧНО)
```python
# dns_analyzer_improved.py
# НУЖНО ДОБАВИТЬ:
from flask import Flask
from prometheus_client import start_http_server, Counter, Gauge
import os

app = Flask(__name__)
METRICS_PORT = int(os.getenv('METRICS_PORT', '9999'))

@app.route('/healthz')
def healthz():
    return 'OK', 200

@app.route('/ready')
def ready():
    return 'OK', 200

@app.route('/metrics')
def metrics():
    # Prometheus метрики
    pass

# В main():
start_http_server(METRICS_PORT)
```

#### 2. **Kubernetes манифесты (k8s/)** - если используете напрямую
- [ ] `k8s/daemonset.yaml` - все 8080 → 9999
- [ ] `k8s/service.yaml` - 8080 → 9999
- [ ] `k8s/configmap.yaml` - 8080 → 9999

---

## Рекомендации

### Вариант 1: Использовать Helm (рекомендуется)
✅ Helm chart уже исправлен на 9999
❌ Но нужно добавить HTTP сервер в код

### Вариант 2: Использовать k8s/ манифесты напрямую
❌ Нужно исправить все вручную
❌ Нужно добавить HTTP сервер в код

---

## Вывод

**Нужно ли менять порт?** 
- ✅ ДА, если 8080 конфликтует (nginx и др.)
- ✅ 9999 - стандартный порт для мониторинга

**Что критично исправить?**
1. ❌ **Добавить HTTP сервер в код** (иначе probes упадут)
2. ✅ Helm chart уже исправлен
3. ⚠️ k8s/ манифесты нужно обновить, если используете их напрямую
