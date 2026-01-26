#!/bin/sh
# Поднимаем memlock — в большинстве контейнеров по умолчанию 64 KB,
# этого мало для BPF ring buffer. Без этого «Cannot allocate memory».
ulimit -l unlimited 2>/dev/null || ulimit -l 16777216
exec python3 /app/dns_analyzer_improved.py "$@"
