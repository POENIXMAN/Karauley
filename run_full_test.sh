#!/bin/bash
#
# Полный тест улучшенной версии DNS Monitor
# 
# Запускает анализатор и использует test_improved_version.py для тестирования
# Сохраняет все логи для последующего анализа
#

# Не останавливаемся при ошибках (set -e отключен)
# set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}======================================================================${NC}"
echo -e "${BOLD}       ПОЛНЫЙ ТЕСТ УЛУЧШЕННОЙ ВЕРСИИ eBPF DNS MONITOR${NC}"
echo -e "${BOLD}======================================================================${NC}"

# Проверка root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Требуется запуск от root: sudo $0${NC}"
    exit 1
fi

# Проверка файлов
if [ ! -f "dns_ebpf_improved.bpf.c" ]; then
    echo -e "${RED}Файл dns_ebpf_improved.bpf.c не найден${NC}"
    exit 1
fi

if [ ! -f "dns_analyzer_improved.py" ]; then
    echo -e "${RED}Файл dns_analyzer_improved.py не найден${NC}"
    exit 1
fi

if [ ! -f "test_improved_version.py" ]; then
    echo -e "${RED}Файл test_improved_version.py не найден${NC}"
    exit 1
fi

# Создаём директорию для логов с timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$SCRIPT_DIR/test_results_$TIMESTAMP"
mkdir -p "$LOG_DIR"

# Файлы логов
ANALYZER_LOG="$LOG_DIR/analyzer.log"
TEST_LOG="$LOG_DIR/test.log"
COMBINED_LOG="$LOG_DIR/combined.log"
STATS_FILE="$LOG_DIR/stats.txt"

echo -e "${BLUE}[*] Логи сохраняются в: $LOG_DIR${NC}"
echo -e "${BLUE}[*] Анализатор: $ANALYZER_LOG${NC}"
echo -e "${BLUE}[*] Тесты: $TEST_LOG${NC}"
echo -e "${BLUE}[*] Комбинированный: $COMBINED_LOG${NC}"

# Запускаем анализатор в фоне
echo -e "${YELLOW}[*] Запуск dns_analyzer_improved.py...${NC}"
python3 dns_analyzer_improved.py > "$ANALYZER_LOG" 2>&1 &
ANALYZER_PID=$!

# Ждём запуска
sleep 3

# Проверяем что анализатор работает
if ! kill -0 $ANALYZER_PID 2>/dev/null; then
    echo -e "${RED}[!] Анализатор не запустился. Проверьте ошибки:${NC}"
    cat "$ANALYZER_LOG"
    exit 1
fi

echo -e "${GREEN}[+] Анализатор запущен (PID: $ANALYZER_PID)${NC}"

# Функция очистки
cleanup() {
    echo -e "\n${YELLOW}[*] Остановка анализатора...${NC}"
    kill -INT $ANALYZER_PID 2>/dev/null || true
    sleep 1
    kill $ANALYZER_PID 2>/dev/null || true
    wait $ANALYZER_PID 2>/dev/null || true
}
trap cleanup EXIT

# Запускаем тесты через test_improved_version.py
echo -e "${YELLOW}[*] Запуск тестов через test_improved_version.py...${NC}"
echo ""

# Запускаем в автоматическом режиме (без интерактивного ввода)
AUTO_TEST_MODE=1 timeout 120 python3 test_improved_version.py --auto > "$TEST_LOG" 2>&1
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}[+] Тесты завершены успешно${NC}"
elif [ $TEST_EXIT_CODE -eq 124 ]; then
    echo -e "${YELLOW}[!] Тесты прерваны по таймауту (120 сек)${NC}"
else
    echo -e "${YELLOW}[!] Тесты завершены с кодом: $TEST_EXIT_CODE${NC}"
fi

# Ждём обработки последних событий
echo -e "${YELLOW}[*] Ожидание обработки событий...${NC}"
sleep 3

# Останавливаем анализатор
kill -INT $ANALYZER_PID 2>/dev/null || true
sleep 2
kill $ANALYZER_PID 2>/dev/null || true
wait $ANALYZER_PID 2>/dev/null || true

# Объединяем логи
cat "$ANALYZER_LOG" "$TEST_LOG" > "$COMBINED_LOG" 2>/dev/null || true

# Результаты
echo ""
echo -e "${BOLD}======================================================================${NC}"
echo -e "${BOLD}                         РЕЗУЛЬТАТЫ${NC}"
echo -e "${BOLD}======================================================================${NC}"
echo ""

# Анализ логов
if [ -f "$ANALYZER_LOG" ]; then
    echo -e "${BLUE}Анализ логов анализатора:${NC}"
    echo ""
    
    # Статистика
    UDP_QUERY=$(grep -c "UDP QUERY" "$ANALYZER_LOG" 2>/dev/null || echo "0")
    UDP_RESP=$(grep -c "UDP RESPONSE" "$ANALYZER_LOG" 2>/dev/null || echo "0")
    TCP_QUERY=$(grep -c "TCP QUERY" "$ANALYZER_LOG" 2>/dev/null || echo "0")
    TCP_RESP=$(grep -c "TCP RESPONSE" "$ANALYZER_LOG" 2>/dev/null || echo "0")
    SUSPICIOUS=$(grep -c "SUSPICIOUS" "$ANALYZER_LOG" 2>/dev/null || echo "0")
    UNPARSEABLE=$(grep -c "<unparseable>" "$ANALYZER_LOG" 2>/dev/null || echo "0")
    TOTAL=$(grep -c "QUERY\|RESPONSE" "$ANALYZER_LOG" 2>/dev/null || echo "0")
    
    # Сохраняем статистику
    {
        echo "=== СТАТИСТИКА ТЕСТИРОВАНИЯ ==="
        echo "Дата: $(date)"
        echo ""
        echo "Всего событий:           $TOTAL"
        echo ""
        echo "UDP:"
        echo "  Запросов:              $UDP_QUERY"
        echo "  Ответов:               $UDP_RESP"
        echo ""
        echo "TCP:"
        echo "  Запросов:              $TCP_QUERY"
        echo "  Ответов:               $TCP_RESP"
        echo ""
        echo "Подозрительных:          $SUSPICIOUS"
        echo "Непарсируемых:           $UNPARSEABLE"
        echo ""
    } > "$STATS_FILE"
    
    echo -e "${BOLD}Статистика:${NC}"
    echo "  Всего событий:           $TOTAL"
    echo "  UDP запросов:            $UDP_QUERY"
    echo "  UDP ответов:            $UDP_RESP"
    echo "  TCP запросов:            $TCP_QUERY"
    echo "  TCP ответов:            $TCP_RESP"
    echo "  Подозрительных:          $SUSPICIOUS"
    echo "  Непарсируемых:           $UNPARSEABLE"
    echo ""
    
    # Чеклист
    echo -e "${BOLD}Чеклист:${NC}"
    
    [ "$UDP_QUERY" -gt 0 ] && echo -e "  ${GREEN}✓${NC} 8.1.1 UDP запросы перехватываются" || echo -e "  ${RED}✗${NC} 8.1.1 UDP запросы"
    [ "$UDP_RESP" -gt 0 ] && echo -e "  ${GREEN}✓${NC} 8.1.1 UDP ответы перехватываются" || echo -e "  ${RED}✗${NC} 8.1.1 UDP ответы"
    [ "$TCP_QUERY" -gt 0 ] && echo -e "  ${GREEN}✓${NC} 8.1.2 TCP DNS работает" || echo -e "  ${YELLOW}⚠${NC} 8.1.2 TCP DNS (может быть заблокирован)"
    
    # Проверяем парсинг TCP QUERY
    TCP_QUERY_PARSEABLE=$(grep "TCP QUERY" "$ANALYZER_LOG" | grep -v "<unparseable>" | wc -l)
    if [ "$TCP_QUERY" -gt 0 ] && [ "$TCP_QUERY_PARSEABLE" -gt 0 ]; then
        echo -e "  ${GREEN}✓${NC} 8.1.2 TCP QUERY парсится корректно"
    elif [ "$TCP_QUERY" -gt 0 ]; then
        echo -e "  ${YELLOW}⚠${NC} 8.1.2 TCP QUERY не парсится (все <unparseable>)"
    fi
    
    [ "$TCP_RESP" -gt 0 ] && echo -e "  ${GREEN}✓${NC} 8.1.2 TCP RESPONSE работает"
    [ "$SUSPICIOUS" -gt 0 ] && echo -e "  ${GREEN}✓${NC} Детекция подозрительных работает" || echo -e "  ${YELLOW}⚠${NC} Детекция"
    
    # Проверяем длинные домены
    if grep -q "aaaaaaa\|bbbbbbb" "$ANALYZER_LOG" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} 8.1.3 Длинные домены видны"
    else
        echo -e "  ${YELLOW}⚠${NC} 8.1.3 Длинные домены"
    fi
    
    # Проверяем разные DNS типы
    DNS_TYPES=$(grep -oE "(A|TXT|MX|AAAA|NS|CNAME)" "$ANALYZER_LOG" | sort -u | wc -l)
    if [ "$DNS_TYPES" -ge 3 ]; then
        echo -e "  ${GREEN}✓${NC} 8.2.1 Разные DNS типы парсятся ($DNS_TYPES типов)"
    else
        echo -e "  ${YELLOW}⚠${NC} 8.2.1 DNS типы (найдено: $DNS_TYPES)"
    fi
    
    echo ""
    
    # Показываем последние строки лога
    echo -e "${BLUE}Последние 30 строк лога анализатора:${NC}"
    echo ""
    tail -30 "$ANALYZER_LOG"
    echo ""
    
else
    echo -e "${RED}Лог-файл анализатора не найден${NC}"
fi

# Показываем результаты тестов
if [ -f "$TEST_LOG" ]; then
    echo -e "${BLUE}Результаты тестов:${NC}"
    echo ""
    tail -50 "$TEST_LOG"
echo ""
fi

# Итоговая информация
echo -e "${BOLD}======================================================================${NC}"
echo -e "${GREEN}Тестирование завершено!${NC}"
echo ""
echo -e "${CYAN}Все логи сохранены в:${NC}"
echo -e "  ${BOLD}$LOG_DIR${NC}"
echo ""
echo -e "${CYAN}Файлы:${NC}"
echo -e "  • analyzer.log    - полный лог анализатора"
echo -e "  • test.log        - вывод тестов"
echo -e "  • combined.log    - объединённый лог"
echo -e "  • stats.txt       - статистика"
echo ""
echo -e "${YELLOW}Для просмотра логов:${NC}"
echo -e "  cat $ANALYZER_LOG"
echo -e "  cat $TEST_LOG"
echo -e "  cat $STATS_FILE"
echo ""
echo -e "${BOLD}======================================================================${NC}"
