#!/usr/bin/env python3
"""
DNS Analyzer - Улучшенная версия (entrypoint).
Работает с dns_ebpf_improved.bpf.c.
Код разбит по модулям в пакете dns_monitor.
"""
from dns_monitor.main import main

if __name__ == "__main__":
    main()
