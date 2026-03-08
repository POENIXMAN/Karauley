#!/usr/bin/env python3
"""
Генератор DNS-запросов для тестирования монитора DNS-туннелей на VM.

Проверяет разные типы записей (A, AAAA, TXT, MX, ...) и разную длину имён
(короткие, длинные, на границе 64 байт payload), чтобы убедиться, что
монитор корректно парсит события и не даёт лишних <unparseable>.

Использование:
  # Ресолвер по умолчанию — systemd-resolved (127.0.0.53) или 8.8.8.8
  python3 dns_query_tester.py

  # Только определённые типы
  python3 dns_query_tester.py --types A,TXT,AAAA

  # Только длинные домены (проверка парсера на длинных именах)
  python3 dns_query_tester.py --sizes long,very_long

  # Принудительно IPv4 (по умолчанию), или попытка IPv6
  python3 dns_query_tester.py --family 4
  python3 dns_query_tester.py --family 6

  # Триггер для <unparseable> (монитор с DEBUG_UNPARSEABLE=1):
  #   Текущий BPF проверяет proto по offset 9 (IPv4); для IPv6 пакеты отбрасываются
  #   и вообще не попадают в userspace — поэтому IPv6 тут не даёт событий.
  #   Работающий триггер — обрезка payload (имя длиннее 64 байт):
  python3 dns_query_tester.py --sizes truncated --types A -n 3
  #   Режим --unparseable гоняет только truncated (+ short для контраста)
  python3 dns_query_tester.py --unparseable

Запуск монитора в другом терминале:
  sudo DEBUG_UNPARSEABLE=1 python3 -m dns_tunnel_monitor.main
"""

import argparse
import random
import socket
import struct
import sys

# DNS QTYPE (из dns_parsing.py)
DNS_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "NULL": 10,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "NAPTR": 35,
    "ANY": 255,
}


def build_dns_query(domain: str, qtype: int, qid: int = None) -> bytes:
    """Собрать сырой DNS-запрос (только вопрос)."""
    if qid is None:
        qid = random.randint(1, 65535)
    # Заголовок: ID, flags=0, QDCOUNT=1, остальные 0
    header = struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0)
    # QNAME: метки
    qname = b""
    for label in domain.rstrip(".").split("."):
        if len(label) > 63:
            label = label[:63]
        qname += bytes([len(label)]) + label.encode("utf-8")
    qname += b"\x00"
    # QTYPE, QCLASS=1 (IN)
    footer = struct.pack(">HH", qtype, 1)
    return header + qname + footer


def send_udp(payload: bytes, host: str, port: int = 53, family: int = socket.AF_INET) -> None:
    """Отправить UDP-пакет на host:port."""
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(2.0)
        sock.sendto(payload, (host, port))
        _ = sock.recv(4096)
    except socket.timeout:
        pass
    except Exception as e:
        print(f"  [warn] {host}:{port} {e}", file=sys.stderr)
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser(description="Тест разных типов и размеров DNS-запросов для монитора")
    ap.add_argument("--resolver", default="127.0.0.53", help="Куда слать запросы (default: 127.0.0.53)")
    ap.add_argument("--port", type=int, default=53, help="Порт DNS (default: 53)")
    ap.add_argument(
        "--types",
        default=",".join(DNS_TYPES.keys()),
        help="Типы записей через запятую (default: все)",
    )
    ap.add_argument(
        "--sizes",
        default="short,medium,long,very_long",
        help="Размеры доменов: short,medium,long,very_long,truncated (default: все, без truncated)",
    )
    ap.add_argument(
        "--unparseable",
        action="store_true",
        help="Гонять только триггеры unparseable: IPv6 + truncated (резолвер ::1)",
    )
    ap.add_argument("--family", type=int, default=4, choices=(4, 6), help="IP: 4 или 6 (default: 4)")
    ap.add_argument("-n", "--count", type=int, default=1, help="Сколько раз гонять каждый вариант (default: 1)")
    ap.add_argument("-q", "--quiet", action="store_true", help="Меньше вывода")
    args = ap.parse_args()

    if args.unparseable:
        args.types = "A"
        args.sizes = "short,truncated"
        args.count = max(args.count, 3)
        if not args.quiet:
            print("[unparseable] режим: short (норма) + truncated (unparseable); IPv6 текущим BPF не виден", file=sys.stderr)

    types_filter = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    sizes_filter = [s.strip().lower() for s in args.sizes.split(",") if s.strip()]

    # Домены разной длины (все резолвятся в реальности или просто уходят в монитор)
    short_domains = [
        "example.com",
        "a.co",
        "test.local",
    ]
    medium_domains = [
        "sub.domain.example.com",
        "mail.google.com",
        "api.github.com",
    ]
    long_domains = [
        "some-very-long-subdomain-sequence.google.com",
        "one.two.three.four.five.six.example.com",
        "a.b.c.d.e.f.g.h.i.j.k.l.m.n.example.com",
    ]
    # Очень длинное имя — укладываемся в 64 байта payload (заголовок DNS 12 + имя + 4)
    # 64 - 12 - 4 = 48 байт на QNAME. Один label 63 нельзя, делаем несколько коротких.
    very_long_domains = [
        "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.aa.bb.cc.example.com",
        "x" * 20 + ".y" * 10 + ".test.com",
    ]
    # Обрезка: BPF отдаёт только 64 байта. Один label длиной 63 — 12+1+63=76 > 64,
    # в буфере после байта длины только 51 байт метки → парсер видит length=63,
    # i+1+63 > len(data), break без добавления label → parse_dns_name возвращает None → <unparseable>
    truncated_domains = [
        ("x" * 63) + ".test.com",
        ("a" * 63) + ".example.com",
    ]

    size_to_list = {
        "short": short_domains,
        "medium": medium_domains,
        "long": long_domains,
        "very_long": very_long_domains,
        "truncated": truncated_domains,
    }

    family = socket.AF_INET if args.family == 4 else socket.AF_INET6
    resolver = args.resolver
    if args.family == 6 and resolver == "127.0.0.53":
        resolver = "::1"

    total = 0
    for type_name in types_filter:
        if type_name not in DNS_TYPES:
            print(f"[skip] неизвестный тип {type_name}", file=sys.stderr)
            continue
        qtype = DNS_TYPES[type_name]
        for size_name in sizes_filter:
            if size_name not in size_to_list:
                print(f"[skip] неизвестный размер {size_name}", file=sys.stderr)
                continue
            for domain in size_to_list[size_name]:
                for _ in range(args.count):
                    payload = build_dns_query(domain, qtype)
                    send_udp(payload, resolver, args.port, family)
                    total += 1
                    if not args.quiet:
                        print(f"  {type_name:6} {size_name:10} {domain[:50]}{'...' if len(domain) > 50 else ''}")

    if not args.quiet:
        print(f"\nОтправлено запросов: {total}")
    else:
        print(total)


if __name__ == "__main__":
    main()
