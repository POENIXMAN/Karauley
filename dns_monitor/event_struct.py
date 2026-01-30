"""eBPF event structure (must match C layout)."""
import ctypes


class DNSEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("cgroup_id", ctypes.c_uint64),
        ("netns_id", ctypes.c_uint32),
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("dns_id", ctypes.c_uint16),
        ("dns_flags", ctypes.c_uint16),
        ("dns_questions", ctypes.c_uint16),
        ("dns_answers", ctypes.c_uint16),
        ("timestamp_ns", ctypes.c_uint64),
        ("data_len", ctypes.c_uint16),
        ("dns_data", ctypes.c_uint8 * 256),
    ]
