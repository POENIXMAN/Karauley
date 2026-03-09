import ctypes

PAYLOAD_SAMPLE = 256


class CgroupDNSEvent(ctypes.Structure):
    _fields_ = [
        ("direction", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 7),
        ("cgroup_id", ctypes.c_uint64),
        ("payload", ctypes.c_uint8 * PAYLOAD_SAMPLE),
        ("ip_version", ctypes.c_uint8),
    ]
