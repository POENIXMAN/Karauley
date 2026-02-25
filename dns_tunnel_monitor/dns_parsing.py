"""DNS payload parsing: domain name, type, entropy."""
import math
from collections import defaultdict


def parse_dns_name(data, offset=12):
    """Parse DNS name with compression pointer support."""
    labels = []
    i = offset
    max_jumps = 10
    jumps = 0

    while i < len(data) and data[i] != 0 and jumps < max_jumps:
        length = data[i]
        if (length & 0xC0) == 0xC0:
            if i + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[i + 1]
            if pointer < i and pointer < len(data):
                jumps += 1
                sub_labels = parse_dns_name(data, pointer)
                if sub_labels:
                    labels.extend(sub_labels.split('.'))
            break
        if length > 63 or i + length + 1 > len(data):
            break
        label = bytes(data[i+1:i+1+length]).decode('utf-8', errors='ignore')
        labels.append(label)
        i += length + 1
    return '.'.join(labels) if labels else None


def get_dns_type_name(qtype):
    types = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
        10: "NULL", 12: "PTR", 15: "MX", 16: "TXT",
        28: "AAAA", 33: "SRV", 35: "NAPTR", 255: "ANY"
    }
    return types.get(qtype, f"TYPE{qtype}")


def parse_dns_type(data):
    i = 12
    while i < len(data) and data[i] != 0:
        length = data[i]
        if (length & 0xC0) == 0xC0:
            i += 2
            break
        i += length + 1
    else:
        i += 1
    if i + 2 <= len(data):
        qtype = (data[i] << 8) | data[i + 1]
        return qtype if qtype else 1
    return 1


def calculate_entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
