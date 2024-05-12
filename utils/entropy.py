import math


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    data_bytes = bytes(data)  # Convert mmap object or data to bytes
    for x in range(256):
        p_x = float(data_bytes.count(x)) / len(data_bytes)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy
