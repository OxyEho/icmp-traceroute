import struct
import random


def get_checksum(msg: bytes) -> int:
    checksum = 0
    for i in range(0, len(msg), 2):
        part = (msg[i] << 8) + (msg[i + 1])
        checksum += part
    checksum = (checksum >> 16) + (checksum & 0xffff)

    return checksum ^ 0xffff


class IcmpPack:
    def __init__(self, icmp_type: int, icmp_code: int):
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code

    @staticmethod
    def pack_icmp() -> bytes:
        icmp_type = 8
        icmp_code = 0
        mock_data = struct.pack('!BBH', icmp_type, icmp_code, 0)
        current_sum = get_checksum(mock_data)
        return struct.pack('!BBHHH', icmp_type, icmp_code, current_sum, 1, random.randint(256, 3000))

    @classmethod
    def get_icmp(cls, data: bytes):
        icmp_type, icmp_code = struct.unpack('!BB', data[:2])
        return cls(icmp_type, icmp_code)

