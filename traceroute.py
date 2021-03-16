import socket
import requests

from icmp import IcmpPack
from trace_node import TraceNode


class Traceroute:
    def __init__(self, host: str):
        self._host = socket.gethostbyname(host)
        self._max_hops = 30
        self._ttl = 1

    @staticmethod
    def _is_over(icmp: IcmpPack) -> bool:
        if icmp.icmp_type == icmp.icmp_code == 0:
            return True
        return False

    def _create_sockets(self) -> (socket.socket, socket.socket):
        send_sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM,
                                  socket.IPPROTO_ICMP)
        send_sock.setsockopt(socket.SOL_IP,
                             socket.IP_TTL,
                             self._ttl)
        recv_sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_RAW,
                                  socket.IPPROTO_ICMP)
        recv_sock.settimeout(3)
        return send_sock, recv_sock

    def make_trace(self):
        while self._ttl <= self._max_hops:
            send_sock, recv_sock = self._create_sockets()
            icmp_pack = IcmpPack(0, 0)
            send_sock.sendto(icmp_pack.pack_icmp(), (self._host, 80))
            try:
                data, address = recv_sock.recvfrom(1024)
            except socket.timeout:
                yield '*\n'
                self._ttl += 1
                continue
            whois_data = requests.get(f'http://ip-api.com/json/{address[0]}').json()
            trace_node = TraceNode(address[0], whois_data)
            yield trace_node
            recv_icmp = IcmpPack.get_icmp(data[20:])
            if self._is_over(recv_icmp):
                send_sock.close()
                recv_sock.close()
                break
            self._ttl += 1
            send_sock.close()
            recv_sock.close()
