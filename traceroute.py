import socket

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

    @staticmethod
    def _get_whois_data(address: str):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((socket.gethostbyname('whois.iana.org'), 43))
        sock.send((address + '\r\n').encode('utf-8'))
        result_data = {}
        try:
            first_data = sock.recv(1024).decode()
            if 'refer' in first_data:
                refer_ind = first_data.index('refer')
                first_data = first_data[refer_ind:].split('\n')[0].replace(' ', '').split(':')
                whois_server = first_data[1]
                whois_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                whois_sock.connect((whois_server, 43))
                whois_sock.send((address + '\r\n').encode('utf-8'))
                data = b''
                current_part = whois_sock.recv(1024)
                while current_part != b'':
                    data += current_part
                    current_part = whois_sock.recv(1024)
                data = data.decode().lower()
                for el in ['country', 'origin', 'originas']:
                    if el in data:
                        ind = data.index(el)
                        record = data[ind:].split('\n')[0]
                        record = record.replace(' ', '').split(':')
                        result_data[record[0]] = record[1]
                return result_data
        except socket.timeout:
            pass
        finally:
            sock.close()
            return result_data

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
            whois_data = self._get_whois_data(address[0])
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
