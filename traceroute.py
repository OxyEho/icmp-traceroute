import socket

from icmp import IcmpPack


class Traceroute:
    def __init__(self, host: str):
        self._host = socket.gethostbyname(host)
        self._port = 33434
        self._max_hops = 30
        self._ttl = 0

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
                                  socket.SOCK_DGRAM,
                                  socket.IPPROTO_ICMP)
        recv_sock.settimeout(3)
        return send_sock, recv_sock

    def make_trace(self) -> list:
        trace_result = []
        while self._ttl <= self._max_hops:
            send_sock, recv_sock = self._create_sockets()
            icmp_pack = IcmpPack(0, 0)
            send_sock.sendto(icmp_pack.pack_icmp(),
                             (self._host, self._port))
            try:
                data, address = recv_sock.recvfrom(1024)
                print(address[0])
            except socket.timeout:
                trace_result.append('*')
                self._ttl += 1
                continue
            trace_result.append(address[0])
            recv_icmp = IcmpPack.get_icmp(data[20:])
            if self._is_over(recv_icmp):
                send_sock.close()
                recv_sock.close()
                break
            self._ttl += 1
            send_sock.close()
            recv_sock.close()

        return trace_result