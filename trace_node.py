import socket


class TraceNode:
    def __init__(self, addr: str, whois_data: dict):
        self.address = addr
        self.name = ''
        try:
            self.name = socket.gethostbyaddr(addr)[0]
        except socket.herror:
            pass
        self.country = ''
        self.auto_sys = ''
        if 'country' in whois_data:
            self.country = whois_data["country"]
        if 'as' in whois_data:
            self.auto_sys = whois_data['as']

    def _make_result_str(self):
        result = f'{self.address}\n'
        if self.name and not self.auto_sys and not self.country:
            result += f'{self.name}\n'
        elif self.name:
            result += f'{self.name}, '
        if self.auto_sys and not self.country:
            result += f'{self.auto_sys}\n'
        elif self.auto_sys:
            result += f'{self.auto_sys}, '
        if self.country:
            result += f'{self.country}\n'
        return result

    def __str__(self):
        return self._make_result_str()
