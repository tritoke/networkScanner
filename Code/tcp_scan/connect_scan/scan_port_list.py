#!/usr/bin/python3

from typing import List

def connect_scan(address, ports):
    import socket
    from contextlib import closing
    open_ports: List[int] = []
    for port in ports:
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                s.connect((address, port))
                open_ports.append(port)
        except ConnectionRefusedError:
            pass
    return open_ports
if __name__ == "__main__":
    open_ports = connect_scan("192.168.1.159", range(65535))
    print("\n".join(map(lambda x: f"port: [{x}]\tis open", open_ports)))
