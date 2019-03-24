#!/usr/bin/python3

from typing import List, Set


def connect_scan(address: str, ports: Set[int]) -> List[int]:
    import socket
    from contextlib import closing
    open_ports: List[int] = []
    for port in ports:
        # loop through each port in the list of ports to scan
        try:
            with closing(
                    socket.socket(
                        socket.AF_INET,
                        socket.SOCK_STREAM
                    )
            ) as s:
                # open an IPV4 TCP socket
                s.connect((address, port))
                # attempt to connect the newly created socket to the target
                # address and port
                open_ports.append(port)
                # if the connection was successful then add the port to the
                # list of open ports
        except ConnectionRefusedError:
            pass
    return open_ports


def main() -> None:
    open_ports = connect_scan("127.0.0.1", set(range(65535)))
    print("\n".join(map(lambda x: f"port: [{x}]\tis open", open_ports)))
