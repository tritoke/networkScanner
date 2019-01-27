#!/usr/bin/python3.7

import socket
from contextlib import closing

with closing(
        socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )
) as s:
    s.bind(("127.0.0.1", 6969))
    while True:
        data, addr = s.recvfrom(1024)
        s.sendto(bytes("Well hello there young one.", "utf-8"), addr)
