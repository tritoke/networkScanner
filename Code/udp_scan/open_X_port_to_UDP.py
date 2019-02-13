#!/usr/bin/env python

import socket
from contextlib import closing

with closing(
        socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )
) as s:
    s.bind(("127.0.0.1", 6969))
    print("opened port 6969 on localhost")
    while True:
        data, addr = s.recvfrom(1024)
        s.sendto(bytes("Well hello there young one.", "utf-8"), addr)
