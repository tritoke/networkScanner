#!/usr/bin/env python
import socket
from typing import List
from headers import ip_header, icmp_header

# socket object using an IPV4 address, using only raw socket access, set
# ICMP protocol
ping_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

packets: List[bytes] = []

while len(packets) < 1:
    recPacket, addr = ping_sock.recvfrom(1024)
    ip = ip_header(recPacket[:20])
    icmp = icmp_header(recPacket[20:28])

    print(ip)
    print()
    print(icmp)
    print("\n")

    packets.append(recPacket)
