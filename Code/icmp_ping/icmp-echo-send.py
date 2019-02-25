#!/usr/bin/env python
import socket
import struct
import os
import time
from ip_utils import ip_checksum


ICMP_ECHO_REQUEST = 8

# opens a raw socket for the ICMP protocol
ping_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# allows manual IP header creation
# ping_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

ID = os.getpid() & 0xFFFF

# the two zeros are the code and the dummy checksum, the one is the
# sequence number
dummy_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)

data = struct.pack("d", time.time()) + \
    bytes((192 - struct.calcsize("d")) * "A", "ascii")
# the data to send in the packet
checksum = socket.htons(ip_checksum(dummy_header + data))
# calculates the checksum for the packet and psuedo header
header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksum, ID, 1)
# packs the packet header
packet = header + data
# concatonates the header and the data to form the final packet.
ping_sock.sendto(packet, ("127.0.0.1", 1))
# sends the packet to localhost
