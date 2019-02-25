#!/usr/bin/python3.7
from contextlib import closing
import socket
import ip_utils

dest_port = 22
src_port = ip_utils.get_free_port()
local_ip = ip_utils.get_local_ip()
dest_ip = "192.168.1.159"
local_ip = dest_ip = "127.0.0.1"
loc_long = ip_utils.dot_to_long(local_ip)

SYN = 2
RST = 4



with closing(
        socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_TCP
        )
) as s:
    tcp_packet = ip_utils.make_tcp_packet(
        src_port,
        dest_port,
        local_ip,
        dest_ip,
        SYN
    )
    if tcp_packet is not None:
        s.sendto(tcp_packet, (dest_ip, dest_port))
    else:
        print(f"Couldn't make TCP packet with supplied arguments:",
              f"source port: [{src_port}]",
              f"destination port: [{dest_port}]",
              f"local ip: [{local_ip}]",
              f"destination ip: [{dest_ip}]",
              f"SYN flag: [{SYN}]",
              sep="\n")
