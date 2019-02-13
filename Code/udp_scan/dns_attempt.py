#!/usr/bin/ python
from contextlib import closing
import ip_utils
import socket

dest_ip = "192.168.1.1"
dest_port = 68
local_ip = ip_utils.get_local_ip()
local_port = ip_utils.get_free_port()

local_ip = dest_ip = "127.0.0.1"

address = (dest_ip, dest_port)

with closing(
        socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_UDP
        )) as s:
    try:
        pkt = ip_utils.make_udp_packet(
            local_port,
            dest_port,
            local_ip,
            dest_ip
        )
        if pkt is not None:
            packet = bytes(pkt)
            s.sendto(packet, address)
        else:
            print(
                "Error making packet.",
                f"local port: [{local_port}]",
                f"destination port: [{dest_port}]",
                f"local ip: [{local_ip}]",
                f"destination ip: [{dest_ip}]",
                sep="\n"
            )
    except socket.error:
        raise
