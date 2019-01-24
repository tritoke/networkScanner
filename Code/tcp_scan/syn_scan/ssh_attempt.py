#!/usr/bin/python3.7
import time
import struct
from contextlib import closing
import socket
import ip_utils
from os import getcwd
import sys
sys.path.append(getcwd() + "/../../modules/")


dest_port = 22
src_port = ip_utils.get_free_port()
local_ip = ip_utils.get_local_ip()
dest_ip = "192.168.1.159"
local_ip = dest_ip = "127.0.0.1"
loc_long = ip_utils.dot_form_to_long_form(local_ip)

if loc_long is None:
    exit()
else:
    local_long = int(loc_long)

dst_long = ip_utils.dot_form_to_long_form(dest_ip)
if dst_long is None:
    exit()
else:
    dest_long = int(dst_long)

assert(isinstance(dest_long, int))
SYN = 2
RST = 4
with closing(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)) as s:
    tcp_packet = ip_utils.make_tcp_packet(
        src_port, dest_port, local_long, dest_long, SYN)
    if tcp_packet is not None:
        s.sendto(tcp_packet, (dest_ip, dest_port))
    else:
        print(
            f"Couldn't make TCP packet with supplied arguments:\nsource port: [{src_port}]\ndestination port: [{dest_port}]\nlocal ip: [{local_ip}]\ndestination ip: [{dest_ip}]\nSYN flag: [{SYN}]")
