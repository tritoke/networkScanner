#!/usr/bin/python3.7
from os import getcwd
import sys
sys.path.append(getcwd()+"/../../modules/")

import ip_utils

import socket
from contextlib import closing
import struct
import time

dest_port = 22
src_port = ip_utils.get_free_port()
local_ip = ip_utils.get_local_ip()
dest_ip  = "192.168.1.159"
local_ip = dest_ip = "127.0.0.1"
local_long = ip_utils.dot_form_to_long_form(local_ip)
dest_long = ip_utils.dot_form_to_long_form(dest_ip)
SYN = 2
RST = 4
with closing(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)) as s:
    tcp_packet = ip_utils.make_tcp_packet(src_port, dest_port, local_long, dest_long, SYN)
    s.sendto(tcp_packet, (dest_ip, dest_port))
