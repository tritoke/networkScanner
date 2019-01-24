#!/usr/bin/python3.7
from contextlib import closing
import socket
import ip_utils
from os import getcwd
import sys
sys.path.append(getcwd() + "/../modules/")


dest_ip = "192.168.1.1"
dest_port = 68
local_ip = ip_utils.get_local_ip()
local_port = ip_utils.get_free_port()

local_ip = dest_ip = "127.0.0.1"

with closing(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)) as s:
    try:
        pkt = ip_utils.make_udp_packet(
            local_port, dest_port, local_ip, dest_ip)
        if pkt is not None:
            packet = bytes(pkt)
            s.sendto(packet, (dest_ip, dest_port))
        else:
            print(
                f"Error making packet.\nlocal port: [{local_port}]\ndestination port: [{dest_port}]\nlocal ip: [{local_ip}]\ndestination ip: [{dest_ip}]")
    except socket.error:
        print("")
