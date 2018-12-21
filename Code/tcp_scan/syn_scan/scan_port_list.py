#!/usr/bin/python3.7
from os import getcwd
import sys
sys.path.append(getcwd()+"/../../modules/")

import ip_utils

import socket
from contextlib import closing
import struct
import time
from typing import List, Tuple, Union, Optional
from multiprocessing import Pool


def syn_listener(address: Tuple[str, int], timeout: int) -> List[int]:
    print(f"address: [{address}]\ntimeout: [{timeout}]")
    open_ports: List[int] = []
    with closing(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)) as s:
        s.bind(address)
        time_remaining = timeout
        print("started listening")
        while True:
            time_taken = ip_utils.wait_for_socket(s, time_remaining)
            if time_taken == -1:
                break
            else:
                time_remaining -= time_taken
            packet = s.recv(1024)
            src_prt, dst_prt, seq, ack, data_offset, flags, window_size, checksum, urg = struct.unpack("!HHIIBBHHH", packet[20:40])
            if flags == int("00010010", 2): # syn ack
                open_ports.append(src_prt)
            else:
                continue
        print("finished listening")
    return open_ports



def syn_scan(dest_ip: Union[str, int], portlist: int) -> Optional[List[int]]:
    src_port = ip_utils.get_free_port()
    local_ip = ip_utils.get_local_ip()

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

    p = Pool(1)
    listener = p.apply_async(syn_listener, ((local_ip, src_port), 5))
    if not ip_utils.is_valid_ip(dest_ip):
        print(f"Invalid IP address to scan: [{dest_ip}].")
        return None
    else:
        if type(dest_ip) == str:
            dst_long = ip_utils.dot_form_to_long_form(dest_ip)
            if type(dst_long) == None:
                print("Failed to convert destination ip to long form.")
                return None
            else:
                dest_long = int(dst_long)
        time.sleep(1)
        print("starting scan")
        for port in portlist:
            pkt = ip_utils.make_tcp_packet(src_port, port, local_long, dest_long, 2) # 2 is TCP flag SYN
            if pkt is None:
                return None
            else:
                packet = bytes(pkt)
            with closing(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)) as s:
                s.sendto(packet, (dest_ip, port))

        print("finished scan")
        p.close()
        p.join()
        open_ports = listener.get()
        print(open_ports)


dest_ip  = "192.168.1.159"

syn_scan(dest_ip, range(2**16))

