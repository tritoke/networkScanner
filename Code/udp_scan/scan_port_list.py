#!/usr/bin/python3.7
from os import getcwd
import sys
sys.path.append(getcwd()+"/../modules/")

import ip_utils

import socket
import struct
from contextlib import closing
from typing import Union, List, Tuple, Set, Optional, Iterator
from functools import reduce
from multiprocessing import Pool
import time
def udp_listener(dest_ip: int, timeout: float) -> Set[int]:
    """
    This listener detects UDP packets from dest_ip in the given timespan, all ports
    that send direct replies are marked as being open.
    Returns a list of open ports.
    """

    time_remaining = timeout
    ports: Set[int] = set()
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
        while True:
            time_taken = ip_utils.wait_for_socket(s, time_remaining)
            if time_taken == -1:
                break
            else:
                time_remaining -= time_taken
            packet = s.recv(1024)
            ip_header, udp_header = packet[:20], packet[20:28]
            ip_hp_ip_v, ip_dscp_ip_ecn, ip_len, ip_id, ip_flgs_ip_off, ip_ttl, ip_p, ip_sum, ip_src, ip_dst = struct.unpack('!BBHHHBBHII', ip_header)
            src_port, dest_port, length, checksum = struct.unpack("!HHHH", udp_header)
            # print(f"ip_p: [{ip_p}]\nip_src: [{ip_utils.long_form_to_dot_form(ip_src)}]\nsrc_port: [{src_port}]\nip_dst: [{ip_utils.long_form_to_dot_form(ip_dst)}]\ndest_port: [{dest_port}]\n")
            # print(f"dest_ip == ip_src || {dest_ip} == {ip_src}")
            if dest_ip == ip_src and ip_p == 17:
                ports |= set([src_port])

    return ports


def icmp_listener(src_ip: Union[str, int], timeout=2) -> Optional[int]:
    """
    This listener detects ICMP destination unreachable packets and returns the icmp code.
    This is later used to mark them as either close, open|filtered, filtered.
    3 -> closed
    0|1|2|9|10|13 -> filtered
    -1 -> error with arguments
    open|filtered means that they are either open or filtered but return nothing.
    """
    src_adr = ip_utils.union_to_int(src_ip)
    if src_adr is not None:
        src_addr = int(src_adr)
    else:
        print(f"Couldn't translate destination ip: [{src_ip}] to long form.")
        return -1

    ping_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    time_remaining = timeout
    code = None
    while True:
        time_waiting = ip_utils.wait_for_socket(ping_sock, time_remaining)
        if time_waiting == -1:
            break
        else:
            time_remaining -= time_waiting
        recPacket, addr = ping_sock.recvfrom(1024)
        ip_header = recPacket[:20]
        ip_hp_ip_v, ip_dscp_ip_ecn, ip_len, ip_id, ip_flgs_ip_off, ip_ttl, ip_p, ip_sum, ip_src, ip_dst = struct.unpack('!BBHHHBBHII', ip_header)
        icmp_header = recPacket[20:28]
        msg_type, icmp_code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)

        # print(f"msg_type: [{msg_type}]\nicmp_code: [{icmp_code}]\n")
        # print(f"ip_src == src_addr || {ip_src} == {src_addr}")

        if ip_src == src_addr and msg_type == 3 and icmp_code in [0, 1, 2, 3, 9, 10, 13]:
            code = icmp_code
            break
        elif time_remaining <= 0:
            break
        else:
            continue
    ping_sock.close()
    return code


def udp_scan(dest_ip: Union[str, int], portlist: List[int]) -> Optional[Tuple[Set[int], Set[int], Set[int], Set[int]]]:
    """
    Takes in a destination IP address in either dot or long form and a list of ports to scan.
    Sends UDP packets to each port specified in portlist and uses the listeners to mark them as open, open|filtered, filteredm, closed
    they are marked open|filtered if no response is recieved at all.
    """

    local_ip = ip_utils.get_local_ip()
    local_port = ip_utils.get_free_port()

    local_ip = dest_ip = "127.0.0.1"
    filtered_ports: Set[int] = set()
    closed_ports: Set[int] = set()

    dest_lng = ip_utils.dot_form_to_long_form(dest_ip)
    if dest_lng is not None:
        dest_long = int(dest_lng)
    else:
        print(f"invalid destination ip: [{dest_ip}].")

    local_lng = ip_utils.dot_form_to_long_form(local_ip)
    if local_lng is not None:
        local_long = int(local_lng)
    else:
        print(f"invalid local ip: [{dest_ip}].")

    p = Pool(1)
    udp_listen = p.apply_async(udp_listener, (dest_long, 4))

    with closing(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)) as s:
        for _ in range(2): # repeat 3 times because UDP is dodgy as
            for dest_port in portlist:
                try:
                    pkt = ip_utils.make_udp_packet(local_port, dest_port, local_long, dest_long)
                    if pkt is not None:
                        packet = bytes(pkt)
                        s.sendto(packet, (dest_ip, dest_port))
                    else:
                        print(f"Error making packet.\nlocal port: [{local_port}]\ndestination port: [{dest_port}]\nlocal ip: [{local_ip}]\ndestination ip: [{dest_ip}]")
                except socket.error:
                    packet_bytes = " ".join(map("{:02x}".format, packet))
                    print(f'The socket modules sendto method with the following argument resulting in a socket error.\npacket: [{packet_bytes}]\naddress: [{dest_ip, dest_port}])')

    p.close()
    p.join()

    open_prts: Set[int] = set(udp_listen.get())
    if open_prts is not None:
        open_ports: Set[int] = set(open_prts)
    # print(open_ports)
    portlist = list(filter(lambda x: x not in open_ports, portlist))
    with closing(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)) as s:
        for dest_port in portlist:
            try:
                pkt = ip_utils.make_udp_packet(local_port, dest_port, local_long, dest_long)
                if pkt is not None:
                    packet = bytes(pkt)
                    p = Pool(1)
                    icmp_listen = p.apply_async(icmp_listener, (dest_long,))
                    time.sleep(1)
                    s.sendto(packet, (dest_ip, dest_port))
                    p.close()
                    p.join()
                    icmp_code = icmp_listen.get()
                    # print(icmp_code)
                    if icmp_code == -1:
                        return None
                    elif icmp_code in [0, 1, 2, 9, 10, 13]:
                        filtered_ports |= set([dest_port])
                    elif icmp_code == 3:
                        closed_ports |= set([dest_port])
                    else:
                        pass
                else:
                    print(f"Error making packet.\nlocal port: [{local_port}]\ndestination port: [{dest_port}]\nlocal ip: [{local_ip}]\ndestination ip: [{dest_ip}]")
            except socket.error:
                packet_bytes = " ".join(map("{:02x}".format, packet))
                print(f'The socket modules sendto method with the following argument resulting in a socket error.\npacket: [{packet_bytes}]\naddress: [{dest_ip, dest_port}])')

    open_filtered_ports = set(portlist) - reduce(lambda a, b: a|b, [open_ports, filtered_ports, closed_ports])
    return (open_ports, open_filtered_ports, filtered_ports, closed_ports)

maybe_ports = udp_scan("127.0.0.1", [22, 68, 53, 6969])
if maybe_ports is not None:
    open_ports, open_filtered_ports, filtered_ports, closed_ports = maybe_ports
    print(f"Open ports: {open_ports}")
    print(f"Open or filtered ports: {open_filtered_ports}")
    print(f"Filtered ports: {filtered_ports}")
    print(f"Closed ports: {closed_ports}")
else:
    print("Something went wrong, check error messages.")
