#!/usr/bin/env python
import ip_utils
import struct
import socket
import time
from contextlib import closing
from itertools import repeat
from math import log10, floor
from multiprocessing import Pool
from os import getpid
from typing import List, Tuple


def round_significant_figures(x: float, n: int) -> float:
    """
    rounds x to n significant figures.
    round_significant_figures(1234, 2) = 1200.0
    """
    return round(x, n - (1 + int(floor(log10(abs(x))))))


def recieved_ping_from_addresses(
        ID: int, timeout: float) -> List[Tuple[str, float, int]]:
    """
    Takes in a process id and a timeout and returns
    a list of addresses which sent ICMP ECHO REPLY
    packets with the packed id matching ID in the time given by timeout.
    """
    ping_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_ICMP)
    # opens a raw socket for sending ICMP protocol packets
    time_remaining = timeout
    addresses = []
    while True:
        time_waiting = ip_utils.wait_for_socket(ping_sock, time_remaining)
        # time_waiting stores the time the socket took to become readable
    # or returns minus one if it ran out of time

        if time_waiting == -1:
            break
        time_recieved = time.time()
        # store the time the packet was recieved
        recPacket, addr = ping_sock.recvfrom(1024)
        # recieve the packet
        ip_header = recPacket[:20]
        # split the IP header from the packet
        ip_hp_ip_v, ip_dscp_ip_ecn, ip_len, ip_id, ip_flgs_ip_off, ip_ttl,\
            ip_p, ip_sum, ip_src, ip_dst = struct.unpack('!BBHHHBBHII',
                                                         ip_header)
        # unpack the IP header into its respective components
        icmp_header = recPacket[20:28]
        # split the ICMP header from the packet
        msg_type, code, checksum, p_id, sequence = struct.unpack(
            'bbHHh', icmp_header)
        # unpack the ICMP header
        time_remaining -= time_waiting
        # decrease the amount of time remaining to wait for by the amount of
        # time spent waiting
        time_sent = struct.unpack(
            "d", recPacket[28:28 + struct.calcsize("d")])[0]
        # unpack the value for when the packet was sent
        time_taken: float = time_recieved - time_sent
        # calculate the round trip time taken for the packet
        if p_id == ID:
            # if the ping was sent from this machine then add it to the list of
            # responses
            ip, port = addr
            addresses.append((str(ip), float(time_taken), int(ip_ttl)))
        elif time_remaining <= 0:
            break
        else:
            continue
    # return a list of all the addesses that replied to our ICMP echo request.
    return addresses


with closing(
        socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_ICMP
        )
) as ping_sock:
    subnet_spec = ("192.168.1.0", 24)
    # subnet mask to scan
    ip_addresses = ip_utils.ip_range(*subnet_spec)
    # generate the range of IP addresses to scan.
    local_ip = ip_utils.get_local_ip()
    # get the local ip address
    addresses = list(filter(lambda x: not x.endswith(".0")
                            and not x.endswith(".255")
                            and x != local_ip,
                            ip_addresses))

    # initialise a process pool
    p = Pool(1)
    # get the local process id for use in creating packets.
    ID = getpid() & 0xFFFF
    # run the recieved_ping_from_addresses function asynchronously
    replied = p.apply_async(recieved_ping_from_addresses, (ID, 2))
    for address in zip(addresses, repeat(1)):
        try:
            packet = ip_utils.make_icmp_packet(ID)
            print(f"scanning {address}")
            ping_sock.sendto(packet, address)
        except PermissionError:
            ip_utils.eprint("raw sockets require root priveleges, exiting")
            raise
    p.close()
    p.join()
    # close and join the process pool to so that all the values
    # have been returned and the pool closed
    hosts_up = replied.get()
    # get the list of addresses that replied to the echo request from the
    # listener function
    print("\n".join(
        map(lambda x: f"host: [{x[0]}]\t" +
            "responded to an ICMP ECHO REQUEST in " +
            f"{str(round_significant_figures(x[1], 2))+ 's':<10s} " +
            f"ttl: [{x[2]}]",
            hosts_up
            )))
    # print the results nice, though with
