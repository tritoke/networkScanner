#!/usr/bin/env python
from modules import headers
from modules import ip_utils
import socket
import struct
import time
from contextlib import closing
from itertools import repeat
from math import log10, floor
from multiprocessing import Pool
from os import getpid
from typing import Set, Tuple


def sig_figs(x: float, n: int) -> float:
    """
    rounds x to n significant figures.
    sig_figs(1234, 2) = 1200.0
    """
    return round(x, n - (1 + int(floor(log10(abs(x))))))


def ping_listener(
        ID: int,
        timeout: float
) -> Set[Tuple[str, float, headers.ip]]:
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
    addresses = set()
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
        ip = headers.ip(recPacket[:20])
        # unpack the IP header into its respective components
        icmp = headers.icmp(recPacket[20:28])
        # unpack the time from the packet.
        time_sent = struct.unpack(
            "d",
            recPacket[28:28 + struct.calcsize("d")]
        )[0]
        # unpack the value for when the packet was sent
        time_taken: float = time_recieved - time_sent
        # calculate the round trip time taken for the packet
        if icmp.id == ID:
            # if the ping was sent from this machine then add it to the list of
            # responses
            ip_address, port = addr
            addresses.add((ip_address, time_taken, ip))
        elif time_remaining <= 0:
            break
        else:
            continue
    # return a list of all the addesses that replied to our ICMP echo request.
    return addresses


def main() -> None:
    with closing(
            socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_ICMP
            )
    ) as ping_sock:
        ip_addresses = ip_utils.ip_range("192.168.1.0", 24)
        # generate the range of IP addresses to scan.
        local_ip = ip_utils.get_local_ip()

        # get the local ip address
        addresses = [
            ip
            for ip in ip_addresses
            if (
                not ip.endswith(".0")
                and not ip.endswith(".255")
                and ip != local_ip
            )
        ]

        # initialise a process pool
        p = Pool(1)
        # get the local process id for use in creating packets.
        ID = getpid() & 0xFFFF
        # run the listeners.ping function asynchronously
        replied = p.apply_async(ping_listener, (ID, 5))
        for address in zip(addresses, repeat(1)):
            try:
                packet = ip_utils.make_icmp_packet(ID)
                ping_sock.sendto(packet, address)
            except PermissionError:
                ip_utils.eprint("raw sockets require root priveleges, exiting")
                exit()
        p.close()
        p.join()
        # close and join the process pool to so that all the values
        # have been returned and the pool closed
        hosts_up = replied.get()
        # get the list of addresses that replied to the echo request from the
        # listener function
        print("\n".join(
            f"host: [{host}]\t" +
            "responded to an ICMP ECHO REQUEST in " +
            f"{str(sig_figs(taken, 2))+'s':<10s} " +
            f"ttl: [{ip_head.time_to_live}]"
            for host, taken, ip_head in hosts_up
        ))
