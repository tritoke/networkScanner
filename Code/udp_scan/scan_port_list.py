#!/usr/bin/python3.7
import ip_utils
import time
from multiprocessing import Pool
from functools import reduce
from typing import List, Tuple, Set
from contextlib import closing
import struct
import socket


def udp_listener(dest_ip: str, timeout: float) -> Set[int]:
    """
    This listener detects UDP packets from dest_ip in the given timespan,
    all ports that send direct replies are marked as being open.
    Returns a list of open ports.
    """

    time_remaining = timeout
    ports: Set[int] = set()
    with socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_UDP
    ) as s:
        while True:
            time_taken = ip_utils.wait_for_socket(s, time_remaining)
            if time_taken == -1:
                break
            else:
                time_remaining -= time_taken
            packet = s.recv(1024)
            ip_header, udp_header = packet[:20], packet[20:28]
            # strip out the IP and UDP header from the packet
            ip_hp_ip_v, ip_dscp_ip_ecn, ip_len, ip_id, ip_flgs_ip_off, ip_ttl,\
                ip_p, ip_sum, ip_src, ip_dst = struct.unpack('!BBHHHBBHII',
                                                             ip_header)
            # unpack the IP header
            src_port, dest_port, length, checksum = struct.unpack(
                "!HHHH", udp_header)
            # unpack the UDP header
            if dest_ip == ip_src and ip_p == 17:
                ports |= set([src_port])

    return ports


def icmp_listener(src_ip: str, timeout=2) -> int:
    """
    This listener detects ICMP destination unreachable
    packets and returns the icmp code.
    This is later used to mark them as either close, open|filtered, filtered.
    3 -> closed
    0|1|2|9|10|13 -> filtered
    -1 -> error with arguments
    open|filtered means that they are either open or
    filtered but return nothing.
    """

    ping_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_ICMP)
    # open raw socket to listen for ICMP destination unrechable packets
    time_remaining = timeout
    code = -1
    while True:
        time_waiting = ip_utils.wait_for_socket(ping_sock, time_remaining)
        # wait for socket to be readable
        if time_waiting == -1:
            break
        else:
            time_remaining -= time_waiting
        recPacket, addr = ping_sock.recvfrom(1024)
        # recieve the packet
        ip_header = recPacket[:20]
        ip_hp_ip_v, ip_dscp_ip_ecn, ip_len, ip_id, ip_flgs_ip_off, ip_ttl,\
            ip_p, ip_sum, ip_src, ip_dst = struct.unpack('!BBHHHBBHII',
                                                         ip_header)
        icmp_header = recPacket[20:28]
        msg_type, icmp_code, checksum, p_id, sequence = struct.unpack(
            'bbHHh', icmp_header)
        # unpack the UDP and IP headers
        if ip_src == src_ip and msg_type == 3 and icmp_code in [
                0, 1, 2, 3, 9, 10, 13]:
            code = icmp_code
            break
        elif time_remaining <= 0:
            break
        else:
            continue
    ping_sock.close()
    return code


def udp_scan(dest_ip: str,
             portlist: List[int]) -> Tuple[Set[int],
                                           Set[int],
                                           Set[int],
                                           Set[int]]:
    """
    Takes in a destination IP address in either dot or long form and
    a list of ports to scan. Sends UDP packets to each port specified
    in portlist and uses the listeners to mark them as open, open|filtered,
    filtered, closed they are marked open|filtered if no response is
    recieved at all.
    """

    local_ip = ip_utils.get_local_ip()
    local_port = ip_utils.get_free_port()
    # get local ip address and port number
    filtered_ports: Set[int] = set()
    closed_ports: Set[int] = set()

    p = Pool(1)
    udp_listen = p.apply_async(udp_listener, (dest_ip, 4))
    # start the UDP listener
    with closing(
            socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_UDP
            )
    ) as s:
        for _ in range(2):
            # repeat 3 times because UDP scanning comes
            # with a high chance of packet loss
            for dest_port in portlist:
                try:
                    packet = ip_utils.make_udp_packet(
                        local_port, dest_port, local_ip, dest_ip)
                    # create the UDP packet to send
                    s.sendto(packet, (dest_ip, dest_port))
                    # send the packet to the currently scanning address
                except socket.error:
                    packet_bytes = " ".join(map("{:02x}".format, packet))
                    print(
                        "The socket modules sendto method with the following",
                        "argument resulting in a socket error.",
                        f"\npacket: [{packet_bytes}]\n",
                        "address: [{dest_ip, dest_port}])"
                    )

    p.close()
    p.join()

    open_ports: Set[int] = set(udp_listen.get())

    portlist = list(filter(lambda x: x not in open_ports, portlist))
    # only scan the ports which we know are not open
    with closing(
            socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_UDP
            )
    ) as s:
        for dest_port in portlist:
            try:
                packet = ip_utils.make_udp_packet(
                    local_port, dest_port, local_ip, dest_ip)
                # make a new UDP packet
                p = Pool(1)
                icmp_listen = p.apply_async(icmp_listener, (dest_ip,))
                # start the ICMP listener
                time.sleep(1)
                s.sendto(packet, (dest_ip, dest_port))
                # send packet
                p.close()
                p.join()
                icmp_code = icmp_listen.get()
                # recieve ICMP code from the ICMP listener
                if icmp_code in [0, 1, 2, 9, 10, 13]:
                    filtered_ports |= set([dest_port])
                elif icmp_code == 3:
                    closed_ports |= set([dest_port])
            except socket.error:
                packet_bytes = " ".join(map("{:02x}".format, packet))
                ip_utils.eprint(
                    "The socket modules sendto method with the following",
                    "argument resulting in a socket error.",
                    f"\npacket: [{packet_bytes}]\n",
                    "address: [{dest_ip, dest_port}])"
                )
    # this creates a new set which contains all the elements that
    # are in the list of ports to be scanned but have not yet
    # been classified
    open_filtered_ports = set(portlist) - reduce(lambda a, b: a | b,
                                                 [
                                                     open_ports,
                                                     filtered_ports,
                                                     closed_ports
                                                 ]
                                                 )
    # set comprehension to update the list of open filtered ports
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
