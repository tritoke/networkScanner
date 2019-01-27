#!/usr/bin/python3.7
from multiprocessing import Pool
from typing import List, Tuple, Iterable
import struct
from contextlib import closing
import socket
import ip_utils


def syn_listener(address: Tuple[str, int], timeout: float) -> List[int]:
    """
    This function is run asynchronously and listens for
    TCP ACK responses to the sent TCP SYN msg.
    """
    print(f"address: [{address}]\ntimeout: [{timeout}]")
    open_ports: List[int] = []
    with closing(
            socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_TCP
            )) as s:
        s.bind(address)
        # bind the raw socket to the listening address
        time_remaining = timeout
        print("started listening")
        while True:
            time_taken = ip_utils.wait_for_socket(s, time_remaining)
            # wait for the socket to become readable
            if time_taken == -1:
                break
            else:
                time_remaining -= time_taken
            packet = s.recv(1024)
            # recieve the packet data
            src_prt, dst_prt, seq, ack, data_offset, flags, window_size,\
                checksum, urg = struct.unpack("!HHIIBBHHH", packet[20:40])
            # unpack the data from the TCP header section
            if flags == int("00010010", 2):  # syn ack
                open_ports.append(src_prt)
                # check that the header contained the TCP ACK flag and if it
                # did append it
            else:
                continue
        print("finished listening")
    return open_ports


def syn_scan(dest_ip: str, portlist: Iterable[int]) -> List[int]:
    src_port = ip_utils.get_free_port()
    # request a local port to connect from
    local_ip = ip_utils.get_local_ip()
    p = Pool(1)
    listener = p.apply_async(syn_listener, ((local_ip, src_port), 5))
    # start the TCP ACK listener in the background
    print("starting scan")
    for port in portlist:
        packet = ip_utils.make_tcp_packet(src_port, port, local_ip, dest_ip, 2)
        # create a TCP packet with the syn flag
        with closing(
                socket.socket(
                    socket.AF_INET,
                    socket.SOCK_RAW,
                    socket.IPPROTO_TCP
                )
        ) as s:
            s.sendto(packet, (dest_ip, port))
            # send the packet to its destination

    print("finished scan")
    p.close()
    p.join()
    open_ports = listener.get()
    # collect the list of ports that responded to the TCP SYN message
    print(open_ports)
    return open_ports


dest_ip = "127.0.0.1"

syn_scan(dest_ip, range(2**16))
