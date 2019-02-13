#!/usr/bin/env python

import array
import socket
import struct
import select
import time

from contextlib import closing
from itertools import islice, cycle
from sys import stderr
from typing import List, Union


def eprint(*args, **kwargs):
    """
    Mirrors print exactly but prints to stderr
    instead of stdout.
    """
    print(*args, file=stderr, **kwargs)


def long_to_dot(long: int) -> str:
    """
    Take in an IP address in packed 32 bit int form
    and return that address in dot notation.
    i.e. long_form_to_dot_form(0x7F000001) = 127.0.0.1
    """
    # these are long form values for 0.0.0.0
    # and 255.255.255.255
    if not 0 <= long <= 0xFFFFFFFF:
        raise ValueError(f"Invalid long form IP address: [{long:08x}]")
    else:
        # shift the long form IP along 0, 8, 16, 24 bits
        # take only the first 8 bits of the newly shifted number
        # cast them to a string and join them with '.'s
        return ".".join(
            str(
                (long >> (8*(3-i))) & 0xFF
            )
            for i in range(4)
        )


def dot_to_long(ip: str) -> int:
    """
    Take an ip address in dot notation and return the packed 32 bit int version
    i.e. dot_form_to_long_form("127.0.0.1") = 0x7F000001
    """
    # dot form ips: a.b.c.d must have each
    # part (a,b,c,d) between 0 and 255,
    # otherwise they are invalid

    parts = [int(i) for i in ip.split(".")]

    if not all(
            0 <= int(i) <= 255
            for i in parts
    ):
        raise ValueError(f"Invalid dot form IP address: [{ip}]")

    else:
        # for each part of the dotted IP address
        # bit shift left each part by eight times
        # three minus it's position. This puts the bits
        # from each part in the right place in the final sum
        # a.b.c.d -> a<<3*8 + b<<2*8 + c<<1*8 + d<<0*8
        return sum(
            part << ((3-i)*8)
            for i, part in enumerate(parts)
        )


def is_valid_ip(ip: Union[int, str]) -> bool:
    """
    checks whether a given IP address is valid.
    """

    if isinstance(ip, int):
        try:
            dot_form = long_to_dot(ip)
        except ValueError:
            return False
    else:
        dot_form = str(ip)

    try:
        socket.inet_aton(dot_form)
        return True
    except socket.error:
        return False


def is_valid_port_number(port_num: int) -> bool:
    """
    Checks whether the given port number is valid i.e. between 0 and 65536.
    """
    if 0 <= port_num < 2**16:
        return True
    else:
        return False


def ip_range(ip: str, network_bits: int) -> List[str]:
    """
    Takes a Classless Inter Domain Routing(CIDR) address subnet
    specification and returns the list of addresses specified
    by the IP/network bits format.
    If the number of network bits is not between 0 and 32 it raises an error.
    If the IP address is invalid according to is_valid_ip it raises an error.
    """

    if not 0 <= network_bits <= 32:
        raise ValueError(f"Invalid number of network bits: [{network_bits}]")

    if not is_valid_ip(ip):
        raise ValueError(f"Invalid IP address: [{ip}]")

    ip_long = dot_to_long(ip)

    mask = int(f"{'1'*network_bits:0<32s}", 2)
    lower_bound = ip_long & mask
    upper_bound = ip_long | (mask ^ 0xFFFFFFFF)

    return list(map(
        long_to_dot,
        range(lower_bound, upper_bound + 1)
    ))


def get_local_ip() -> str:
    """
    Connects to the router with UDP and gets the local IP specified by
    the router or google. takes no argument
    """

    with closing(
            socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )
    ) as s:
        s.connect(("google.com", 80))
        ip, _ = s.getsockname()
    return ip


def get_free_port() -> int:
    """
    Attempts to bind to port 0 which assigns a free port number to the socket,
    the socket is then closed and the port number assigned is returned.
    """

    with closing(
            socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
    ) as s:
        s.bind(('', 0))
        _, port = s.getsockname()
    return port


def ip_checksum(pkt: bytes) -> int:
    """
    ip_checksum takes a packet and calculates the IP checksum
    for the given packet.
    This checksum function is taken from the scapy python library
    which is released under the open source GPLV2.
    """

    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return (((s >> 8) & 0xff) | s << 8) & 0xffff


def make_icmp_packet(ID: int) -> bytes:
    """
    Takes an argument of the process ID of the calling process.
    Returns an ICMP ECHO REQUEST packet created with this ID
    """

    ICMP_ECHO_REQUEST = 8
    dummy_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
    time_bytes = struct.pack("d", time.time())
    bytes_to_repeat_in_data = map(ord, " y33t ")
    data_bytes = (192 - struct.calcsize("d"))
    data = time_bytes + \
        bytes(islice(cycle(bytes_to_repeat_in_data), data_bytes))
    checksum = socket.htons(ip_checksum(dummy_header + data))
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksum, ID, 1)
    packet = header + data
    return packet


def make_tcp_packet(
        src: int,
        dst: int,
        from_address: str,
        to_address: str,
        flags: int) -> bytes:
    """
    Takes in the source and destination port/ip address
    returns a tcp packet.
    flags:
    2 => SYN
    18 => SYN:ACK
    4 => RST
    """

    if flags not in {2, 18, 4}:
        raise ValueError(
            f"Flags must be one of 2:SYN, 18:SYN,ACK, 4:RST. not: [{flags}]"
        )
    if not is_valid_ip(from_address):
        raise ValueError(
            f"Invalid source IP address: [{from_address}]"
        )
    if not is_valid_ip(to_address):
        raise ValueError(
            f"Invalid destination IP address: [{to_address}]"
        )
    if not is_valid_port_number(src):
        raise ValueError(
            f"Invalid source port: [{src}]"
        )
    if not is_valid_port_number(dst):
        raise ValueError(
            f"Invalid destination port: [{dst}]"
        )

    src_addr = dot_to_long(from_address)
    dst_addr = dot_to_long(to_address)

    seq = ack = urg = 0
    data_offset = 6 << 4
    window_size = 1024
    max_segment_size = (2, 4, 1460)

    dummy_header = struct.pack(
        "!HHIIBBHHHBBH",
        src,
        dst,
        seq,
        ack,
        data_offset,
        flags,
        window_size,
        0,
        urg,
        *max_segment_size
    )
    psuedo_header = struct.pack(
        "!IIBBH",
        src_addr,
        dst_addr,
        0,
        6,
        len(dummy_header)
    )
    checksum = ip_checksum(psuedo_header + dummy_header)

    packet = struct.pack(
        "!HHIIBBHHHBBH",
        src,
        dst,
        seq,
        ack,
        data_offset,
        flags,
        window_size,
        checksum,
        urg,
        *max_segment_size
    )

    return packet


def make_udp_packet(
        src: int,
        dst: int,
        from_address: str,
        to_address: str
) -> bytes:
    """
    Takes in: source IP address and port, destination IP address and port.
    Returns: a UDP packet with those properties.
    the IP addresses are needed for calculating the checksum.
    """

    if not is_valid_ip(from_address):
        raise ValueError(
            f"Invalid source IP address: [{from_address}]"
        )
    if not is_valid_ip(to_address):
        raise ValueError(
            f"Invalid destination IP address: [{to_address}]"
        )
    if not is_valid_port_number(src):
        raise ValueError(
            f"Invalid source port: [{src}]"
        )
    if not is_valid_port_number(dst):
        raise ValueError(
            f"Invalid destination port: [{dst}]"
        )

    UDP_length = 8
    dummy_header = struct.pack(
        "!HHHH",
        src,
        dst,
        UDP_length,
        0
    )
    # 17 is the UDP protocol number
    psuedo_header = struct.pack(
        "!IIBBH",
        src,
        dst,
        0,
        17,
        len(dummy_header)
    )

    checksum = ip_checksum(psuedo_header + dummy_header)

    return struct.pack(
        "!HHHH",
        src,
        dst,
        UDP_length,
        checksum
    )


def wait_for_socket(sock: socket.socket, wait_time: float) -> float:
    """
    Wait for wait_time seconds or until the socket is readable.
    If the socket is readable return a tuple of the socket and the time taken
    otherwise return None.
    """

    start = time.time()
    is_socket_readable = select.select([sock], [], [], wait_time)
    taken = time.time() - start
    if is_socket_readable[0] == []:
        return float(-1)
    else:
        return taken


if __name__ == "__main__":
    print(dot_to_long("127.0.0.1"))
    print(long_to_dot(dot_to_long("127.0.0.1")))
    print(long_to_dot(0x7F000001))
