#!/usr/bin/python3.7
import socket
from contextlib import closing
from typing import Optional, List, Tuple, Union


def long_form_to_dot_form(long: int) -> Optional[str]:
    """
    Take in an IP address in packed 32 bit int form and return that address in dot notation.
    i.e. long_form_to_dot_form(0x7F000001) = 127.0.0.1
    """
    if not (0 <= long <= 0xFFFFFFFF):
        print(f"invalid long form IP: [{long}]")
        return None
    else:
        ip_str = f"{long:032b}"
        return ".".join(str(int(ip_str[i:i+8], 2)) for i in range(0, 32, 8))


def dot_form_to_long_form(ip: str) -> Optional[int]:
    """
    Take an ip address in dot notation and return the packed 32 bit int version
    i.e. dot_form_to_long_form("127.0.0.1") = 0x7F000001
    """
    if not is_valid_ip(ip):
        print(f"Invalid dot form IP: [{ip}]")
        return None
    else:
        return int("".join(map(lambda x: f"{int(x):08b}", ip.split("."))), 2)


def is_valid_ip(ip: Union[int, str]) -> bool:
    """
    does what it says on the tin, checks the validity of an IP address in either long or dot form.
    """

    import socket

    if type(ip) != str:
        dot_form = long_form_to_dot_form(int(ip))
    else:
        dot_form = str(ip)
    if dot_form is None:
        return False
    else:
        ip_str = str(dot_form)

    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False

def ip_range(ip_subnet: str) -> Optional[List[str]]:
    """
    Takes a Classless Inter Domain Routing(CIDR) address subnet specification and returns
    the list of addresses specified by the IP/network bits.
    If it cannot find a CIDR form IP in the ip_subnet variable it returns None.
    If the number of network bits is not between 0 and 32 it returns None.
    If the IP address is invalid according to is_valid_ip it returns None.
    """

    import re

    cidr_form_regex = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}")

    if cidr_form_regex.match(ip_subnet):
        cidr_search = cidr_form_regex.search(ip_subnet)
        if cidr_search is not None:
            ip, n_bits = cidr_search.group().split("/")
        else:
            print(f"Failed to group regex thing: {ip_subnet}")
            return None
    else:
        print(f"Regex couldn't identify the ip address and subnet of {ip_subnet}, ensure that it is in CIDR form.")
        return None

    try:
        network_bits = int(n_bits)
    except ValueError:
        print(f"Invalid address specification: {ip_subnet} subnet must be an integer between 0 and 32.")
        return None

    if not is_valid_ip(ip):
        print(f"Invalid IP address: {ip}.")
        return None

    ip_long = dot_form_to_long_form(ip)
    if ip_long is None:
        return None
    else:
        ip_long_form = int(ip_long)

    subnet_long_form = int(("1"*network_bits).zfill(32)[::-1], 2)
    lower_bound = ip_long_form & subnet_long_form
    upper_bound = ip_long_form | (subnet_long_form ^ 0xFFFFFFFF)
    ips = map(long_form_to_dot_form, range(lower_bound, upper_bound+1))

    if None in ips:
        print("Failed to create ip range because one of the IP's specificed couldn't be turned from long form to dot form.")
        return None
    else:
        return list(map(str, ips))


def get_local_ip() -> str:
    """
    Connects to the router with UDP and gets the local IP specified by the router.
    takes no argument
    """

    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        s.connect(("192.168.1.1", 0))
        ip = s.getsockname()[0]
    return ip


def get_free_port() -> int:
    """
    Attempts to bind to port 0 which assigns a free port number to the socket,
    the socket is then closed and the port number assigned is returned.
    """

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        port_num = s.getsockname()[1]
    return port_num


def ip_checksum(pkt: bytes) -> int:
    """
    ip_checksum takes a packet and calculates the IP checksum for the given packet.
    This checksum is the returned.
    """

    import array

    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return (((s>>8)&0xff)|s<<8) & 0xffff


def make_icmp_packet(ID: int) -> bytes:
    """
    Takes an argument of the process ID of the calling process.
    Returns an ICMP ECHO REQUEST packet created with this ID
    """

    import struct
    import time
    import socket
    from itertools import islice, cycle

    ICMP_ECHO_REQUEST = 8
    dummy_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
    time_bytes = struct.pack("d", time.time())
    bytes_to_repeat_in_data = map(ord, " y33t ")
    data_bytes = (192 - struct.calcsize("d"))
    data = time_bytes + bytes(islice(cycle(bytes_to_repeat_in_data), data_bytes))
    checksum = socket.htons(ip_checksum(dummy_header+data))
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksum, ID, 1)
    packet = header + data
    return packet


def make_tcp_packet(src_port: int, dst_port: int, from_address: Union[int, str], to_address: Union[int, str], flags: int) -> Optional[bytes]:
    """
    Takes in the source and destination port/ip address and returns a tcp packet.
    flags: 2 => SYN, 18 => SYN:ACK, 4 => RST
    """

    import struct
    import socket

    if flags not in [2, 18, 4]:
        print("flags must be one of 2:SYN, 18:SYN,ACK, 4:RST")
        return None
    else:
        if not all(map(is_valid_ip, (from_address, to_address))):
            print(f"ensure that both IP addresses passed to the function are valid: {from_address}, {to_address}")
            return None

        if type(from_address) == str:
            src_addr = dot_form_to_long_form(str(from_address))
        else:
            src_addr = int(from_address)

        if type(to_address) == str:
            dst_addr = dot_form_to_long_form(str(to_address))
        else:
            dst_addr = int(to_address)
        seq = ack = urg = 0
        data_offset = 6
        data_offset = int(f"{data_offset:04b}0000", 2)
        window_size = 1024
        max_segment_size = (2, 4, 1460)
        dummy_header_fields = (src_port, dst_port, seq, ack, data_offset, flags, window_size, 0, urg, *max_segment_size)
        dummy_header = struct.pack("!HHIIBBHHHBBH", *dummy_header_fields)
        psuedo_header_fields = (src_addr, dst_addr, 0, 6, len(dummy_header))
        psuedo_header = struct.pack("!IIBBH", *psuedo_header_fields)
        checksum = ip_checksum(psuedo_header + dummy_header)
        actual_header_fields = (src_port, dst_port, seq, ack, data_offset, flags, window_size, checksum, urg, *max_segment_size)
        actual_tcp_header = struct.pack("!HHIIBBHHHBBH", *actual_header_fields)
        # below line should be 0 use for checking checksum/network byte order.
        # print(ip_checksum(psuedo_header + actual_tcp_header))
        return actual_tcp_header

def wait_for_socket(sock: socket.socket, wait_time: float) -> float:
    """
    Wait for wait_time seconds or until the socket is readable.
    If the socket is readable return a tuple of the socket and the time taken
    otherwise return None.
    """

    import time
    import select

    start = time.time()
    is_socket_readable = select.select([sock], [], [], wait_time)
    taken = time.time() - start
    if is_socket_readable[0] == []:
        return float(-1)
    else:
        return taken

