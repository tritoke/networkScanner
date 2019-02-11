#!/usr/bin/env python

import socket
import struct
from typing import List

# socket object using an IPV4 address, using only raw socket access, set
# ICMP protocol
ping_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

packets: List[bytes] = []

while len(packets) < 1:
    recPacket, addr = ping_sock.recvfrom(1024)
    ip_header = recPacket[:20]
    icmp_header = recPacket[20:28]

    ip_hp_ip_v, ip_dscp_ip_ecn, ip_len, ip_id, ip_flgs_ip_off, ip_ttl,\
        ip_p, ip_sum, ip_src, ip_dst = struct.unpack('!BBHHHBBHII',
                                                     ip_header)
    # the above line deconstructs the ip_header variable into its component
    # parts
    hl_v = f"{ip_hp_ip_v:08b}"
    ip_v = int(hl_v[:4], 2)
    ip_hl = int(hl_v[4:], 2)
    # splits hl_v in ip_v and ip_hl which store the IP version number and
    # header length respectively
    dscp_ecn = f"{ip_dscp_ip_ecn:08b}"
    ip_dscp = int(dscp_ecn[:6], 2)
    ip_ecn = int(dscp_ecn[6:], 2)
    # splits dscp_ecn into ip_dscp and ip_ecn which are two of the compenents
    # in an IP header
    flgs_off = f"{ip_flgs_ip_off:016b}"
    ip_flgs = int(flgs_off[:3], 2)
    ip_off = int(flgs_off[3:], 2)
    # splits flgs_off into ip_flgs and ip_off which represent the ip header
    # flags and the data offset
    src_addr = socket.inet_ntoa(struct.pack('!I', ip_src))
    dst_addr = socket.inet_ntoa(struct.pack('!I', ip_dst))
    # parses the source and destination of each IP address

    print("IP header:",
          f"Version: [{ip_v}]",
          f"Internet Header Length: [{ip_hl}]",
          f"Differentiated Services Point Code: [{ip_dscp}]",
          f"Explicit Congestion Notification: [{ip_ecn}]",
          f"Total Length: [{ip_len}]",
          f"Identification: [{ip_id:04x}]",
          f"Flags: [{ip_flgs:03b}]",
          f"Fragment Offset: [{ip_off}]",
          f"Time To Live: [{ip_ttl}]",
          f"Protocol: [{ip_p}]",
          f"Header Checksum: [{ip_sum:04x}]",
          f"Source Address: [{src_addr}]",
          f"Destination Address: [{dst_addr}]",
          sep="\n")

    msg_type, code, checksum, p_id, sequence = struct.unpack('!bbHHh',
                                                             icmp_header)
    print("ICMP header:", f"Type: [{msg_type}]",
          f"Code: [{code}]",
          f"Checksum: [{checksum:04x}]",
          f"Process ID: [{p_id:04x}]",
          f"Sequence: [{sequence}]",
          sep="\n")

    packets.append(recPacket)

open("current_packet", "w").write("\n".join(
    " ".join(map(lambda x: "{x:02x}", map(int, i))) for i in packets))
