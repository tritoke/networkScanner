#!/usr/bin/python

import socket
import struct

# socket object using an IPV4 address, using only raw socket access, set ICMP protocol        
ping_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# this line sets the IP_HDRINCL attribute in SOL_IP to 1 allowing us to manually create IP headers.
ping_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
packets = []

# capture 6 packets
while len(packets) < 4:
    recPacket, addr = ping_sock.recvfrom(1024)
    ip_header = recPacket[:20]
    icmp_header = recPacket[20:28]
    VER_IHL, DSCP_ECN, p_len, ID, F_FO, ttl, prot, csum, src_ip_long, dest_ip_long = struct.unpack('bbHHHBBHLL', ip_header)
    ver_ihl = "{:08b}".format(VER_IHL)
    VER = int(ver_ihl[:4], 2)
    IHL = int(ver_ihl[4:], 2)  
    dscp_ecn = "{:08b}".format(DSCP_ECN)
    DSCP = int(dscp_ecn[:6], 2)
    ECN = int(dscp_ecn[6:], 2)
    f_fo = "{:016b}".format(F_FO)
    FLAGS = int(f_fo[:3], 2)
    FRAG_OFFSET = int(f_fo[3:], 2)
    src_ip = socket.inet_ntoa(struct.pack('=i', src_ip_long))
    dest_ip = socket.inet_ntoa(struct.pack('=i', dest_ip_long))
    print("IP header:")
    print("version: [{}]\nheader length: [{}]\ndscp: [{}]\necn: [{}]\ntotal length: [{}]\nidentification: [{}]\nflags: [{}]\nfragment offset: [{}]\nttl: [{}]\nprot: [{}]\nchecksum: [{}]\nsource address: [{}]\ndestination address: [{}]".format(VER, IHL, DSCP, ECN, p_len, ID, FLAGS, FRAG_OFFSET, ttl, prot, csum, src_ip, dest_ip))
    print()
    msg_type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    print("ICMP header:")
    print("type: [{}]\ncode: [{}]\nchecksum: [{}]\np_id: [{}]\nsequence: [{}]".format(msg_type, code, checksum, p_id, sequence)) 
    packets.append(recPacket)
    print("\n")

