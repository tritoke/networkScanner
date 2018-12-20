#!/usr/bin/python3.7
import socket
import struct
import os
import time
import array

def calculateChecksum(pkt): # checksum function from scapy project
    if len(pkt) % 2 == 1: # if packet had odd length pad with a null byte
        pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    # ^^ ones complement sum of the pairs of bytes
    return (((s>>8)&0xff)|s<<8) & 0xffff
    # s >> 8 move the leftmost eight bytes into the first byte
    # and-ing that with 0xFF truncates any data that past the first 8 bytes
    # i.e. 01101001,11110000 => 00000000,01101001
    # or-ing that with s<<8 and then anding it places the second byte in the first places and truncates the remainder, leaving just the two bytes switched


ICMP_ECHO_REQUEST = 8

# opens a raw socket for the ICMP protocol
ping_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# allows manual IP header creation
# ping_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

ID = os.getpid() & 0xFFFF

# the two zeros are the code and the dummy checksum, the one is the sequence number
dummy_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)

data = struct.pack("d", time.time()) + bytes((192 - struct.calcsize("d")) * "A", "ascii")

checksum = socket.htons(calculateChecksum(dummy_header+data))

header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksum, ID, 1)

packet = header + data

ping_sock.sendto(packet, ("127.0.0.1", 1))

