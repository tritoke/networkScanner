import socket
import struct
# socket object using an IPV4 address, using only raw socket access, set ICMP protocol        
ping_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# this line sets the IP_HDRINCL attribute in SOL_IP to 1 allowing us to manually create IP headers.
ping_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

while 1:
    recPacket, addr = s.recvfrom(1024)
    icmp_header = recPacket[20:28]
    msg_type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    print "type: [" + str(msg_type) + "] code: [" + str(code) + "] checksum: [" + str(checksum) + "] p_id: [" + str(p_id) + "] sequence: [" + str(sequence) + "]"
