import struct
import socket
from typing import Dict


class ip_header:
    """
    A class for parsing, storing and displaying
    data from an IP header.
    """
    def __init__(self, header: bytes):
        # first unpack the IP header
        (
            ip_hp_ip_v,
            ip_dscp_ip_ecn,
            ip_len,
            ip_id,
            ip_flgs_ip_off,
            ip_ttl,
            ip_p,
            ip_sum,
            ip_src,
            ip_dst
        ) = struct.unpack('!BBHHHBBHII', header)
        # now deal with the sub-byte sized components
        hl_v = f"{ip_hp_ip_v:08b}"
        ip_v = int(hl_v[:4], 2)
        ip_hl = int(hl_v[4:], 2)
        # splits hl_v in ip_v and ip_hl which store the IP version number and
        # header length respectively
        dscp_ecn = f"{ip_dscp_ip_ecn:08b}"
        ip_dscp = int(dscp_ecn[:6], 2)
        ip_ecn = int(dscp_ecn[6:], 2)
        # splits dscp_ecn into ip_dscp and ip_ecn
        # which are two of the compenents
        # in an IP header
        flgs_off = f"{ip_flgs_ip_off:016b}"
        ip_flgs = int(flgs_off[:3], 2)
        ip_off = int(flgs_off[3:], 2)
        # splits flgs_off into ip_flgs and ip_off which represent the ip header
        # flags and the data offset
        src_addr = socket.inet_ntoa(struct.pack('!I', ip_src))
        dst_addr = socket.inet_ntoa(struct.pack('!I', ip_dst))
        self.version: int = ip_v
        self.header_length: int = ip_hl
        self.dscp: int = ip_dscp
        self.ecn: int = ip_ecn
        self.len: int = ip_len
        self.id: int = ip_id
        self.flags: int = ip_flgs
        self.data_offset: int = ip_off
        self.time_to_live: int = ip_ttl
        self.protocol: int = ip_p
        self.checksum: int = ip_sum
        self.source: str = src_addr
        self.destination: str = dst_addr

    def __repr__(self):
        return "\n\t".join((
            "IP header:",
            f"Version: [{self.version}]",
            f"Internet Header Length: [{self.header_length}]",
            f"Differentiated Services Point Code: [{self.dscp}]",
            f"Explicit Congestion Notification: [{self.ecn}]",
            f"Total Length: [{self.len}]",
            f"Identification: [{self.id:04x}]",
            f"Flags: [{self.flags:03b}]",
            f"Fragment Offset: [{self.data_offset}]",
            f"Time To Live: [{self.time_to_live}]",
            f"Protocol: [{self.protocol}]",
            f"Header Checksum: [{self.checksum:04x}]",
            f"Source Address: [{self.source}]",
            f"Destination Address: [{self.destination}]"
        ))


class icmp_header:
    """
    A class for parsing, storing and displaying
    data from an IP header.
    """
    # relates the type and code to the message
    messages: Dict[int, Dict[int, str]] = {
        0: {
            0: "Echo reply."
        },
        3: {
            0: "Destination network unreachable.",
            1: "Destination host unreachable",
            2: "Destination protocol unreachable",
            3: "Destination port unreachable",
            4: "Fragmentation required, and DF flag set.",
            5: "Source route failed.",
            6: "Destination network unknown.",
            7: "Destination host unknown.",
            8: "Source host isolated.",
            9: "Network administratively prohibited.",
            10: "Host administratively prohibited.",
            11: "Network unreachable for ToS.",
            12: "Host unreachable for ToS.",
            13: "Communication administratively prohibited.",
            14: "Host precedence violation.",
            15: "Precedence cutoff in effect."
        },
        4: {
            0: "Source quench."
        },
        5: {
            0: "Redirect datagram for the network",
            1: "Redirect datagram for the host.",
            2: "Redirect datagram for the ToS & network.",
            3: "Redirect datagram for the ToS & host."
        },
        8: {
            0: "Echo request."
        },
        9: {
            0: "Router advertisment"
        },
        10: {
            0: "Router discovery/selection/solicitation."
        },
        11: {
            0: "TTL expired in transit",
            1: "Fragment reassembly time exceeded."
        },
        12: {
            0: "Bad IP header: pointer indicates error.",
            1: "Bad IP header: missing a required option.",
            2: "Bad IP header: Bad length."
        },
        13: {
            0: "Timestamp"
        },
        14: {
            0: "Timestamp reply"
        },
        15: {
            0: "Information request."
        },
        16: {
            0: "Information reply."
        },
        17: {
            0: "Address mask request."
        },
        18: {
            0: "Address mask reply."
        }
    }

    def __init__(self, header: bytes):
        (
            ICMP_type,
            code,
            csum,
            remainder
        ) = struct.unpack('!bbHI', header)

        self.type: int = ICMP_type
        self.code: int = code
        self.checksum: int = csum

        self.message: str
        try:
            self.message = icmp_header.messages[self.type][self.code]
        except KeyError:
            # if we can't assign a message then just set a description
            # as to what caused the failure.
            self.message = f"Failed to assign message: ({self.type/self.code})"

        self.id: int
        self.sequence: int
        if self.type in {0, 8}:
            self.id = socket.htons(remainder >> 16)
            self.sequence = socket.htons(remainder & 0xFFFF)
        else:
            self.id = -1
            self.sequence = -1

    def __repr__(self):
        return "\n\t".join((
            "ICMP header:",
            f"Message: [{self.message}]",
            f"Type: [{self.type}]",
            f"Code: [{self.code}]",
            f"Checksum: [{self.checksum:04x}]",
            f"ID: [{self.id}]",
            f"Sequence: [{self.sequence}]"
        ))


class tcp_header:
    def __init__(self, header: bytes):
        (
            src_prt,
            dst_prt,
            seq,
            ack,
            data_offset,
            flags,
            window_size,
            checksum,
            urg
        ) = struct.unpack("!HHIIBBHHH", header)

        self.source: int = src_prt
        self.destination: int = dst_prt
        self.seq: int = seq
        self.ack: int = ack
        self.data_offset: int = data_offset >> 4
        self.flags: int = flags + ((data_offset & 0x01) << 8)
        self.window_size: int = window_size
        self.checksum: int = checksum
        self.urg: int = urg

    def __repr__(self):
        return "\n\t".join((
            "TCP header:",
            f"Source port: [{self.source}]",
            f"Destination port: [{self.destination}]",
            f"Sequence number: [{self.seq}]",
            f"Acknowledgement number: [{self.ack}]",
            f"Data offset: [{self.data_offset}]",
            f"Flags: [{self.flags:08b}]",
            f"Window size: [{self.window_size}]",
            f"Checksum: [{self.checksum:04x}]",
            f"Urgent: [{self.urg}]"
        ))


class udp_header:
    def __init__(self, header: bytes):
        # parse udp header
        (
            src_port,
            dest_port,
            length,
            checksum
        ) = struct.unpack("!HHHH", header)

        self.src: int = src_port
        self.dest: int = dest_port
        self.length: int = length
        self.checksum: int = checksum

    def __repr__(self):
        return "\n\t".join(
            "UDP header:",
            f"Source port: {self.src}",
            f"Destination port: {self.dest}",
            f"Length: {self.length}",
            f"Checksum: {self.checksum:04x}"
        )
