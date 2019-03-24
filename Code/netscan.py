#!/usr/bin/env python
import re
from argparse import ArgumentParser
from math import floor, log10
from modules import (
    scanners,
    ip_utils,
    directives,
)

top_ports = directives.parse_ports(open("top_ports").read())

parser = ArgumentParser()
parser.add_argument(
    "target_spec",
    help="specify what to scan, i.e. 192.168.1.0/24"
)
parser.add_argument(
    "-sL",
    help="list targets",
    action="store_true"
)
parser.add_argument(
    "-sn",
    help="disable port scanning",
    action="store_true"
)
parser.add_argument(
    "-sS",
    help="TCP SYN scan",
    action="store_true"
)
parser.add_argument(
    "-sT",
    help="TCP connect scan",
    action="store_true"
)
parser.add_argument(
    "-sU",
    help="UDP scan",
    action="store_true"
)
parser.add_argument(
    "-sV",
    help="version scan",
    action="store_true"
)
parser.add_argument(
    "-p",
    help="scan specifed ports",
    required=False,
    default=top_ports["TCP"]
)
parser.add_argument(
    "--exclude_ports",
    help="ports to exclude from the scan",
    required=False,
    default=set()
)

args = parser.parse_args()

# check whether the address spec is in CIDR form
CIDR_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})")
search = CIDR_regex.search(args.target_spec)
if search:
    base_addr, network_bits = search.groups()
    addresses = ip_utils.ip_range(
        base_addr,
        int(network_bits)
    )
else:
    base_addr = args.target_spec
    addresses = {base_addr}

if args.sL:
    print("Targets:")
    print("\n".join(sorted(addresses, key=ip_utils.dot_to_long)))
elif args.sn:
    results = scanners.ping(addresses)

    def sig_figs(x: float, n: int) -> float:
        """
        rounds x to n significant figures.
        sig_figs(1234, 2) = 1200.0
        """
        return round(x, n - (1 + int(floor(log10(abs(x))))))

    print("\n".join(
        f"host: [{host}]\t" +
        "responded to an ICMP ECHO REQUEST in " +
        f"{str(sig_figs(taken, 2))+'s':<10s} " +
        f"ttl: [{ip_head.time_to_live}]"
        for host, taken, ip_head in results
    ))
else:
    # define the ports to scan
    if args.p == "-":
        # case they have specified all ports
        ports = {
            "UDP": set(range(1, 65536)),
            "TCP": set(range(1, 65536)),
        }
    elif isinstance(args.p, str):
        # case they have specifed ports
        ports = directives.parse_ports(args.p)
    else:
        # default
        ports = args.p

    # exclude all the ports speified to be excluded
    to_exclude = directives.parse_ports(args.exclude_ports)
    ports["TCP"] -= to_exclude["TCP"]
    ports["TCP"] -= to_exclude["ANY"]
    ports["UDP"] -= to_exclude["UDP"]
    ports["UDP"] -= to_exclude["ANY"]

    # if version scanning is desired
    if args.sV:
        probes = directives.parse_probes(
            "./version_detection/nmap-service-probes"
        )
        # TODO finish this thing
        targets = {
            directives.Target(addr)
            for addr in addresses
        }

    for addr in addresses:
        if args.sS:
            open_ports = scanners.tcp(
                addr,
                ports["TCP"]
            )
