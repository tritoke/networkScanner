#!/usr/bin/env python
import re
from argparse import ArgumentParser
from collections import defaultdict
from math import floor, log10
from modules import (
    scanners,
    ip_utils,
    directives,
)
from typing import (
    DefaultDict,
    Dict,
)

top_ports = directives.parse_ports(open("top_ports").read())
services: DefaultDict[str, Dict[int, str]] = defaultdict(dict)
for match in re.finditer(
        r"(\S+)\s+(\d+)/(\S+)",
        open("version_detection/nmap-services").read()
):
    service, portnum, protocol = match.groups()
    services[protocol.upper()][int(portnum)] = service

parser = ArgumentParser()
parser.add_argument(
    "target_spec",
    help="specify what to scan, i.e. 192.168.1.0/24"
)
parser.add_argument(
    "-Pn",
    help="assume hosts are up",
    action="store_true"
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
    "--ports",
    help="scan specified ports",
    required=False,
    default=top_ports
)
parser.add_argument(
    "--exclude_ports",
    help="ports to exclude from the scan",
    required=False,
    default=""
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
else:
    if args.sn:
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
            for host, taken, ip_head in scanners.ping(addresses)
        ))
    else:
        if args.Pn:
            targets = [
                directives.Target(
                    addr,
                    defaultdict(set),
                    defaultdict(set)
                )
                for addr in addresses
            ]
        else:
            targets = [
                directives.Target(
                    addr,
                    defaultdict(set),
                    defaultdict(set),
                )
                for addr, _, _ in scanners.ping(addresses)
            ]
        # define the ports to scan
        if args.ports == "-":
            # case they have specified all ports
            ports = {
                "UDP": set(range(1, 65536)),
                "TCP": set(range(1, 65536)),
            }
        elif isinstance(args.ports, str):
            # case they have specifed ports
            ports = directives.parse_ports(args.ports)
        else:
            # default
            ports = args.ports

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

        for target in targets:
            if not args.sU or args.sS:
                tcp_ports = scanners.tcp(
                    target.address,
                    ports["TCP"]
                )
                target.open_ports["TCP"].update(tcp_ports["OPEN"])
                target.open_filtered_ports["TCP"].update(tcp_ports["FILTERED"])
            if args.sT:
                target.open_ports["TCP"].update(
                    scanners.connect(target.address, ports["TCP"])
                )
            if args.sU:
                udp_ports = scanners.udp(
                    target.address,
                    ports["UDP"]
                )
                target.open_ports["UDP"].update(
                    udp_ports["OPEN"]
                )
                target.open_filtered_ports["UDP"].update(
                    udp_ports["FILTERED"]
                )
                target.open_filtered_ports["UDP"].update(
                    udp_ports["OPEN|FILTERED"]
                )
            if args.sV:
                target = scanners.version_detect_scan(target, probes)
            # display scan info
            print()
            print(f"Scan report for: {target.address}")
            #  print(target)
            print("Open ports:")
            for proto, open_ports in target.open_ports.items():
                for port in open_ports:
                    try:
                        service_name = services[proto][port]
                    except KeyError:
                        service_name = "unknown"
                    if port in target.services:
                        exact_match = target.services[port]
                        print(
                            f"{port}/{proto}{exact_match.service:>8s}"
                        )
                        # print version information
                        for key, val in exact_match.version_info.items():
                            print(f"{key}: {val}")
                        if exact_match.cpes:
                            print()
                            print("CPE:")
                            for cpe_type, cpe_vals in exact_match.cpes.items():
                                print(cpe_type)
                                try:
                                    del(cpe_vals["part"])
                                except KeyError:
                                    pass
                                for key, val in cpe_vals.items():
                                    print(f"{key}: {val}")
                        print()
