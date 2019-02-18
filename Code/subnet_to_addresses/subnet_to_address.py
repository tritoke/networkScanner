#!/usr/bin/env python
from ip_utils import (
    ip_range
)
import re


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument(
        "ip_subnet",
        help="The CIDR form ip/subnet that you wish to print" +
             "the IP addresses specified by."
    )
    args = parser.parse_args()
    CIDR_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+)")
    search = CIDR_regex.search(args.ip_subnet)
    if search:
        ip, network_bits = search.group(1).split("/")
        print("\n".join(ip_range(ip, int(network_bits))))
