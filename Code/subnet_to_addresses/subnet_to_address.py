#!/usr/bin/python3.7
import re
import socket

cidr_form_regex = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}")

def long_form_to_dot_form(long):
    ip_str = f"{long:032b}"
    return ".".join(str(int(ip_str[i:i+8], 2)) for i in range(0, 32, 8))

def dot_form_to_long_form(ip):
    return int("".join(map(lambda x: f"{int(x):08b}", ip.split("."))), 2)

def ip_range(ip_subnet):
    if cidr_form_regex.match(ip_subnet):
        ip, n_bits = ip_subnet.split("/")
    else:
        print(f"regex couldn't identify the ip address and subnet of {ip_subnet}")

    try:
        network_bits = int(n_bits)
    except ValueError:
        print(f"invalid address specification: {ip_subnet} subnet must be an integer between 0 and 32")
        return None

    try:
        socket.inet_aton(ip)
    except socket.error:
        print(f"Invalid IP address: {ip}")
        if cidr_form_regex.match(ip):
            print("Either use CIDR form or specify the number of network bits, you cannot do both.")
        return None

    ip_long_form = dot_form_to_long_form(ip)
    subnet_long_form = int(("1"*network_bits).zfill(32)[::-1], 2)
    lower_bound = ip_long_form & subnet_long_form
    upper_bound = ip_long_form | (subnet_long_form ^ 0xFFFFFFFF)

    return [long_form_to_dot_form(ip) for ip in range(lower_bound, upper_bound+1)]



if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("ip_subnet", help="The ip/subnet that you wish to print the IP addresses specified by.")
    args = parser.parse_args()
    print("\n".join(ip_range(args.ip_subnet)))
