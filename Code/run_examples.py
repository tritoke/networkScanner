#!/usr/bin/env python
from icmp_ping import icmp_echo_recv, icmp_echo_send
from ping_scanner import ping_scan
from tcp_scan.connect_scan import scan_port_list as connect_scan_list
from tcp_scan.syn_scan import scan_port_list as syn_scan_list
from udp_scan import scan_port_list as udp_scan_list
from version_detection import version_detection

examples = {
    "icmp_echo_recv": icmp_echo_recv.main,
    "icmp_echo_send": icmp_echo_send.main,
    "ping_scanner": ping_scan.main,
    "connect_scan": connect_scan_list.main,
    "syn_scan": syn_scan_list.main,
    "udp_scan": udp_scan_list.main,
    "version_detection": version_detection.main,
}

while True:
    program = input("Enter the name of the example program to run: ")
    if program.lower() in examples:
        print(f"Running: {program}")
        examples[program]()
        break
    else:
        print(
            "The program name must exactly match one of the following examples"
        )
        print("\n".join(examples))
