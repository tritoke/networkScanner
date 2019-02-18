#!/usr/bin/env python
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass
from typing import DefaultDict, Set, Dict
import ip_utils
import re
import socket


@dataclass
class Target:
    """
    This class holds data about targets to
    scan. the dataclass decorator is simply
    a way of python automatically writing some
    of the basic methods a class for storing data
    has, such as __repr__ for printing information
    in the object etc.
    """
    address: str
    open_ports: DefaultDict[str, Set[int]]
    open_filtered_ports: DefaultDict[str, Set[int]]


class Probe:
    """
    This class represents the Probe directive of the nmap-service-probes file.
    It holds information such as the protocol to use, the string to send,
    the ports to scan, the time to wait for a null TCP to return a banner,
    the rarity of the probe (how often it will return a response) and the
    probes to try if this one fails.
    """

    # a default dict is one which takes in a
    # "default factory" which is called when
    # a new key is introduced to the dict
    # in this case the default factory is
    # the set function meaning that when I
    # do exclude[protocol].update(ports)
    # but exclude[protocol] has not yet been defined
    # it will be defined as an empty set
    # allowing me to update it with ports.
    exclude: DefaultDict[str, Set[int]] = defaultdict(set)
    proto_to_socket_type: Dict[str, int] = {
        "TCP": socket.SOCK_STREAM,
        "UDP": socket.SOCK_DGRAM
    }

    def __init__(self, protocol: str, probename: str, probestring: str):
        """
        This is the initial function that is called by the
        constructor of the Probe class, it is used to define
        the variables that are specific to each instance of
        the class.
        """
        if protocol in {"TCP", "UDP"}:
            self.protocol = protocol
        else:
            raise ValueError(
                f"Probe object must have protocol TCP or UDP not {protocol}.")
        self.name = probename
        self.string = probestring
        self.matches: Set[Match] = set()
        self.softmatches: Set[Softmatch] = set()
        self.ports: DefaultDict[str, Set[int]] = defaultdict(set)
        self.totalwaitms = 6000
        self.tcpwrappedms = 3000
        self.rarity = -1
        self.fallback: Set[str] = set()

    def __repr__(self):
        """
        This is the function that is called when something
        tries to print an instance of this class.
        It is used to reveal information internal
        to the class.
        """
        return ", ".join([
            f"Probe({self.protocol}",
            f"{self.name}",
            f"\"{self.string}\"",
            f"{len(self.matches)} matches",
            f"{len(self.softmatches)} softmatches",
            f"ports: {self.ports}",
            f"rarity: {self.rarity}",
            f"fallbacks: {self.fallback})"
        ])

    def scan(self, target: Target):
        """
        scan takes in an object of class Target to
        probe and attempts to detect the version of
        any services running on the machine.
        """
        # this constructs the set of all ports,
        # that are either open or open_filtered,
        # and are in the set of ports to scan for
        # this particular probe, this means that,
        # we are only connecting to ports that we
        # know are not closed and are not to be excluded.
        ports_to_scan: Set[int] = (
            (
                target.open_filtered_ports[self.protocol]
                | target.open_ports[self.protocol]
                | self.ports["ANY"]
            )
            & self.ports[self.protocol]
        ) - Probe.exclude[self.protocol] - Probe.exclude["ANY"]

        for port in ports_to_scan:
            with closing(
                    socket.socket(socket.AF_INET,
                                  self.proto_to_socket_type[self.protocol]
                                  )
            ) as sock:
                sock.send(bytes(self.string, "utf-8"))
                # TODO main scanning logic


class Match:
    """
    This class holds information for the match directive.
    This includes optional version info as well as a service,
    a pattern to match the response against and some pattern options.
    """
    version_info: DefaultDict[str, str] = defaultdict(str)
    letter_to_name = {
        "p": "vendorproductname",
        "v": "version",
        "i": "info",
        "h": "hostname",
        "o": "operatingsystem",
        "d": "devicetype"
    }

    def __init__(
            self,
            service: str,
            pattern: str,
            pattern_options: str
    ):
        self.service: str = service
        self.pattern: str = pattern
        # inline regex options are the cool
        self.pattern_options: str = pattern_options

    def add_version_info(self, version_string: str):
        # this regular expression matches one character from pvihod
        # followed by a / then it non-greedily matches at least one of
        # any character followed by another slash
        regex = re.compile(r"[pvihod]/.+?/")
        # find all the additional fields and iterate over them
        fields = regex.findall(version_string)
        for field in fields:
            # add the field information to the match object
            self.version_info[Match.letter_to_name[field[0]]] = field[2:-1]


class Softmatch:
    """
    This class holds infomation for the sortmatch directive.
    Such as the service, the regex pattern and the pattern options.
    """
    def __init__(
            self,
            service: str,
            pattern: str,
            pattern_options: str
    ):
        self.service: str = service
        self.pattern: str = pattern
        self.pattern_options: str = pattern_options
