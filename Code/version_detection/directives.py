#!/usr/bin/env python
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass, field
from typing import DefaultDict, Dict, Set, Union, List
import ip_utils
import re
import socket


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

    def __repr__(self):
        return "Match(" + ", ".join((
                f"service={self.service}",
                f"pattern={self.pattern}",
                f"pattern_options={self.pattern_options}",
                f"version_info={self.version_info}"
            )) + ")"

    def add_version_info(self, version_string: str):
        # this regular expression matches one character from pvihod
        # followed by a / then it non-greedily matches at least one of
        # any character followed by another slash
        regex = re.compile(r"[pvihod]/.+?/")
        # find all the additional fields and iterate over them
        fields = regex.findall(version_string)
        for value in fields:
            # add the field information to the match object
            self.version_info[Match.letter_to_name[value[0]]] = value[2:-1]

    def search(self, string: str):
        pass


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

    def search(self, string: str):
        pass


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
    services: Dict[int, Union[Match, Softmatch]] = field(default_factory=dict)

    def __repr__(self):
        # of ports: [1,2,3,4,5,7,9,10,11,12,13,15] are shown as 1..5,7,9..13,15
        def collapse(port_dict: DefaultDict) -> str:
            store_results = list()
            for key in port_dict:
                # items is a sorted list of a set of ports.
                items: List[int] = sorted(port_dict[key])
                key_result = f'"{key}":' + "{"
                # if its an empty list return now to avoid errors
                if len(items) == 0:
                    return ""
                else:
                    new_sequence = False
                    # enumerate up until the one before
                    # the last to prevent index errors.
                    for index, item in enumerate(items[:-1]):
                        # if its the first one add it on
                        if index == 0:
                            key_result += f"{item}"
                            # if its a sequence start one else put a comma
                            if items[index+1] == item+1:
                                key_result += ".."
                            else:
                                key_result += ","
                        # if the sequence breaks then put a comma
                        elif item+1 != items[index+1]:
                            key_result += f"{item},"
                            new_sequence = True
                        # if its a new sequence the put the `..`s in
                        elif item+1 == items[index+1] and new_sequence:
                            key_result += f"{item}.."
                            new_sequence = False
                    # because we only iterate to the one before
                    # the last element, add the last element on to the end.
                    key_result += f"{items[-1]}" + "}"
                    store_results.append(key_result)
            result = "{" + ", ".join(store_results) + "}"
            return result

        open_ports = collapse(self.open_ports)
        open_filtered_ports = collapse(self.open_filtered_ports)
        return "Target(" + ", ".join((
            f"address=[{self.address}]",
            f"open_ports=[{open_ports}]",
            f"open_filtered_ports=[{open_filtered_ports}]"
        )) + ")"


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
        self.name: str = probename
        self.string: str = probestring
        self.payload: bytes = bytes(probestring, "utf-8")
        self.matches: Set[Match] = set()
        self.softmatches: Set[Softmatch] = set()
        self.ports: DefaultDict[str, Set[int]] = defaultdict(set)
        self.totalwaitms: int = 6000
        self.tcpwrappedms: int = 3000
        self.rarity: int = -1
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
        print(f"Scanning {target}")
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
            )
        ) - Probe.exclude[self.protocol] - Probe.exclude["ANY"]
        if self.ports[self.protocol] != set():
            ports_to_scan &= self.ports[self.protocol]
        print(target.open_filtered_ports[self.protocol] |
              target.open_ports[self.protocol])
        print(f"Scanning {self.protocol} ports: {ports_to_scan}")
        for port in ports_to_scan:
            with closing(
                    socket.socket(
                        socket.AF_INET,
                        self.proto_to_socket_type[self.protocol]
                    )
            ) as sock:
                # setup the connection to the target
                try:
                    sock.connect((target.address, port))
                except ConnectionError:
                    continue
                # send the payload to the target
                sock.send(self.payload)
                # wait for the target to send a response
                time_taken = ip_utils.wait_for_socket(
                    sock,
                    self.totalwaitms/1000
                )
                # if the response didn't time out
                if time_taken != -1:
                    # if the port was in open_filtered move it to open
                    if port in target.open_filtered_ports[self.protocol]:
                        target.open_filtered_ports[self.protocol].remove(port)
                        target.open_ports[self.protocol].add(port)

                    # recieve the data and decode it to a string
                    data_recieved = sock.recv(4096).decode("utf-8")
                    # print the header
                    print(data_recieved)
                    service_name = ""
                    # try and softmatch the service first
                    for softmatch in self.softmatches:
                        search = softmatch.search(data_recieved)
                        if search:
                            service_name = search
                            target.services[port] = softmatch
                            break
                    # try and get a full match for the service
                    for match in self.matches:
                        # If the softmatch fails then
                        # service_name defaults to ""
                        # this makes the below statement true
                        # for all match.service names.
                        if service_name in match.service:
                            search = match.search(data_recieved)
                            if search:
                                target.services[port] = match
                                break
