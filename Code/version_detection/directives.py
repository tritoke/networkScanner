#!/usr/bin/env python
from collections import defaultdict
from contextlib import closing
from dataclasses import dataclass, field
from functools import reduce
from string import whitespace, printable
from typing import DefaultDict, Dict, Set, List
import ip_utils
import operator
import regex
import socket
import struct


class Match:
    """
    This is a class for both Matches and
    Softmatches as they are actually the same
    thing except that softmatches have less information.
    """
    options_to_flags = {
        "i": regex.IGNORECASE,
        "s": regex.DOTALL
    }
    letter_to_name = {
        "p": "vendorproductname",
        "v": "version",
        "i": "info",
        "h": "hostname",
        "o": "operatingsystem",
        "d": "devicetype"
    }
    cpe_part_map: Dict[str, str] = {
        "a": "applications",
        "h": "hardware platforms",
        "o": "operating systems"
    }
    # look into match.expand when looking at the substring version info things.

    def __init__(
            self,
            service: str,
            pattern: str,
            pattern_options: str,
            version_info: str
    ):
        self.version_info: Dict[str, str] = dict()
        self.cpes: Dict[str, Dict[str, str]] = dict()
        self.service: str = service
        # bitwise or is used to combine flags
        # pattern options will never be anything but a
        # combination of s and i.
        # the default value of regex.V1 is so that
        # regex uses the newer matching engine.
        flags = reduce(
            operator.ior,
            [
                self.options_to_flags[opt]
                for opt in pattern_options
            ],
            regex.V0
        )
        try:
            self.pattern: regex.Regex = regex.compile(
                pattern,
                flags=flags
            )
        except Exception:
            print(pattern)

        vinfo_regex = regex.compile(r"([pvihod]|cpe:)([/|])(.+?)\2([a]*)")
        cpe_regex = regex.compile(
            ":?".join((
                "(?P<part>[aho])",
                "(?P<vendor>[^:]*)",
                "(?P<product>[^:]*)",
                "(?P<version>[^:]*)",
                "(?P<update>[^:]*)",
                "(?P<edition>[^:]*)",
                "(?P<language>[^:]*)"
            ))
        )

        for fieldname, _, val, opts in vinfo_regex.findall(version_info):
            if fieldname == "cpe:":
                search = cpe_regex.search(val)
                if search:
                    part = search.group("part")
                    self.cpes[Match.cpe_part_map[part]] = search.groupdict()
            else:
                self.version_info[Match.letter_to_name[fieldname]] = val

    def __repr__(self) -> str:
        return "Match(" + ", ".join((
                f"service={self.service}",
                f"pattern={self.pattern}",
                f"version_info={self.version_info}"
            )) + ")"


    def replace_groups(
            string: str,
            original_match: regex.Match
    ) -> str:
        """
        This function takes in a string and the original
        regex search performed on the data recieved and
        replaces all of the $i, $SUBST, $I, $P occurances
        with the relavant formatted text that they produce.
        """
        def remove_unprintable(
                group_number: int,
                original_match: regex.Match
        ) -> str:
            """
            Mirrors the P function from nmap which
            is used to print only printable characters.
            i.e. W\0O\0R\0K\0G\0R\0O\0U\0P -> WORKGROUP
            """
            return "".join(
                i for i in original_match.group(group_number)
                if i in (
                    set(printable)
                    - set(whitespace)
                    | {" "}
                )
            )
            # if i in the set of all printable characters,
            # excluding those of which that are whitespace characters
            # but including space.

        def substitute(
            group_number: int,
            before: str,
            after: str,
            original_match: regex.Match
        ) -> str:
            """
            Mirrors the SUBST function from nmap which is used to
            format some information found by the regex.
            by substituting all instances of `before` with `after`.
            """
            return original_match.group(group_number).replace(before, after)

        def unpack_uint(
                group_number: int,
                endianness: str,
                original_match: regex.Match
        ) -> str:
            """
            Mirrors the I function from nmap which is used to
            unpack an unsigned int from some bytes.
            """
            return str(struct.unpack(
                endianness + "I",
                original_match.group(group_number)
            ))

        # fill in the version information from the regex match
        # find all the dollar groups:
        dollar_regex = regex.compile(r"\$(\d)")
        # find all the $i's in string
        numbers = set(int(i) for i in dollar_regex.findall(string))
        # for each $i found i
        for group_number in numbers:
            string = string.replace(
                f"${group_number}",
                original_match.group(group_number)
            )
        # having replaced all of the groups we can now
        # start doing the SUBST, P and I commands.
        subst_regex = regex.compile(r"\$SUBST\((\d),(.+),(.+)\)")
        # iterate over all of the matches found by the SUBST regex
        for match in subst_regex.finditer(original_match):
            num, before, after = match.groups()
            # replace the full match (group 0)
            # with the output of substitute
            # with the specific arguments
            string.replace(
                match.group(0),
                substitute(int(num), before, after, original_match)
            )

        p_regex = regex.compile(r"\$P\((\d)\)")
        for match in p_regex.finditer(original_match):
            num = match.group(1)
            # replace the full match (group 0)
            # with the output of remove_unprintable
            # with the specific arguments
            string.replace(
                match.group(0),
                remove_unprintable(int(num), original_match)
            )

        i_regex = regex.compile(r"\$I\(\d),\"(\S)\"\)")
        for match in i_regex.finditer(original_match):
            num, endianness = match.groups()
            # this means replace group 0 -> the whole match
            # with the output of the unpack_uint
            # with the specified arguments
            string.replace(
                match.group(0),
                unpack_uint(
                    int(num),
                    endianness,
                    original_match
                )
            )

        return string

    def matches(self, string: str) -> bool:
        search = self.pattern.search(string)
        if search:
            # the fields to replace are all the CPE groups,
            # all of the version info fields.
            self.version_info = {
                key: replace_groups(value, search)
                for key, value in self.version_info.items()
            }
            self.cpes = {
                outer_key: {
                    inner_key: replace_groups(value, search)
                    for inner_key, value in outer_dict.items()
                }
                for outer_key, outer_dict in self.cpes.items()
            }

            return True
        else:
            return False


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
    services: Dict[int, Match] = field(default_factory=dict)

    def __repr__(self) -> str:
        # of ports: [1,2,3,4,5,7,9,10,11,12,13,15] are shown as 1-5,7,9-13,15
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
                                key_result += "-"
                            else:
                                key_result += ","
                        # if the sequence breaks then put a comma
                        elif item+1 != items[index+1]:
                            key_result += f"{item},"
                            new_sequence = True
                        # if its a new sequence the put the `-`s in
                        elif item+1 == items[index+1] and new_sequence:
                            key_result += f"{item}-"
                            new_sequence = False
                    # because we only iterate to the one before
                    # the last element, add the last element on to the end.
                    key_result += f"{items[-1]}" + "}"
                    store_results.append(key_result)
            # format the final result
            result = "{" + ", ".join(store_results) + "}"
            return result

        open_ports = collapse(self.open_ports)
        open_filtered_ports = collapse(self.open_filtered_ports)
        return ", ".join((
            f"Target(address=[{self.address}]",
            f"open_ports=[{open_ports}]",
            f"open_filtered_ports=[{open_filtered_ports}]",
            f"services={self.services})"
        ))


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
        self.softmatches: Set[Match] = set()
        self.ports: DefaultDict[str, Set[int]] = defaultdict(set)
        self.totalwaitms: int = 6000
        self.tcpwrappedms: int = 3000
        self.rarity: int = -1
        self.fallback: Set[str] = set()

    def __repr__(self) -> str:
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

    def scan(self, target: Target) -> Target:
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
            )
        ) - Probe.exclude[self.protocol] - Probe.exclude["ANY"]
        # if the probe defines a set of ports to scan
        # then don't scan any that aren't defined for it
        if self.ports[self.protocol] != set():
            ports_to_scan &= self.ports[self.protocol]
        for port in ports_to_scan:
            # open a self closing IPV4 socket
            # for the correct protocol for this probe.
            with closing(
                    socket.socket(
                        socket.AF_INET,
                        self.proto_to_socket_type[self.protocol]
                    )
            ) as sock:
                # setup the connection to the target
                try:
                    sock.connect((target.address, port))
                    # if the connection fails then continue scanning
                    # the next ports, this shouldn't really happen.
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
                    print("Recieved", data_recieved)
                    service = ""
                    # try and softmatch the service first
                    for softmatch in self.softmatches:
                        if softmatch.matches(data_recieved):
                            print(f"Softmatched: {softmatch}")
                            service = softmatch.service
                            target.services[port] = softmatch
                            break
                    # try and get a full match for the service
                    for match in self.matches:
                        if service in match.service.lower():
                            if "ssh" in match.service.lower():
                                print(f"Trying to match: {match}")
                            if match.matches(data_recieved):
                                print(f"Matched: {match}")
                                target.services[port] = match
                                break
        return target
