import re
from collections import defaultdict
from typing import List, DefaultDict


class Probe:
    """
    This class represents the Probe directive of the nmap-service-probes file.
    It holds information such as the protocol to use, the string to send,
    the ports to scan, the time to wait for a null TCP to return a banner,
    the rarity of the probe (how often it will return a response) and the
    probes to try if this one fails.
    """

    exclude: List[int] = []

    def __init__(self, protocol: str, probename: str, probestring: str):
        if protocol in {"TCP", "UDP"}:
            self.proto = protocol
        else:
            raise ValueError(
                f"Probe object must have protocol TCP or UDP not {protocol}.")
        self.name = probename
        self.string = probestring.split("|")[1]

        self.matches: List[Match] = []
        self.softmatches: List[Softmatch] = []
        self.ports: List[int] = []
        self.totalwaitms = 6000
        self.tcpwrappedms = 3000
        self.rarity = -1
        self.fallback: List[str] = []


class Match:
    """
    This class holds information for the match directive.
    This includes optional version info as well as a service,
    a pattern to match the response against and some pattern options.
    """
    version_info: DefaultDict[str, str] = defaultdict(str)
    letter_to_name = {"p": "vendorproductname",
                      "v": "version",
                      "i": "info",
                      "h": "hostname",
                      "o": "operatingsystem",
                      "d": "devicetype"}

    def __init__(self, service, pattern, pattern_options):
        self.service = service
        self.pattern = pattern
        self.pattern_options = pattern_options

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
    def __init__(self, service, pattern, pattern_options):
        self.service = service
        self.pattern = pattern
        self.pattern_options = pattern_options

