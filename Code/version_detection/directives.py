import re
from collections import defaultdict
from typing import Iterable, List, DefaultDict

class Probe:
    """
    This class represents the Probe directive of the nmap-service-probes file.
    """

    exclude: Iterable[int] = []

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
        self.tcpwrappems = 3000
        self.rarity = -1
        self.fallback: List[Fallback] = []


class Match:

    version_info: DefaultDict[str,str] = defaultdict(str)
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
    def __init__(self, service, pattern, pattern_options):
        self.service = service
        self.pattern = pattern
        self.pattern_options = pattern_options
        

class Fallback:
    def __init__(self):
        pass
