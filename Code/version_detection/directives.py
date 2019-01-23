import re
from collections import defaultdict


class Probe:
    """
    This class represents the Probe directive of the nmap-service-probes file.
    """

    exclude = None

    def __init__(self, protocol: str, probename: str, probestring: str):
        if protocol in {"TCP", "UDP"}:
            self.proto = protocol
        else:
            raise ValueError(
                f"Probe object must have protocol TCP or UDP not {protocol}.")
        self.name = probename
        self.string = probestring.split("|")[1]

        self.matches = []
        self.softmatches = []
        self.ports = []
        self.totalwaitms = 6000
        self.tcpwrappems = 3000
        self.rarity = -1
        self.fallback = []


class Match:

    version_info = defaultdict(str)
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

    def add_version_info(version_string):
        # this regular expression matches one character from pvihod
        # followed by a / then it non-greedily matches at least one of
        # any character followed by another slash
        regex = re.compile(r"[pvihod]/.+?/")
        fields = regex.findall(version_string)
        for field in fields:
            version_info[letter_to_name[field[0]]] = field[2:-1]
