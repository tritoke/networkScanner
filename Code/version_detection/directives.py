class Probe:
    """
    This class represents the Probe directive of the nmap-service-probes file.
    """
    def __init__(self, protocol: str, probename: str, probestring: str):
        if protocol in {"TCP", "UDP"}:
            self.proto = protocol
        else:
            raise ValueError(f"Probe object must have protocol TCP or UDP not {protocol}.")
        self.name = probename
        self.string = probestring

        self.matches = []
        self.softmatches = []
        self.ports = []
        self.totalwaitms = 6000
        self.tcpwrappems = 3000
        self.rarity = -1
        self.fallback = []

