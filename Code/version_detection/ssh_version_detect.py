import directives
from typing import Dict, Set
import re
delims: Set[str] = set()


def parse_ports(portstring: str) -> Set[int]:
    """
    This function takes in a port directive
    and returns a set of the ports specified.
    A set is used because it is O(1) for contains
    operations as opposed for O(N) for lists.
    """
    ports: Set[int] = set()
    # matches both the num-num port range format
    # and the plain num port specification
    # num-num form must come first otherwise it breaks.
    pair_regex = re.compile(r"(\d+)-(\d+)|(\d+)")
    pairs = portstring.split(",")
    # searches contains the result of trying the pair_regex
    # search against all of the command seperated
    # port strings
    searches = map(pair_regex.search, pairs)
    for i in searches:
        if i:
            if i.groups().count(None) < 2:
                # if the regex finds number-number
                # then split the numbers into groups
                # and map them to ints
                start, finish = map(int, i.groups()[:2])
                ports.update(range(start, finish+1))
            else:
                # if the regex only finds one number
                # treat that number as a port
                ports.add(int(i.groups()[-1]))
    return ports


def parse_probes(probe_file: str) -> Dict[str, directives.Probe]:
    # filter out any unicode characters
    data = filter(lambda x: x < 128, open(probe_file, "rb").read())
    # filter out all lines that start with hashtags
    lines = list(filter(lambda x: not x.startswith("#") and x != "",
                        "".join(map(chr, data)).split("\n")))
    # parse the exclude directive
    directives.Probe.exclude = parse_ports(lines[0].split(" ")[1])

    # list holding each of the probe directives.
    probes: Dict[str, directives.Probe] = {}

    # parse the probes out from the file
    for line in lines:
        # new probe directive
        if line.startswith("Probe"):
            # parse line into probe protocol, name and probestring
            proto, name, string = line.split()[1:]
            # add the new probe to the end of the list of probes
            probes[name] = directives.Probe(proto, name, string)
            # assign current_probe to the most recently added probe
            current_probe = probes[name]

        # new match directive
        elif line.startswith("match"):
            match_regex = re.compile(" ".join(["match",
                                               "(\S+)",
                                               "(m\|.*\||m=.*=|m@.*@|m%.*%)(s?i?)",
                                               "([pvihod]/.+/)"]))
            search = match_regex.search(line)
            if search:
                args = search.groups()
                # creates new match object
                match = directives.Match(*args[:-1])
                # add the version info to the match object
                match.add_version_info(args[-1])
                # add the match directive to the current probe
                current_probe.matches.add(match)

        # new softmatch directive
        elif line.startswith("softmatch"):
            # this function returns a list of
            # all the options for the match directive
            args = split_match(line)
            # creates new match object
            softmatch = directives.Softmatch(*args[:-1])
            current_probe.softmatches.add(softmatch)

        # new ports directive
        elif line.startswith("ports"):
            current_probe.ports = parse_ports(line[6:])

        # new totalwaitms directive
        elif line.startswith("totalwaitms"):
            current_probe.totalwaitms = int(line[12:])

        # new rarity directive
        elif line.startswith("rarity"):
            current_probe.rarity = int(line[8:])

        # new fallback directive
        elif line.startswith("fallback"):
            current_probe.fallback = set(line[10:].split(","))
    return probes


if __name__ == "__main__":
    probes = parse_probes("./small-example-probes")
    print(probes)
    exit()
