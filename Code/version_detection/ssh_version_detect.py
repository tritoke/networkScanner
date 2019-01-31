import directives
from typing import Dict, Set, Pattern
from functools import reduce
import re
import operator
delims: Set[str] = set()


def parse_ports(portstring: str) -> Set[int]:
    """
    This function takes in a port directive
    and returns a set of the ports specified.
    A set is used because it is O(1) for contains
    operations as opposed for O(N) for lists.
    """
    # matches both the num-num port range format
    # and the plain num port specification
    # num-num form must come first otherwise it breaks.
    pair_regex = re.compile(r"(\d+)-(\d+)")
    single_regex = re.compile(r"(\d+)")
    # searches contains the result of trying the pair_regex
    # search against all of the command seperated
    # port strings
    pairs = pair_regex.findall(portstring)
    # for each pair of numbers in the pairs list
    # seperate each number and cast them to int
    # then generate the range of numbers from x[0]
    # to x[1]+1 then cast this range to a list
    # and "reduce" the list of lists by joining them
    # with operator.add and then let ports be the set
    # of all the ports defined by the ranges.
    ports: Set[int] = set(reduce(operator.add,
                                 map(lambda x: list(range(int(x[0]),
                                                          int(x[1])+1)),
                                     pairs)))
    singles = single_regex.findall(portstring)
    # for each of the ports that are specified on their own
    # cast them to int and update the set of all ports with
    # that list.
    ports.update(map(int, singles))
    return ports


def parse_probes(probe_file: str) -> Dict[str, directives.Probe]:
    # filter out any unicode characters
    data = filter(lambda x: x < 128, open(probe_file, "rb").read())
    # filter out all lines that start with hashtags
    lines = list(filter(lambda x: not x.startswith("#") and x != "",
                        "".join(map(chr, data)).split("\n")))

    # list holding each of the probe directives.
    probes: Dict[str, directives.Probe] = {}

    # this defines the string on which to form
    # the regex which I use to match the match directives.
    match_string = " ".join(["match",
                             r"(\S+)",
                             r"(m\|.*\||m=.*=|m@.*@|m%.*%)(s?i?)",
                             r"([pvihod]/.+/)"])
    match_regex = re.compile(match_string)
    regexes: Dict[str, Pattern]
    regexes = {"rarity":       re.compile(r"rarity (\d+)"),
               "totalwaitms":  re.compile(r"totalwaitms (\d+)"),
               "tcpwrappedms": re.compile(r"tcpwrappedms (\d+)"),
               "fallback":     re.compile(r"fallback (\S+)"),
               "ports":        re.compile(r"ports (\S+)"),
               "exclude":      re.compile(r"Exclude T:(\S+)")}

    # parse the probes out from the file
    for line in lines:
        # add any ports to be excluded to the base probe class
        if line.startswith("Exclude"):
            search = regexes["exclude"].search(line)
            if search:
                # parse the ports from the grouped output of
                # a search with the regex defined above.
                directives.Probe.exclude.update(parse_ports(search.group()))

        # new probe directive
        if line.startswith("Probe"):
            # parse line into probe protocol, name and probestring
            proto, name, string = line.split()[1:]
            # add the new probe to the end of the list of probes
            probes[name] = directives.Probe(proto, name, string)
            # assign current_probe to the most recently added probe
            current_probe = probes[name]

        # new match directive
        elif line.startswith("match") or line.startswith("softmatch"):
            # service name, match string, version strings
            search = match_regex.search(line)
            if search:
                # return any information matched by the regex
                service, regex, regex_options, version_info = search.groups()
                if line[0] == "m":  # new match object
                    match = directives.Match(service,
                                             regex[2:-1],
                                             regex_options)
                    # add the version info to the match object
                    match.add_version_info(version_info)
                    # add the match directive to the current probe
                    current_probe.matches.add(match)

                else:
                    softmatch = directives.Softmatch(service,
                                                     regex[2:-1],
                                                     regex_options)
                    current_probe.softmatches.add(softmatch)

        # new ports directive
        elif line.startswith("ports"):
            search = regexes["ports"].search(line)
            if search:
                current_probe.ports = parse_ports(search.group(1))

        # new totalwaitms directive
        elif line.startswith("totalwaitms"):
            search = regexes["totalwaitms"].search(line)
            if search:
                current_probe.totalwaitms = int(search.group(1))

        # new rarity directive
        elif line.startswith("rarity"):
            search = regexes["rarity"].search(line)
            if search:
                current_probe.rarity = int(search.group(1))

        # new fallback directive
        elif line.startswith("fallback"):
            search = regexes["fallback"].search(line)
            if search:
                current_probe.fallback = set(search.group(1).split(","))

    return probes


if __name__ == "__main__":
    probes = parse_probes("./small-example-probes")
    print(probes)
    exit()
