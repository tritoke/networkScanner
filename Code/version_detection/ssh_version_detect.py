import directives
from typing import List, Dict
import re


# split match and softmatch information out of a line.
def split_match(line: str) -> List[str]:
    # split the line into words
    words = line.split(" ")
    # the protocol will always be the first word
    service = words[1]
    # make the rest of the line
    remainder = " ".join(words)
    # this will find the index of the first "m" character
    # in the remainder of the string
    m_pos = remainder.find("m")
    # the delimiter for the match is the next charcter after the m
    delimiter = remainder[m_pos + 1]
    # finds the start and end of the match
    match_start, match_end = [i for i, j in
                              enumerate(remainder)
                              if j == delimiter][:2]
    # splits to the string to match on out of the remainder
    match_string = remainder[match_start:match_end + 1]
    next_space = remainder[match_end + 2:].find(" ")
    pattern_options = remainder[match_end + 2:match_end + 2 + next_space]
    if next_space != -1:
        return [service, match_string, pattern_options]
    else:
        version_info = remainder[match_end + 2 + next_space:]
        return [service, match_string, pattern_options, version_info]


def parse_ports(portstring: str) -> List[int]:
    ports: List[int] = []
    # matches both the num-num port range format
    # and the plain num port specification
    # num-num form must come first otherwise it breaks.
    pair_regex = re.compile(r"(\d+)-(\d+)|(\d+)")
    pairs = portstring.split(",")
    # searches contains the result of trying the pair_regex
    # search against all of the command seperated
    # port strings
    searches = list(map(pair_regex.search, pairs))
    print(list(searches))
    for i in searches:
        if i:
            if i.groups().count(None) < 2:
                # if the regex finds number-number
                # then split the numbers into groups
                # and map them to ints
                print(i)
                print(i.groups())
                start, finish = map(int, i.groups()[:2])
                ports += list(range(start, finish+1))
            else:
                # if the regex only finds one number
                # treat that number as a port
                print(i)
                print(i.groups())
                ports.append(int(i.groups()[-1]))
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
            # this function returns a list of
            # all the options for the match directive
            args = split_match(line)
            # creates new match object
            match = directives.Match(*args[:-1])
            # add the version info to the match object
            match.add_version_info(args[-1])
            # add the match directive to the current probe
            current_probe.matches.append(match)

        # new softmatch directive
        elif line.startswith("softmatch"):
            # this function returns a list of
            # all the options for the match directive
            args = split_match(line)
            # creates new match object
            softmatch = directives.Softmatch(*args[:-1])
            current_probe.softmatches.append(softmatch)

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
            current_probe.fallback = line[10:].split(",")
    return probes


if __name__ == "__main__":
    print(parse_ports("1,2,3,4,5-10,6-89"))
    exit()


