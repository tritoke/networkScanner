from .version_detection import directives
from typing import List


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


# filter out any unicode characters
data = filter(lambda x: x < 128, open("./small-example-probes", "rb").read())
# filter out all lines that start with hashtags
lines = list(filter(lambda x: not x.startswith("#") and x !=
                    "", "".join(map(chr, data)).split("\n")))


def parse_ports(portstring: str) -> List[int]:
    ports: List[int] = []
    for i in portstring.split(","):
        if "-" in i:
            start, finish = map(int, i.split("-"))
            ports += list(range(start, finish+1))
        else:
            ports.append(int(i))
    return ports


# parse the exclude directive
directives.Probe.exclude = parse_ports(lines[0].split(" ")[1])

probes: List[directives.Probe] = []

for line in lines:
    # new probe directive
    if line.startswith("Probe"):
        # parse line into probe protocol, name and probestring
        proto, name, string = line.split()[1:]
        # add the new probe to the end of the list of probes
        probes.append(directives.Probe(proto, name, string))
        # assign current_probe to the most recently added probe
        current_probe = probes[-1]

    # new match directive
    elif line.startswith("match"):
        # this function returns a list of all the options for the match directive
        args = split_match(line)
        # creates new match object
        match = directives.Match(*args[:-1])
        # add the version info to the match object
        match.add_version_info(args[-1])
        # add the match directive to the current probe
        current_probe.matches.append(match)


    # new softmatch directive
    elif line.startswith("softmatch"):
        # this function returns a list of all the options for the match directive
        args = split_match(line)
        # creates new match object
        softmatch = directives.Softmatch(*args[:-1])
        current_probe.softmatches.append(softmatch)


# TODO: more directives
