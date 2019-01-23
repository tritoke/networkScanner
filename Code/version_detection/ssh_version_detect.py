#!/usr/bin/python3.7
import directives
from os import getcwd
from sys import path
path.append(getcwd())

# filter out any unicode characters
data = filter(lambda x: x < 128, open("nmap-service-probes", "rb").read())
# filter out all lines that start with hashtags
lines = list(filter(lambda x: not x.startswith("#") and x !=
                    "", "".join(map(chr, data)).split("\n")))

# parse the exclude directive
directives.Probe.Exclude = range(int(lines[0][10:14]), int(lines[0][15:]) + 1)

probes = []

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
        # split the line into words
        service = line.split(" ")
        # the protocol will always be the first word
        protocol = words[1]
        # make the rest of the line
        remainder = " ".join(words)
        # this will find the index of the first "m" character
        # in the remainder of the string
        m_pos = remainder.find("m")
        # the delimiter for the match is the next charcter after the m
        delimiter = remainder[match_start + 1]
        # finds the start and end of the match
        match_start, match_end = [i for i, j in i, j in enumerate(remainder) if j == delimiter][:2]
        # splits to the string to match on out of the remainder
        match_string = remainder[match_start:match_end + 1]
        next_space = remainder[match_end + 2:].find(" ")
        pattern_options = remainder[match_end + 2:match_end + 2 + next_space]
        # creates new match object
        match = directives.Match(service, match_string)
        # add the version info to the match object
        match.add_version_info(remainder[match_end + 2 + next_space:])
        current_probe.matches.append(match)



# TODO: more directives 
