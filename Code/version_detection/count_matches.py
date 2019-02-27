#!/usr/bin/env python

file = "./nmap-service-probes"

matches = 0
softmatches = 0

for line in open(file).read().splitlines():
    if line.startswith("match"):
        matches += 1
    elif line.startswith("softmatch"):
        softmatches += 1

print(
    f"file: {file}",
    f"found {matches} matches",
    f"found {softmatches} softmatches",
    sep="\n"
)
