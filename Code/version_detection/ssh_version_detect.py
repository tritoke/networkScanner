#!/usr/bin/python3.7
from os import getcwd
import sys
path.append(getcwd())
import directives

# filter out any unicode characters
data = filter(lambda x: x<128, open("nmap-service-probes", "rb").read())
# filter out all lines that start with hashtags
lines = list(filter(lambda x: not x.startswith("#") and x != "", "".join(map(chr,data)).split("\n")))

# parse the exclude directive
Exclude = range(int(lines[0][10:14]), int(lines[0][15:])+1)


