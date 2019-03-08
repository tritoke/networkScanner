import re

lines = open("version_info_strings").read().splitlines()

cpe_regex = re.compile(r"(cpe:([/|]).+?\2\S+)")

cpes = set()

for line in lines:
    for match, _ in cpe_regex.findall(line):
        cpes.add(match)

open("cpes", "w").write("\n".join(cpes))
