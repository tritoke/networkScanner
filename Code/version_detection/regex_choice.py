# I had the choice to use either of these syntaxes for
# my CPE regular expression, I have gone with cpe_regex2
# because it uses named regex groups and it is more clear
# what it is doing.

cpe_regex1 = regex.compile(
    ":?".join((
        "([aho])",
        *["([^:]*)" for _ in range(6)]
    ))
)
cpe_regex2 = regex.compile(
    ":?".join((
        "(?P<part>[aho])",
        "(?P<vendor>[^:]*)",
        "(?P<product>[^:]*)",
        "(?P<version>[^:]*)",
        "(?P<update>[^:]*)",
        "(?P<edition>[^:]*)",
        "(?P<language>[^:]*)"
    ))
)

for fieldname, _, val, opts in vinfo_regex.findall(version_info):
    if fieldname == "cpe:":
        search1 = cpe_regex1.search(val)
        search2 = cpe_regex2.search(val)
        if search1 and search2:
            (
                part,
                vendor,
                product,
                version,
                update,
                edition,
                language
            ) = search1.groups()

            part = search2.group("part")
            vendor = search2.group("vendor")
            product = search2.group("product")
            version = search2.group("version")
            update = search2.group("update")
            edition = search2.group("edition")
            language = search2.group("language")
