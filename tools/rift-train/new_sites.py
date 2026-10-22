"""For a time-separated test: the URLs in NEWER whose site (by the Public
Suffix List, as rift-train finds sites) is on no line of OLDER. Lines that
are not http(s) URLs are skipped. IP addresses are their own site.

usage: python3 -I new_sites.py <psl-ascii.txt> <older.txt> <newer.txt> <out.txt>
"""
import ipaddress, sys
from urllib.parse import urlsplit

psl_path, older_path, newer_path, out_path = sys.argv[1:5]
rules, wild, exceptions = set(), set(), set()
for line in open(psl_path, encoding="utf-8"):
    rule = line.strip().lower()
    if not rule:
        continue
    if rule.startswith("!"):
        exceptions.add(rule[1:])
    elif rule.startswith("*."):
        wild.add(rule[2:])
    else:
        rules.add(rule)


def site(host):
    host = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    labels = host.split(".")
    # The longest matching public suffix; an exception rule's suffix is one label shorter.
    suffix_len = 1
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exceptions:
            suffix_len = len(labels) - i - 1
            break
        if candidate in rules:
            suffix_len = len(labels) - i
            break
        if i + 1 < len(labels) and ".".join(labels[i + 1:]) in wild:
            suffix_len = len(labels) - i
            break
    return ".".join(labels[-(suffix_len + 1):]) if len(labels) > suffix_len else host


def sites_and_urls(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        url = line.strip()
        if not url.startswith(("http://", "https://")):
            continue
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if host:
            yield site(host), url


older = {s for s, _ in sites_and_urls(older_path)}
kept = seen = 0
with open(out_path, "w", encoding="utf-8") as out:
    for s, url in sites_and_urls(newer_path):
        if s in older:
            seen += 1
            continue
        out.write(url + "\n")
        kept += 1
print(f"{kept} URLs on sites not in the older list, {seen} on sites it has", file=sys.stderr)
