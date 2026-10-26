"""Rift AI's memory of phishing pages (docs/reports/rift-ai.md, "Learning
from new data"): each monthly retrain adds the month's prepared phishing
URLs to the memory the last run left, so pages that have since gone offline
keep teaching the model. Entries not seen for MONTHS months are dropped,
and at most MAX entries are kept, the most recently seen first.

The memory is a list of `YYYY-MM<TAB>url` lines (the month each URL was
last seen). It holds real malicious URLs: it lives outside the repository
(the retrain workflow keeps it as an artifact), never in it.

usage: python3 -I memory.py <month YYYY-MM> <old memory or -> <new memory> <training urls> <prepared list>...
"""
import re
import sys

MONTHS = 24
MAX = 1_500_000

month, old, new, urls, *lists = sys.argv[1:]
if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month) or not lists:
    sys.exit(__doc__)
year, mon = map(int, month.split("-"))
oldest = f"{year - MONTHS // 12:04d}-{mon:02d}"

seen = {}
if old != "-":
    with open(old, encoding="utf-8", errors="replace") as f:
        for line in f:
            when, _, url = line.rstrip("\n").partition("\t")
            if re.fullmatch(r"\d{4}-\d{2}", when) and url and oldest <= when <= month:
                seen[url] = max(when, seen.get(url, when))
before = len(seen)
added = 0
for path in lists:
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            url = line.strip()
            if not url or "\t" in url:
                continue
            added += url not in seen
            seen[url] = month

kept = sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[:MAX]
with open(new, "w", encoding="utf-8") as out, open(urls, "w", encoding="utf-8") as train:
    for url, when in kept:
        out.write(f"{when}\t{url}\n")
        train.write(url + "\n")
print(f"memory {month}: {before} remembered, {added} new, {len(kept)} kept (since {oldest}, at most {MAX})")
