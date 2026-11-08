"""Rift AI's memory of phishing pages (docs/reports/rift-ai.md, "Learning
from new data"): each monthly retrain adds the month's prepared phishing
URLs to the memory the last run left, so pages that have since gone offline
keep teaching the model. Entries not seen for MONTHS months are dropped,
and at most MAX entries are kept, the most recently seen first.

The memory is a list of `YYYY-MM<TAB>url` lines (the month each URL was
last seen). It holds real malicious URLs: it lives outside the repository
(the retrain workflow keeps it as an artifact), never in it.

The training file has one `url<TAB>weight` line per URL: a page last seen on
a feed this month weighs 1, and the weight halves every HALF_LIFE months
since (never under FLOOR), so the model leans on what phishing looks like now
and keeps what older pages taught it. RIFT_AI_HALF_LIFE_MONTHS=0 gives every
URL weight 1. URLs listed in the file named by RIFT_AI_EXCLUDE (the forward
test's links, retrain.sh) stay in the memory but are left out of the training
file this once.

usage: python3 -I memory.py <month YYYY-MM> <old memory or -> <new memory> <training urls> <prepared list>...
"""
import os
import re
import sys

MONTHS = 24
MAX = 1_500_000
FLOOR = 0.1


def months_between(then, now):
    (y0, m0), (y1, m1) = (map(int, x.split("-")) for x in (then, now))
    return (y1 - y0) * 12 + (m1 - m0)


def weight(then, now, half_life):
    if half_life <= 0:
        return 1.0
    return max(FLOOR, 0.5 ** (months_between(then, now) / half_life))


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

half_life = float(os.environ.get("RIFT_AI_HALF_LIFE_MONTHS", "6"))
excluded = set()
if os.environ.get("RIFT_AI_EXCLUDE"):
    with open(os.environ["RIFT_AI_EXCLUDE"], encoding="utf-8", errors="replace") as f:
        excluded = {line.strip() for line in f}

kept = sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[:MAX]
with open(new, "w", encoding="utf-8") as out, open(urls, "w", encoding="utf-8") as train:
    for url, when in kept:
        out.write(f"{when}\t{url}\n")
        if url not in excluded:
            train.write(f"{url}\t{weight(when, month, half_life):.3f}\n")
print(f"memory {month}: {before} remembered, {added} new, {len(kept)} kept (since {oldest}, at most {MAX})")
