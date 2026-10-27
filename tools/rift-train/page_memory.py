"""Rift AI's memory of fetched pages (docs/reports/page-model.md, "Learning
from new pages"): each monthly retrain adds the month's counted pages to the
memory the last run left, so pages that have since gone offline keep
teaching the page model. A page seen again replaces its older copy; pages
not seen for MONTHS months are dropped, and at most MAX are kept, the most
recent first.

The memory holds counts, not pages: `YYYY-MM<TAB>label<TAB>url<TAB>report`
lines, the report being what the browser's script would send (numbers, the
title and the start of the text). It lives outside the repository (the
retrain workflow keeps it as an artifact).

usage: python3 -I page_memory.py <month YYYY-MM> <old memory or -> <new memory> <training counts> <this month's counts>
Writes the new memory, and every page in it as `rift-train page` counts.
"""
import re
import sys

MONTHS = 24
MAX = 300_000

if len(sys.argv) != 6:
    sys.exit(__doc__)
month, old, new, training, fresh = sys.argv[1:]
if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
    sys.exit(__doc__)
year, mon = map(int, month.split("-"))
oldest = f"{year - MONTHS // 12:04d}-{mon:02d}"

pages = {}
if old != "-":
    with open(old, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t", 3)
            if len(parts) == 4 and re.fullmatch(r"\d{4}-\d{2}", parts[0]) and oldest <= parts[0] <= month \
                    and parts[1] in ("0", "1"):
                pages[parts[2]] = parts
before = len(pages)
added = 0
with open(fresh, encoding="utf-8", errors="replace") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t", 2)
        if len(parts) == 3 and parts[0] in ("0", "1"):
            pages[parts[1]] = [month, *parts]
            added += 1
kept = sorted(pages.values(), key=lambda p: p[0], reverse=True)[:MAX]
with open(new, "w", encoding="utf-8") as m, open(training, "w", encoding="utf-8") as t:
    for when, label, url, report in kept:
        m.write(f"{when}\t{label}\t{url}\t{report}\n")
        t.write(f"{label}\t{url}\t{report}\n")
phishing = sum(1 for p in kept if p[1] == "1")
print(f"Page memory: {before} pages from earlier months, {added} this month; "
      f"{len(kept)} kept ({phishing} phishing, {len(kept) - phishing} legitimate).")
