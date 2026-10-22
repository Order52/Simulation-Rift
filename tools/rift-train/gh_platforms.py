"""Ordinary sites on hosting platforms Common Crawl barely covers (pages.dev,
web.app...), from links in GitHub READMEs: projects link their own demo,
documentation and blog sites there. Uses GitHub's code search through the
`gh` CLI (signed in), which returns at most 1,000 results per query, so each
platform is searched in slices of README size. At most PER_HOST links per
host; hosts any malicious feed lists are left out.

usage: python3 -I gh_platforms.py <platform,...> <out.txt> <feed>...
"""
import json, re, subprocess, sys, time
from urllib.parse import urlsplit

platforms = sys.argv[1].split(",")
out_path = sys.argv[2]
feeds = sys.argv[3:]
PER_HOST = 2
# README sizes in bytes; each slice is its own search of up to 1,000 results.
SLICES = ["<1500", "1500..3000", "3000..5000", "5000..8000", "8000..12000",
          "12000..20000", "20000..40000", ">40000"]

bad = set()
for path in feeds:
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        try:
            bad.add((urlsplit(line).hostname or "").lower() if "://" in line else line.lower())
        except ValueError:
            pass


def search(query, page):
    """One page of code search results with text fragments; waits out the rate limit."""
    for attempt in range(6):
        r = subprocess.run(
            ["gh", "api", "-X", "GET", "search/code", "-f", f"q={query}", "-f", "per_page=100", "-f", f"page={page}",
             "-H", "Accept: application/vnd.github.text-match+json"],
            capture_output=True, text=True)
        if r.returncode == 0:
            return json.loads(r.stdout)
        if "rate limit" in r.stderr.lower() or "403" in r.stderr or "429" in r.stderr:
            time.sleep(20 * (attempt + 1))
            continue
        if "422" in r.stderr:  # past the last page GitHub serves
            return None
        print(f"search failed: {r.stderr.strip()[:200]}", file=sys.stderr)
        time.sleep(10)
    return None


per_host = {}
urls = []
for platform in platforms:
    link = re.compile(r"https?://[a-z0-9][a-z0-9.-]*\." + re.escape(platform) + r"(?:/[^\s\"'<>)\]`]*)?", re.I)
    found = 0
    for size in SLICES:
        for page in range(1, 11):
            result = search(f'"{platform}" filename:README.md size:{size}', page)
            if not result or not result.get("items"):
                break
            for item in result["items"]:
                for match in item.get("text_matches", []):
                    for url in link.findall(match.get("fragment", "")):
                        url = url.rstrip(".,;:!?*")
                        try:
                            host = (urlsplit(url).hostname or "").lower()
                        except ValueError:
                            continue
                        if not host.endswith("." + platform) or host in bad:
                            continue
                        if per_host.get(host, 0) >= PER_HOST:
                            continue
                        per_host[host] = per_host.get(host, 0) + 1
                        urls.append(url)
                        found += 1
            time.sleep(6.5)  # code search allows about ten requests a minute
    print(f"{platform}: {found} links on {sum(1 for h in per_host if h.endswith('.' + platform))} hosts", file=sys.stderr)

with open(out_path, "w", encoding="utf-8") as f:
    f.write("\n".join(urls) + "\n")
