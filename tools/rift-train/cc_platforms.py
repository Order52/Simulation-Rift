"""Ordinary pages on hosting platforms, from a Common Crawl index: for each
platform, BLOCKS random index blocks within its SURT range, at most
PER_HOST pages per host and PER_PLATFORM per platform. Hosts any malicious
feed lists are left out."""
import bisect, collections, gzip, json, random, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

crawl, idx_path, platforms_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
feeds = sys.argv[5:]
BLOCKS, PER_HOST, PER_PLATFORM = 8, 2, 2500
BASE = f"https://data.commoncrawl.org/cc-index/collections/{crawl}/indexes/"
rows = [l.split("\t") for l in open(idx_path, encoding="utf-8").read().splitlines()]
keys = [r[0].split(" ")[0] for r in rows]
random.seed(11)

bad = set()
for path in feeds:
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        try:
            bad.add((urlsplit(line).hostname or "").lower() if "://" in line else line.lower())
        except ValueError:
            pass

def block(i, surt):
    shard, off, length = rows[i][1], int(rows[i][2]), int(rows[i][3])
    req = urllib.request.Request(BASE + shard, headers={"Range": f"bytes={off}-{off + length - 1}"})
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                lines = gzip.decompress(r.read()).decode("utf-8", "replace").splitlines()
            break
        except Exception:
            lines = []
    urls = []
    for line in lines:
        if not line.startswith(surt + ","):  # a host under the platform
            continue
        try:
            rec = json.loads(line.split(" ", 2)[2])
        except (IndexError, ValueError):
            continue
        if rec.get("status") != "200" or rec.get("mime-detected", rec.get("mime")) != "text/html":
            continue
        url = rec.get("url", "")
        if url.startswith(("http://", "https://")) and not url.endswith("/robots.txt"):
            urls.append(url)
    return urls

def fetch(platform):
    surt = ",".join(reversed(platform.split(".")))
    lo = max(bisect.bisect_left(keys, surt + ",") - 1, 0)
    hi = max(bisect.bisect_left(keys, surt + "-"), lo + 1)
    chosen = random.sample(range(lo, hi), min(BLOCKS, hi - lo))
    urls = [u for i in chosen for u in block(i, surt)]
    return platform, hi - lo, urls

total = 0
with open(out_path, "w", encoding="utf-8") as out, ThreadPoolExecutor(8) as pool:
    for platform, nblocks, urls in pool.map(fetch, [l.strip() for l in open(platforms_path) if l.strip()]):
        random.shuffle(urls)
        per_host, n, dropped = collections.Counter(), 0, 0
        for url in urls:
            host = url.split("/")[2].split(":")[0].lower()
            if host in bad:
                dropped += 1
                continue
            if per_host[host] >= PER_HOST or n >= PER_PLATFORM:
                continue
            per_host[host] += 1
            n += 1
            out.write(url + "\n")
        total += n
        print(f"{platform}: {n} pages, {len(per_host)} hosts, {nblocks} blocks in range, {dropped} on listed hosts", file=sys.stderr, flush=True)
print(f"done: {total}", file=sys.stderr)
