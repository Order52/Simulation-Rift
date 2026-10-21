"""Samples real page URLs from a Common Crawl index: random cluster blocks,
HTML pages that answered 200, at most PER_HOST per host."""
import collections, gzip, json, random, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor

crawl, idx_path, out_path, blocks = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
PER_HOST = 20
BASE = f"https://data.commoncrawl.org/cc-index/collections/{crawl}/indexes/"
lines = open(idx_path, encoding="utf-8").read().splitlines()
random.seed(43)
chosen = random.sample(lines, blocks)

def fetch(line):
    _, shard, off, length, _ = line.split("\t")
    off, length = int(off), int(length)
    req = urllib.request.Request(BASE + shard, headers={"Range": f"bytes={off}-{off + length - 1}"})
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return gzip.decompress(r.read()).decode("utf-8", "replace").splitlines()
        except Exception as e:
            err = e
    print("block failed:", err, file=sys.stderr)
    return []

per_host = collections.Counter()
kept = 0
with open(out_path, "w", encoding="utf-8") as out, ThreadPoolExecutor(8) as pool:
    for n, rows in enumerate(pool.map(fetch, chosen)):
        for row in rows:
            try:
                rec = json.loads(row.split(" ", 2)[2])
            except (IndexError, ValueError):
                continue
            if rec.get("status") != "200" or rec.get("mime-detected", rec.get("mime")) != "text/html":
                continue
            url = rec.get("url", "")
            if not url.startswith(("http://", "https://")) or url.endswith("/robots.txt"):
                continue
            host = url.split("/")[2].lower()
            if per_host[host] >= PER_HOST:
                continue
            per_host[host] += 1
            out.write(url + "\n")
            kept += 1
        if n % 100 == 0:
            print(f"{n} blocks, {kept} urls, {len(per_host)} hosts", file=sys.stderr, flush=True)
print(f"done: {kept} urls from {len(per_host)} hosts", file=sys.stderr)
