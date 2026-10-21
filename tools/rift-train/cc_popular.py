"""Real page URLs on the most popular domains, from a Common Crawl index:
for each domain, one random index block within its range (the index is
sorted by SURT key), up to PER_DOMAIN pages, at most PER_HOST per host."""
import bisect, collections, gzip, json, random, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor

crawl, idx_path, hosts_path, n_domains, out_path = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
PER_DOMAIN, PER_HOST = 60, 12
BASE = f"https://data.commoncrawl.org/cc-index/collections/{crawl}/indexes/"
rows = [l.split("\t") for l in open(idx_path, encoding="utf-8").read().splitlines()]
keys = [r[0].split(" ")[0] for r in rows]
random.seed(7)

def domains():
    seen = []
    for line in open(hosts_path, encoding="utf-8"):
        d = line.strip().lower()
        if d and d not in seen:
            seen.append(d)
        if len(seen) >= n_domains:
            break
    return seen

def blocks_for(domain):
    surt = ",".join(reversed(domain.split(".")))
    lo = bisect.bisect_left(keys, surt + ")")
    hi = bisect.bisect_left(keys, surt + "-")  # just past "surt)" and "surt,"
    start = max(lo - 1, 0)
    return surt, list(range(start, max(hi, start + 1)))

def fetch(domain):
    surt, candidates = blocks_for(domain)
    i = random.choice(candidates)
    _, shard, off, length, _ = rows[i][:5] if len(rows[i]) >= 5 else (None,) * 5
    if shard is None:
        return domain, []
    off, length = int(off), int(length)
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
        if not (line.startswith(surt + ")") or line.startswith(surt + ",")):
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
    return domain, urls

kept, done = 0, 0
with open(out_path, "w", encoding="utf-8") as out, ThreadPoolExecutor(8) as pool:
    for domain, urls in pool.map(fetch, domains()):
        random.shuffle(urls)
        per_host = collections.Counter()
        n = 0
        for url in urls:
            host = url.split("/")[2].lower()
            if per_host[host] >= PER_HOST or n >= PER_DOMAIN:
                continue
            per_host[host] += 1
            n += 1
            out.write(url + "\n")
        kept += n
        done += 1
        if done % 200 == 0:
            print(f"{done} domains, {kept} urls", file=sys.stderr, flush=True)
print(f"done: {kept} urls from {done} domains", file=sys.stderr)
