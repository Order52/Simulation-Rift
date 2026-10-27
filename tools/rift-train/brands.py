"""Chooses the brands Check protects (models/brands.txt; architecture §10.3)
from today's feeds: the well-known sites whose names phishing addresses use
far more often than ordinary addresses do. The hand-picked brands are always
kept; the learned ones are those that

- are among the TOP most visited sites (Tranco), with a name of five letters
  or more (shorter names are too often parts of other words),
- are not an ordinary word (in the dictionary, or one of the check's own
  lure words: `login.gov` would make every `login-` host a fake),
- are named, as the check reads hosts (the brand as a word, or joined to a
  lure word: `paypal-help`, `paypalsecure`), in the host of at least
  MIN_SITES phishing sites that are not the brand's own, and
- are named in phishing sites' hosts at least RATIO times as often, as a
  share of all sites, as in ordinary sites' hosts.

Names in brands-never.txt (products people run on their own sites, and
publishing platforms) are never learned.

usage: python3 -I brands.py <tranco hosts, ranked> <hand-picked> <never> <heuristics.rs> <words> <out> --phishing <urls>... --legit <urls>...
"""
import re
import sys
import urllib.parse

TOP = 20_000
MIN_SITES = 15
RATIO = 20
MAX_LEARNED = 200


def site(host):
    labels = host.lower().rstrip(".").split(".")
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else 2
    return ".".join(labels[-n:])


def hosts(paths):
    out = set()
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("\t")[0].strip()
                if not line or line.startswith("#"):
                    continue
                host = urllib.parse.urlsplit(line if "://" in line else "http://" + line).hostname
                if host and re.fullmatch(r"[a-z0-9.-]+", host):
                    out.add(host)
    return out


def words(host):
    labels = host.split(".")
    return [w for label in labels[:-1] for w in label.split("-") if w]


def named(host, brand, lures):
    """As rift_core::heuristics::brand_in: a word of the host is the brand, or the brand joined to a lure."""
    def joined(w):
        return len(brand) >= 4 and ((w.startswith(brand) and w[len(brand):] in lures)
                                    or (w.endswith(brand) and w[:-len(brand)] in lures))
    return any(w == brand or joined(w) for w in words(host))


def main(argv):
    if len(argv) < 10 or "--phishing" not in argv or "--legit" not in argv:
        sys.exit(__doc__)
    ranked, curated_path, never_path, rust, words_path, out = argv[:6]
    rest = argv[6:]
    with open(rust, encoding="utf-8") as f:
        block = re.search(r"const LURES: &\[&str\] = &\[(.*?)\];", f.read(), re.S)
    if not block:
        sys.exit("brands: LURES not found in " + rust)
    lures = set(re.findall(r'"([a-z]+)"', block.group(1)))
    with open(words_path, encoding="utf-8", errors="replace") as f:
        ordinary = {w.strip().lower() for w in f} | lures
    with open(never_path, encoding="utf-8") as f:
        ordinary |= {w.strip() for w in f if w.strip() and not w.startswith("#")}
    p, l = rest.index("--phishing"), rest.index("--legit")
    phishing = hosts(rest[p + 1:l] if p < l else rest[p + 1:])
    legit = hosts(rest[l + 1:p] if l < p else rest[l + 1:])
    with open(curated_path, encoding="utf-8") as f:
        curated = [d.strip() for d in f if d.strip() and not d.startswith("#")]
    picked = {d.split(".")[0] for d in curated}
    brands = {}
    with open(ranked, encoding="utf-8") as f:
        for n, line in enumerate(f):
            if n >= TOP:
                break
            domain = line.strip().split(",")[-1].lower()
            brand = domain.split(".")[0]
            if len(brand) >= 5 and brand.isalpha() and brand not in brands and brand not in ordinary \
                    and brand not in picked:
                brands[brand] = domain
    # Each site counts once, whatever number of its addresses a feed lists.
    by_brand = {b: [set(), set()] for b in brands}
    index = {}
    for b in brands:
        index.setdefault(b[:3], []).append(b)
    for label, pool in ((0, phishing), (1, legit)):
        for host in pool:
            text = " ".join(words(host))
            for b in {b for i in range(len(text) - 2) for b in index.get(text[i:i + 3], ())}:
                d = brands[b]
                if host != d and not host.endswith("." + d) and named(host, b, lures):
                    by_brand[b][label].add(site(host))
    phishing_sites = max(1, len({site(h) for h in phishing}))
    legit_sites = max(1, len({site(h) for h in legit}))
    learned = []
    for b, (bad, good) in by_brand.items():
        if len(bad) >= MIN_SITES and len(bad) / phishing_sites >= RATIO * len(good) / legit_sites:
            learned.append((len(bad), len(good), brands[b]))
    learned.sort(reverse=True)
    chosen = [d for _, _, d in learned if d not in curated][:MAX_LEARNED]
    with open(out, "w", encoding="utf-8") as f:
        f.write("# The brands Check protects (docs/architecture.md §10.3): the hand-picked ones\n")
        f.write("# (tools/rift-train/brands-picked.txt), then those today's phishing addresses\n")
        f.write(f"# fake most, written by tools/rift-train/brands.py from {len(phishing)} phishing\n")
        f.write(f"# and {len(legit)} ordinary hosts. One registrable domain per line; a learned one is\n")
        f.write("# marked `learned` and protects addresses only, not page names (§10.5).\n")
        for d in curated:
            f.write(d + "\n")
        for bad, good, d in learned:
            if d in chosen:
                f.write(f"{d} learned  # {bad} phishing sites, {good} ordinary\n")
    print(f"brands: {len(curated)} hand-picked, {len(chosen)} learned from {phishing_sites} phishing "
          f"and {legit_sites} ordinary sites")


if __name__ == "__main__":
    main(sys.argv[1:])
