"""Turns the public feeds rift-train learns from into one-entry-per-line
files (docs/reports/rift-ai.md lists each feed, its licence and date).

    python3 -I prepare.py <download-dir> <out-dir>

The download directory holds the feeds as fetched (see the report). Nothing
here is opened as a link or fetched: every line is text. Python's standard
library only; the files are never committed (they are real malicious URLs).
"""
import csv, os, sys
from urllib.parse import urlsplit

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)

def host_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""

def read_optional(name):
    """A Common Crawl sample's lines, or none before it is made (the first
    pass writes tranco-hosts.txt, which the popular sample needs)."""
    path = os.path.join(src, name)
    if not os.path.exists(path):
        print(f"{name}: not there yet, skipped")
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()

def write(name, lines):
    with open(os.path.join(out, name), "w", encoding="utf-8") as f:
        n = 0
        for line in lines:
            line = line.strip()
            if line and "\n" not in line and "\r" not in line:
                f.write(line + "\n")
                n += 1
    print(f"{name}: {n}")

# Phishing.Database, ACTIVE links (MIT). The single phishing-links-ACTIVE.txt
# stopped changing on 22 December 2025; the live list has since been the
# files in phishing-links-ACTIVE/, joined here as phishing-db-now.txt.
def links(lines):
    return [l.strip() for l in lines if l.strip().startswith(("http://", "https://"))]

phish_2025 = links(open(os.path.join(src, "phishing-db-active.txt"), encoding="utf-8", errors="replace"))
write("phishing-db.txt", phish_2025)
phish_now = links(read_optional("phishing-db-now.txt"))
write("phishing-db-now.txt", phish_now)
phish = phish_2025 + phish_now

# URLhaus hosts, through malware-filter's mirror: domains and addresses.
# Not used for the shipped model since 24 Oct 2026: abuse.ch's terms
# (s. 7.3) forbid training an AI model on its data without consent
# (docs/reports/rift-ai.md). Kept for a local experiment that has it.
malware_hosts = set()
if os.path.exists(os.path.join(src, "mf-urlhaus-filter.txt")):
    for line in open(os.path.join(src, "mf-urlhaus-filter.txt"), encoding="utf-8", errors="replace"):
        line = line.strip().lower()
        if line and not line.startswith(("!", "#")):
            malware_hosts.add(line)
    write("urlhaus-hosts.txt", sorted(malware_hosts))

# Tranco top sites (hosts, best first).
tranco = []
for line in open(os.path.join(src, "tranco", "top-1m.csv"), encoding="utf-8"):
    rank, _, domain = line.strip().partition(",")
    if domain:
        tranco.append(domain.lower())
write("tranco-hosts.txt", tranco)

# Common Crawl pages, minus any on a known malware host or listed as phishing.
listed = set(phish)
cc = []
for line in read_optional("cc-benign.txt"):
    url = line.strip()
    if url and url not in listed and host_of(url) not in malware_hosts:
        cc.append(url)
write("commoncrawl.txt", cc)

# Common Crawl pages on the most visited domains (their real sign-in, mail
# and file pages), filtered the same way: without them a model knows these
# sites only from the fakes of them in the phishing feeds.
popular = []
for line in read_optional("cc-popular.txt"):
    url = line.strip()
    if url and url not in listed and host_of(url) not in malware_hosts:
        popular.append(url)
write("commoncrawl-popular.txt", popular)

# Common Crawl pages on hosting platforms (github.io, vercel.app,
# workers.dev...), where most sites are ordinary but most of what the feeds
# list is not; filtered the same way, and also by phishing host.
phish_hosts = {host_of(u) for u in phish}
platforms = []
for line in read_optional("cc-platforms.txt"):
    url = line.strip()
    host = host_of(url)
    if url and url not in listed and host not in malware_hosts and host not in phish_hosts:
        platforms.append(url)
write("commoncrawl-platforms.txt", platforms)

# Sites on the platforms Common Crawl barely covers (pages.dev, web.app...),
# linked from GitHub READMEs (gh_platforms.py); filtered the same way. Also
# left out: hosts named like a brand or a sign-in, which on GitHub are often
# "clones" of real sites, so as benign examples they would teach the wrong
# thing even when the project means no harm.
LOOKS_LIKE_A_FAKE = ("amazon", "amzn", "paypal", "apple", "icloud", "microsoft", "office", "outlook",
                     "netflix", "facebook", "instagram", "whatsapp", "google", "gmail", "bank", "login",
                     "signin", "sign-in", "verify", "wallet", "metamask", "coinbase", "binance",
                     "steam", "roblox", "discord", "telegram", "clone")
github = []
for line in read_optional("gh-platforms.txt"):
    url = line.strip()
    host = host_of(url)
    if (url and url not in listed and host not in malware_hosts and host not in phish_hosts
            and not any(word in host for word in LOOKS_LIKE_A_FAKE)):
        github.append(url)
write("github-platforms.txt", github)

# PhiUSIIL (UCI, CC BY 4.0): label 1 is legitimate, 0 is phishing.
legit, phishing = [], []
with open(os.path.join(src, "phiusiil", "PhiUSIIL_Phishing_URL_Dataset.csv"), encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        (legit if row["label"] == "1" else phishing).append(row["URL"])
write("phiusiil-legit.txt", legit)
write("phiusiil-phishing.txt", phishing)

# Public Suffix List (MPL-2.0), both sections: each rule with its labels in
# their ASCII ("xn--") form, which is how Rift sees host names. A rule that
# does not encode is left out (and counted).
rules, failed = [], 0
for line in open(os.path.join(src, "public_suffix_list.dat"), encoding="utf-8"):
    rule = line.split()[0] if line.split() else ""
    if not rule or rule.startswith("//"):
        continue
    prefix = "!" if rule.startswith("!") else ""
    try:
        rules.append(prefix + ".".join(
            label if label == "*" else label.encode("idna").decode("ascii").lower()
            for label in rule[len(prefix):].split(".")))
    except UnicodeError:
        failed += 1
write("psl-ascii.txt", rules)
print(f"psl-ascii.txt: {failed} rules did not encode")
