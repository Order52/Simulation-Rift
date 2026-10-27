"""Fetches pages for Rift AI's page model (docs/reports/page-model.md,
"Learning from new pages"): the HTML of today's phishing pages and of
ordinary pages, as a phone's browser asks for them, for `rift-train page
counts`. Only the HTML is read: nothing in it is run, rendered or followed.

Phishing and ordinary pages go through the same fetch and the same filters,
so the model cannot tell them apart by how they were fetched. A page is
kept only if it answered 200 with HTML, stayed on the site it was linked
as (a kit that sends visitors elsewhere shows nothing of itself), is not a
hosting error, parking or bot-check page, and is not a byte-for-byte copy
of one already kept.

Addresses that resolve to private, loopback, link-local or other non-public
networks are refused, before connecting and at every redirect, so a link
cannot reach the machine's own network.

usage: python3 -I fetch_pages.py <out-dir> <max-per-label> <seed> --phishing <urls>... --legit <urls>...

Writes <out-dir>/pages/<n>.html and <out-dir>/index.tsv (url, file, label:
1 phishing, 0 legitimate; the url is where the page was finally found).
"""
import concurrent.futures
import hashlib
import http.client
import ipaddress
import os
import random
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 2 * 1024 * 1024
MIN_BYTES = 512
TIMEOUT = 15
WORKERS = 32
USER_AGENT = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
# Pages that are not the site's own: hosting errors, parking, bot checks.
NOT_A_PAGE = re.compile(
    r"account (has been )?suspended|website (is )?suspended|suspendedpage|"
    r"\b40[34]\b|not found|forbidden|index of /|domain (is )?for sale|"
    r"parked|coming soon|under construction|default web ?site page|it works!|"
    r"welcome to nginx|attention required|just a moment|access denied|"
    r"this (site|page) (can.?t|cannot) be reached|has been (disabled|removed|deleted)",
    re.I)
TITLE = re.compile(rb"<title[^>]*>(.{0,300}?)</title", re.I | re.S)


def site(host):
    """The last two labels (three under a short second level), as rift_core::pagemodel::site_key."""
    labels = host.lower().rstrip(".").split(".")
    if labels and labels[0] == "www":
        labels = labels[1:]
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else 2
    return ".".join(labels[-n:])


def public(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)


class Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        if u.scheme not in ("http", "https") or not u.hostname or not public(u.hostname):
            raise urllib.error.HTTPError(newurl, code, "redirect refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


CONTEXT = ssl.create_default_context()
# Phishing and ordinary sites alike are read whatever their certificate:
# a rule on certificates would teach the model the fetch, not the page.
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE
OPENER = urllib.request.build_opener(Redirects, urllib.request.HTTPSHandler(context=CONTEXT))


def fetch(url):
    """(final url, body) or (None, why)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return None, "not a web address"
    if not public(u.hostname):
        return None, "not a public address"
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    try:
        with OPENER.open(req, timeout=TIMEOUT) as r:
            if r.status != 200:
                return None, f"status {r.status}"
            if "html" not in (r.headers.get("Content-Type") or "").lower():
                return None, "not HTML"
            body = r.read(MAX_BYTES)
            final = r.geturl()
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
        return None, type(e).__name__
    host = urllib.parse.urlsplit(final).hostname or ""
    if site(host) != site(u.hostname):
        return None, "left the site"
    if len(body) < MIN_BYTES:
        return None, "too short"
    title = TITLE.search(body[:65536])
    if title and NOT_A_PAGE.search(title.group(1).decode("utf-8", "replace")):
        return None, "not the site's own page"
    return final, body


def main(argv):
    if len(argv) < 6 or "--phishing" not in argv or "--legit" not in argv:
        sys.exit(__doc__)
    out, most, seed = argv[0], int(argv[1]), argv[2]
    rest = argv[3:]
    p, l = rest.index("--phishing"), rest.index("--legit")
    files = {1: rest[p + 1:l] if p < l else rest[p + 1:],
             0: rest[l + 1:p] if l < p else rest[l + 1:]}
    os.makedirs(os.path.join(out, "pages"), exist_ok=True)
    rng = random.Random(seed)
    jobs = []
    for label, paths in files.items():
        urls = set()
        for path in paths:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith("#") and "\t" not in url:
                        urls.add(url if "://" in url else "http://" + url)
        # One page per site, so no site outweighs the others.
        by_site = {}
        for url in sorted(urls):
            host = urllib.parse.urlsplit(url).hostname
            if host:
                by_site.setdefault(site(host), []).append(url)
        chosen = [rng.choice(v) for v in by_site.values()]
        rng.shuffle(chosen)
        jobs += [(label, url) for url in chosen[:most]]
    seen, kept, why = set(), {0: 0, 1: 0}, {}
    with open(os.path.join(out, "index.tsv"), "a", encoding="utf-8") as index, \
            concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
        futures = {pool.submit(fetch, url): (label, url) for label, url in jobs}
        for n, future in enumerate(concurrent.futures.as_completed(futures)):
            label, _ = futures[future]
            final, body = future.result()
            if final is None:
                why[(label, body)] = why.get((label, body), 0) + 1
                continue
            digest = hashlib.sha256(body).hexdigest()
            if digest in seen or "\t" in final or "\n" in final:
                why[(label, "a copy")] = why.get((label, "a copy"), 0) + 1
                continue
            seen.add(digest)
            name = f"{label}-{n}.html"
            with open(os.path.join(out, "pages", name), "wb") as f:
                f.write(body)
            index.write(f"{final}\t{name}\t{label}\n")
            kept[label] += 1
    for label, name in ((1, "phishing"), (0, "legitimate")):
        tried = sum(1 for j in jobs if j[0] == label)
        reasons = ", ".join(f"{r} {c}" for (lb, r), c in sorted(why.items(), key=lambda x: -x[1]) if lb == label)
        print(f"{name}: {kept[label]} kept of {tried} tried; left out: {reasons or 'none'}")


if __name__ == "__main__":
    main(sys.argv[1:])
