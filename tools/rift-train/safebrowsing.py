"""Which links Google Safe Browsing flags (docs/reports/check-accuracy.md,
"Against Safe Browsing"): a maintainer's measurement, never the app's. Rift
sends nothing to Google (INV-11); this asks the Safe Browsing Lookup API
(v4) about public feed links and a public crawl sample, once, for the
comparison.

    SAFE_BROWSING_KEY=... python3 -I safebrowsing.py <links.txt>... <flagged.txt>

The key is read from the environment so it is not in the process list or a
shell history. Writes each link Safe Browsing matched, as given, one a line.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
BATCH = 500  # the API's limit of entries per request
TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def ask(key, links):
    body = json.dumps({
        "client": {"clientId": "rift-compare", "clientVersion": "1"},
        "threatInfo": {
            "threatTypes": TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": link} for link in links],
        },
    }).encode()
    request = urllib.request.Request(API + key, body, {"Content-Type": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                answer = json.load(response)
            return {m["threat"]["url"] for m in answer.get("matches", [])}
        except urllib.error.HTTPError as error:
            # The key never appears in what is printed.
            if error.code not in (429, 500, 503) or attempt == 3:
                sys.exit(f"safebrowsing: HTTP {error.code}")
        except urllib.error.URLError as error:
            if attempt == 3:
                sys.exit(f"safebrowsing: {error.reason}")
        time.sleep(2 ** attempt * 5)
    return set()


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    key = os.environ.get("SAFE_BROWSING_KEY", "").strip()
    if not key:
        sys.exit("safebrowsing: set SAFE_BROWSING_KEY")
    *inputs, out = sys.argv[1:]
    links = []
    for path in inputs:
        with open(path, encoding="utf-8", errors="replace") as f:
            links += [line.strip() for line in f if line.strip()]
    links = list(dict.fromkeys(links))
    flagged = set()
    for at in range(0, len(links), BATCH):
        flagged |= ask(key, links[at:at + BATCH])
    with open(out, "w", encoding="utf-8") as f:
        f.writelines(link + "\n" for link in links if link in flagged)
    print(f"Safe Browsing flagged {len(flagged)} of {len(links)} links", file=sys.stderr)


main()
