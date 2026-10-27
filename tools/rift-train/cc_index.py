"""Reads blocks of a Common Crawl index for the samplers (cc_sample.py,
cc_popular.py, cc_platforms.py). Common Crawl answers 503 or 429 when it is
busy, so a block is retried with growing waits, and the samplers fail when
too many blocks could not be read: a sample short of a whole kind of page
teaches the model that kind is not ordinary (as on 26 October 2026, when an
empty sample of hosting-platform pages had platform sites flagged)."""
import gzip, random, sys, threading, time, urllib.error, urllib.request

TRIES = 7
MAX_FAILED = 0.05

_lock = threading.Lock()
asked = failed = 0


def block(crawl, shard, off, length):
    """The lines of one index block, or [] if it could not be read."""
    global asked, failed
    req = urllib.request.Request(
        f"https://data.commoncrawl.org/cc-index/collections/{crawl}/indexes/{shard}",
        headers={"Range": f"bytes={off}-{off + length - 1}", "User-Agent": "rift-train (sampling ordinary pages)"})
    err = None
    for attempt in range(TRIES):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                lines = gzip.decompress(r.read()).decode("utf-8", "replace").splitlines()
            with _lock:
                asked += 1
            return lines
        except Exception as e:
            err = e
            wait = min(60, 2 ** attempt) + random.random()
            if isinstance(e, urllib.error.HTTPError) and e.code in (429, 503):
                retry = e.headers.get("Retry-After", "")
                wait = max(wait, min(120, int(retry))) if retry.isdigit() else wait
            time.sleep(wait)
    with _lock:
        asked += 1
        failed += 1
    print(f"block failed after {TRIES} tries: {err}", file=sys.stderr, flush=True)
    return []


def check(name):
    """Exits with an error if more than MAX_FAILED of the blocks failed."""
    print(f"{name}: {asked - failed} of {asked} index blocks read", file=sys.stderr, flush=True)
    if asked and failed > MAX_FAILED * asked:
        sys.exit(f"{name}: {failed} of {asked} index blocks could not be read; the sample would be lopsided")
