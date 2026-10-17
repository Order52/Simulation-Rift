"""Fixture server for the Simulation-Rift Android security tests (Phase 2).

Serves harmless test pages on localhost; the emulator reaches it through
`adb reverse tcp:8766 tcp:8766`, which also makes http://localhost:8766 a
secure context (needed for service workers and permission prompts).

Pages report what they observed with fetch("/report?test=..&key=..&value=..").
The instrumentation tests read the reports back from /results?test=..; the
app itself has no test hooks and no JavaScript bridge.

Usage: python3 -I server.py [port]
"""

import http.server
import json
import pathlib
import sys
import threading
import urllib.parse

WEB_ROOT = pathlib.Path(__file__).resolve().parent / "web"
REPORTS: dict[str, dict[str, str]] = {}
LOCK = threading.Lock()


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def send_bytes(self, body: bytes, content_type: str, extra=()):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (http.server naming)
        url = urllib.parse.urlparse(self.path)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
        if url.path == "/report":
            with LOCK:
                REPORTS.setdefault(query.get("test", ""), {})[query.get("key", "")] = query.get("value", "")
            print(f"REPORT {query.get('test')} {query.get('key')}={query.get('value')}", flush=True)
            return self.send_bytes(b"ok", "text/plain")
        if url.path == "/results":
            with LOCK:
                body = json.dumps(REPORTS.get(query.get("test", ""), {})).encode()
            return self.send_bytes(body, "application/json")
        if url.path == "/clear":
            with LOCK:
                REPORTS.pop(query.get("test", ""), None)
            return self.send_bytes(b"ok", "text/plain")
        if url.path == "/set-cookie":
            # A server-set cookie, so disposal is tested for both kinds.
            return self.send_bytes(b"ok", "text/plain", [("Set-Cookie", "rift_server_cookie=1; Max-Age=86400; Path=/")])
        if url.path == "/cacheable.js":
            body = b"window.cacheableLoaded = true;\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "max-age=86400")
            self.end_headers()
            self.wfile.write(body)
            return None
        return super().do_GET()

    def end_headers(self):
        if self.path.endswith(".html"):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"serving {WEB_ROOT} on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
