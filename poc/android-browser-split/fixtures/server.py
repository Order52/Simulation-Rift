"""Fixture for the browser-split PoC: serves page.html, logs every request
(so a probe that got through is visible here), takes reports, and listens
for STUN datagrams on UDP 3478 (WebRTC bypassing the proxy)."""
import http.server
import socket
import sys
import threading
import time

PORT = int(sys.argv[1])
HERE = __file__.rsplit("/", 1)[0]


def log(line):
    print(f"{time.strftime('%H:%M:%S')} {line}", flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        log(f"GET {self.path} from {self.client_address[0]} via-host={self.headers.get('Host')}")
        if self.path.startswith("/page.html"):
            with open(f"{HERE}/page.html", "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        else:
            body = b"probe"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8", "replace")
        log(f"REPORT {body}")
        self.send_response(204)
        self.end_headers()


def stun():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 3478))
    while True:
        data, addr = s.recvfrom(2048)
        log(f"UDP {len(data)} bytes on 3478 from {addr[0]}:{addr[1]} (STUN type 0x{data[:2].hex()})")


threading.Thread(target=stun, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
