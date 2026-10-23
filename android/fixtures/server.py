"""Fixture server for the Simulation-Rift Android security tests (Phase 2).

Serves harmless test pages on localhost; the emulator reaches it through
`adb reverse tcp:8766 tcp:8766`, which also makes http://localhost:8766 a
secure context (needed for service workers and permission prompts).

Pages report what they observed with fetch("/report?test=..&key=..&value=..").
The instrumentation tests read the reports back from /results?test=..; the
app itself has no test hooks and no JavaScript bridge.

For the network lock (S25, S26) the server also records every request for
/hit/<name>, whichever address it arrived on, and every datagram on UDP
3478 (where test pages point WebRTC's STUN and the escape probe sends UDP).
The emulator reaches both on the host's loopback through 10.0.2.2, so an
arrival means something got past the lock. /arrivals lists them and
/arrivals/clear empties the list.

Usage: python3 -I server.py [port]
"""

import http.server
import json
import pathlib
import socket
import sys
import struct
import threading
import urllib.parse
import zlib

WEB_ROOT = pathlib.Path(__file__).resolve().parent / "web"
REPORTS: dict[str, dict[str, str]] = {}
HELLO = b"harmless download fixture\n" * 40
PRIVATE = b"cookie-gated fixture\n" * 50
SESSION_COOKIE = "rift_login=1"
BIG = 101 * 1024 * 1024  # just over the 100 MiB per-object limit
LOCK = threading.Lock()
ARRIVALS: list[str] = []
STUN_PORT = 3478
# Embedded in the preview fixtures, so plaintext left on disk can be searched for.
MARKER = b"RIFT-PREVIEW-PLAINTEXT-MARKER"
# Byte for byte rift_pack::DEMO_FILE: the demo database's hash and marker
# rule match it (S21). Harmless text.
DEMO_FILE = b"Simulation-Rift demo file. It is harmless. RIFT-DEMO-MARKER\n"


def png(width: int, height: int) -> bytes:
    """An RGB gradient with MARKER in a tEXt chunk."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(
        b"\0" + bytes(v for x in range(width) for v in (x * 255 // width, y * 255 // height, 128))
        for y in range(height)
    )
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"tEXt", b"Comment\0" + MARKER)
            + chunk(b"IDAT", zlib.compress(rows))
            + chunk(b"IEND", b""))


def pdf() -> bytes:
    """One US-letter page with a filled box and MARKER as text; xref offsets exact."""
    content = b"0 0 1 rg 72 600 468 120 re f BT /F1 18 Tf 72 500 Td (" + MARKER + b") Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


PICTURE = png(300, 200)
DOCUMENT = pdf()


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
        if url.path.startswith("/hit/"):
            with LOCK:
                ARRIVALS.append(f"tcp {url.path[5:]} host={self.headers.get('Host')}")
            print(f"HIT {url.path} Host={self.headers.get('Host')}", flush=True)
            return self.send_bytes(b"hit", "text/plain", [("Access-Control-Allow-Origin", "*")])
        if url.path == "/echo-headers":
            # What the browser sent with this request: names and values, so a test can look for what it must not send.
            body = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
            return self.send_bytes(body, "application/json")
        if url.path == "/arrivals":
            with LOCK:
                body = json.dumps(ARRIVALS).encode()
            return self.send_bytes(body, "application/json")
        if url.path == "/arrivals/clear":
            with LOCK:
                ARRIVALS.clear()
            return self.send_bytes(b"ok", "text/plain")
        if url.path == "/clear":
            with LOCK:
                REPORTS.pop(query.get("test", ""), None)
            return self.send_bytes(b"ok", "text/plain")
        if url.path == "/set-cookie":
            # A server-set cookie, so disposal is tested for both kinds.
            return self.send_bytes(b"ok", "text/plain", [("Set-Cookie", "rift_server_cookie=1; Max-Age=86400; Path=/")])
        if url.path == "/files/hello.txt":
            return self.send_bytes(HELLO, "text/plain", [("Content-Disposition", 'attachment; filename="hello.txt"')])
        if url.path == "/files/picture.png":
            return self.send_bytes(PICTURE, "image/png", [("Content-Disposition", 'attachment; filename="picture.png"')])
        if url.path == "/files/document.pdf":
            return self.send_bytes(DOCUMENT, "application/pdf", [("Content-Disposition", 'attachment; filename="document.pdf"')])
        if url.path == "/files/notes.txt":
            # Text with a CRLF, a terminal escape and a right-to-left override.
            body = "line one\r\nline two \x1b[31mred\x1b[0m \u202eesrever\n".encode("utf-8") + MARKER
            return self.send_bytes(body, "text/plain; charset=utf-8", [("Content-Disposition", 'attachment; filename="notes.txt"')])
        if url.path == "/files/demo-file.txt":
            return self.send_bytes(DEMO_FILE, "text/plain", [("Content-Disposition", 'attachment; filename="demo-file.txt"')])
        if url.path == "/files/invoice.pdf":
            # Executable header under a document name (a type mismatch, §12.1); not a real program.
            return self.send_bytes(b"MZ\x90\x00" + b"\x00" * 60 + b"not a real program", "application/pdf",
                                   [("Content-Disposition", 'attachment; filename="invoice.pdf"')])
        if url.path == "/files/broken.png":
            # A PNG signature followed by garbage: the worker must fail cleanly.
            return self.send_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8, "image/png",
                                   [("Content-Disposition", 'attachment; filename="broken.png"')])
        if url.path == "/files/hostile":
            # Traversal plus a right-to-left override, as raw UTF-8 bytes.
            name = 'attachment; filename="../../evil\u202egpj.pdf"'.encode("utf-8").decode("latin-1")
            return self.send_bytes(b"%PDF-1.4 fixture", "application/pdf", [("Content-Disposition", name)])
        if url.path == "/files/to-loopback":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/files/hello.txt")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        if url.path == "/login":
            self.send_response(302)
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}; Path=/; HttpOnly")
            self.send_header("Location", query.get("next", "/"))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        if url.path == "/files/private.bin":
            if SESSION_COOKIE not in (self.headers.get("Cookie") or ""):
                self.send_response(403)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            return self.send_bytes(PRIVATE, "application/octet-stream", [("Content-Disposition", 'attachment; filename="private.bin"')])
        if url.path == "/files/big":
            # No Content-Length: the stream itself must be cut at the limit.
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="big.bin"')
            self.send_header("Connection", "close")
            self.end_headers()
            chunk = bytes(1024 * 1024)
            try:
                for _ in range(BIG // len(chunk)):
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the client stopped reading at its limit
            return None
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


def listen_udp() -> None:
    """Records every datagram: none may arrive while the lock holds."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", STUN_PORT))
    while True:
        data, address = udp.recvfrom(2048)
        with LOCK:
            ARRIVALS.append(f"udp {len(data)} bytes from {address[0]}:{address[1]} starting {data[:24]!r}")
        print(f"UDP {len(data)} bytes on {STUN_PORT} from {address[0]}:{address[1]}", flush=True)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
    threading.Thread(target=listen_udp, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"serving {WEB_ROOT} on http://127.0.0.1:{port}, UDP on {STUN_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
