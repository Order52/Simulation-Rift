#!/usr/bin/python3 -I
"""PoC Q2 (Phase 5): the controller's half of the network lock for Qt.

Runs as the Flatpak's main process, which keeps the app's network. It
starts the browser host (browser-host.py, then qt-probe) in a sub-sandbox
with no network (flatpak-spawn --sandbox --no-network) and hands it one end
of a socketpair. The host's forwarder sends each connection the engine makes
to its proxy over that socketpair (SCM_RIGHTS); this process answers it as
an HTTP proxy that knows one destination. In the product this is rift-core's
checking egress proxy; here it only shows the path works.

Usage: controller.py proxy|proxy-offscreen|direct <seconds to stay open>
  proxy            the engine is told to use the forwarder; the page must load
  proxy-offscreen  the same with Qt's offscreen platform (no display needed)
  direct           no proxy, offscreen: the engine connects itself, so the
                   page must not load
"""

import os
import select
import socket
import subprocess
import sys
import threading

HOST_PAGE = ("127.0.0.1", 8765)
# The only destination this proxy serves. A name, not 127.0.0.1: Chromium
# never sends loopback addresses to a proxy.
KNOWN = {"rift-probe.test:8765": HOST_PAGE}
MAX_HEAD = 16 * 1024


def log(message):
    print(f"controller: {message}", flush=True)


def relay(a, b):
    sockets = [a, b]
    while True:
        readable, _, _ = select.select(sockets, [], [], 60)
        if not readable:
            return
        for source in readable:
            data = source.recv(65536)
            if not data:
                return
            (b if source is a else a).sendall(data)


def handle(conn):
    with conn:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            if not chunk or len(head) + len(chunk) > MAX_HEAD:
                log("refused: no complete request head")
                return
            head += chunk
        request_line, _, rest = head.partition(b"\r\n")
        try:
            method, target, version = request_line.decode("ascii").split(" ")
        except ValueError:
            log(f"refused: malformed request line {request_line[:80]!r}")
            return
        # Plain HTTP in absolute form only: the probe page needs no more.
        authority, origin_form = target, None
        if method != "CONNECT" and target.startswith("http://"):
            authority, _, path = target[len("http://"):].partition("/")
            origin_form = f"{method} /{path} {version}".encode("ascii")
        if origin_form is None or authority not in KNOWN:
            log(f"refused {method} {target}")
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        log(f"allowed {method} {target}")
        with socket.create_connection(KNOWN[authority], timeout=10) as upstream:
            upstream.sendall(origin_form + b"\r\n" + rest)
            relay(conn, upstream)


def serve(channel):
    while True:
        try:
            message, fds, _, _ = socket.recv_fds(channel, 1, 4)
        except OSError as error:
            log(f"channel closed: {error}")
            return
        if not message:
            return
        for fd in fds:
            threading.Thread(target=handle, args=(socket.socket(fileno=fd),), daemon=True).start()


def main():
    case, linger = sys.argv[1], sys.argv[2]
    # Control: this process reaches the page directly, so a failure inside
    # the sub-sandbox is the lock and not a missing server.
    with socket.create_connection(HOST_PAGE, timeout=5):
        log(f"reaches {HOST_PAGE[0]}:{HOST_PAGE[1]} directly")
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    os.set_inheritable(theirs.fileno(), True)
    url = "http://rift-probe.test:8765/" if case.startswith("proxy") else "http://127.0.0.1:8765/"
    command = [
        "flatpak-spawn", "--sandbox", "--no-network", "--watch-bus",
        "--sandbox-flag=share-display", "--sandbox-flag=share-gpu", "--sandbox-flag=allow-dbus",
        f"--forward-fd={theirs.fileno()}",
        f"--env=RIFT_PROXY_FD={theirs.fileno()}",
        "--env=QTWEBENGINEPROCESS_PATH=/app/bin/QtWebEngineProcess",
    ]
    if case == "proxy":
        for name in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY"):
            if name in os.environ:
                command.append(f"--env={name}={os.environ[name]}")
    else:
        command.append("--env=QT_QPA_PLATFORM=offscreen")
    command += ["/app/bin/browser-host.py", case, url, linger]
    log(f"spawning: {' '.join(command)}")
    child = subprocess.Popen(command, pass_fds=(theirs.fileno(),))
    theirs.close()
    threading.Thread(target=serve, args=(ours,), daemon=True).start()
    status = child.wait()
    log(f"browser host exit {status}")
    sys.exit(status)


main()
