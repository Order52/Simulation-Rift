#!/usr/bin/python3 -I
"""PoC Q2 (Phase 5): the browser host's side, inside the no-network
sub-sandbox. Records what the sandbox can reach, starts the forwarder (its
own loopback, 127.0.0.1:8899, to the controller over the inherited
socketpair), then runs qt-probe.

Usage: browser-host.py proxy|direct <url> <seconds>
"""

import os
import socket
import subprocess
import sys
import threading

FORWARDER = ("127.0.0.1", 8899)


def say(message):
    print(f"host: {message}", flush=True)


def attempt(name, action):
    try:
        action()
        say(f"{name}: REACHED")
    except OSError as error:
        say(f"{name}: blocked ({error.__class__.__name__}: {error})")


def connect(address):
    with socket.create_connection(address, timeout=5):
        pass


def forward(listener, channel):
    while True:
        conn, _ = listener.accept()
        with conn:
            socket.send_fds(channel, [b"c"], [conn.fileno()])


def main():
    case, url, linger = sys.argv[1], sys.argv[2], sys.argv[3]
    channel = socket.socket(fileno=int(os.environ["RIFT_PROXY_FD"]))
    say(f"interfaces: {' '.join(sorted(os.listdir('/sys/class/net')))}")
    attempt("dns dl.flathub.org", lambda: socket.getaddrinfo("dl.flathub.org", 443))
    attempt("tcp 1.1.1.1:443", lambda: connect(("1.1.1.1", 443)))
    attempt("tcp host loopback 127.0.0.1:8765", lambda: connect(("127.0.0.1", 8765)))
    listener = socket.create_server(FORWARDER)
    threading.Thread(target=forward, args=(listener, channel), daemon=True).start()
    command = ["/app/bin/qt-probe", url, linger]
    if case == "proxy":
        command.append(f"{FORWARDER[0]}:{FORWARDER[1]}")
    sys.exit(subprocess.call(command))


main()
