#!/usr/bin/python3 -I
"""PoC Q2 (Phase 5): the browser host's side, inside the no-network
sub-sandbox. Records what the sandbox can reach, starts the forwarder (its
own loopback, 127.0.0.1:8899, to the controller over the inherited
socketpair), then runs qt-probe.

Usage: browser-host.py proxy|proxy-offscreen|direct <url> <seconds>
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
    # /proc/net/dev lists this process's network namespace; /sys/class/net
    # shows whichever namespace sysfs was mounted in (the host's here).
    with open("/proc/net/dev") as dev:
        names = [line.split(":")[0].strip() for line in dev.readlines()[2:]]
    say(f"interfaces: {' '.join(sorted(names))}")
    for name in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "QT_QPA_PLATFORM"):
        value = os.environ.get(name)
        exists = f" (exists: {os.path.exists(value)})" if name == "XAUTHORITY" and value else ""
        say(f"{name}={value}{exists}")
    try:
        say(f"/tmp/.X11-unix: {' '.join(sorted(os.listdir('/tmp/.X11-unix')))}")
    except OSError as error:
        say(f"/tmp/.X11-unix: {error}")
    attempt("dns dl.flathub.org", lambda: socket.getaddrinfo("dl.flathub.org", 443))
    attempt("tcp 1.1.1.1:443", lambda: connect(("1.1.1.1", 443)))
    attempt("tcp host loopback 127.0.0.1:8765", lambda: connect(("127.0.0.1", 8765)))
    listener = socket.create_server(FORWARDER)
    threading.Thread(target=forward, args=(listener, channel), daemon=True).start()
    command = ["/app/bin/qt-probe", url, linger]
    if case.startswith("proxy"):
        command.append(f"{FORWARDER[0]}:{FORWARDER[1]}")
    sys.exit(subprocess.call(command))


main()
