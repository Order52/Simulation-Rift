"""PoC Q1 (Phase 5): are Qt WebEngine's renderers confined? Seen from the host.

Run while qt-probe has a page open (run-ci.sh waits for its "ready" line).
Finds every process whose comm is the engine's (QtWebEngineProcess,
truncated by the kernel to 15 bytes), reads its type from its own command
line (Chromium's --type=...), its seccomp and NoNewPrivs state, and which
namespaces differ from the host's and from the app's main process.

A renderer counts as confined only with Seccomp=2, NoNewPrivs=1, and user,
mount and network namespaces different from the app's main process (a
sandbox of its own, not just the app's Flatpak sandbox).

Usage: python3 -I host-probe.py (the app's main process is found by its
comm, qt-probe; the pid it prints is in its own pid namespace)
Exit 0: every renderer confined; 1: a renderer not confined; 2: none found.
"""

import os
import pathlib
import sys

NAMESPACES = ("user", "mnt", "pid", "net", "ipc")
ENGINE = "QtWebEngineProc"


def read(path):
    try:
        return pathlib.Path(path).read_bytes()
    except OSError as error:
        return None if error.errno else b""


def status(pid):
    fields = {}
    raw = read(f"/proc/{pid}/status")
    for line in (raw or b"").decode(errors="replace").splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.strip()
    return fields


def namespace(pid, kind):
    try:
        return os.readlink(f"/proc/{pid}/ns/{kind}")
    except OSError as error:
        return f"unreadable({error.strerror})"


def differs(pid, other, kind):
    """True only when both links are readable and differ: an unreadable
    namespace is no evidence of a new one."""
    mine, theirs = namespace(pid, kind), namespace(other, kind)
    return not mine.startswith("unreadable") and not theirs.startswith("unreadable") and mine != theirs


def process_type(pid):
    raw = read(f"/proc/{pid}/cmdline")
    if raw is None:
        return "unreadable"
    for arg in raw.split(b"\0"):
        if arg.startswith(b"--type="):
            return arg[len(b"--type="):].decode(errors="replace")
    return "browser-or-launcher"


def find(comm):
    for entry in pathlib.Path("/proc").iterdir():
        if entry.name.isdigit() and (read(entry / "comm") or b"").decode(errors="replace").strip() == comm:
            return entry.name
    return None


def main():
    app = find("qt-probe")
    host = str(os.getpid())
    renderers = confined = 0
    for entry in sorted(pathlib.Path("/proc").iterdir(), key=lambda p: p.name):
        if not entry.name.isdigit():
            continue
        comm = (read(entry / "comm") or b"").decode(errors="replace").strip()
        if comm != ENGINE:
            continue
        pid = entry.name
        fields = status(pid)
        kind = process_type(pid)
        vs_host = [k for k in NAMESPACES if differs(pid, host, k)]
        vs_app = [k for k in NAMESPACES if app and differs(pid, app, k)]
        unread = [k for k in NAMESPACES if namespace(pid, k).startswith("unreadable")]
        print(
            f"host sees pid {pid} type={kind} Seccomp={fields.get('Seccomp')} "
            f"filters={fields.get('Seccomp_filters')} NoNewPrivs={fields.get('NoNewPrivs')} "
            f"new_vs_host={','.join(vs_host) or '-'} new_vs_app={','.join(vs_app) or '-'}"
            + (f" unreadable_ns={','.join(unread)}" if unread else "")
        )
        if kind == "renderer":
            renderers += 1
            ok = (
                fields.get("Seccomp") == "2"
                and fields.get("NoNewPrivs") == "1"
                and all(k in vs_app for k in ("user", "mnt", "net"))
            )
            confined += ok
    if app:
        print(f"app main pid {app}: Seccomp={status(app).get('Seccomp')} "
              f"new_vs_host={','.join(k for k in NAMESPACES if differs(app, host, k)) or '-'}")
    print(f"verdict: {confined} of {renderers} renderers confined")
    if renderers == 0:
        sys.exit(2)
    sys.exit(0 if confined == renderers else 1)


main()
