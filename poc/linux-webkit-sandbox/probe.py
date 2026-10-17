"""PoC L1: is the WebKitGTK 6.0 web-content sandbox actually active?

Starts a WebKitGTK 6.0 WebView, loads a page, then inspects every
WebKitWebProcess the way Rift's fail-closed check would (§9.2): from
outside, via /proc, without trusting the engine's own configuration.

A web process counts as confined only if it has NoNewPrivs=1, an active
seccomp filter (Seccomp=2), and user + mount namespaces different from
ours. Usage (under a display, e.g. xvfb-run): python3 -I probe.py
"""

import os
import pathlib
import sys

try:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("WebKit", "6.0")
    from gi.repository import GLib, Gtk, WebKit
except (ImportError, ValueError) as error:  # environment problem, not a verdict
    print(f"probe could not start: {error}")
    sys.exit(2)

NAMESPACES = ("user", "mnt", "pid", "net", "ipc")


def status_fields(pid):
    fields = {}
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.strip()
    return fields


def namespace(pid, kind):
    try:
        return os.readlink(f"/proc/{pid}/ns/{kind}")
    except OSError as error:
        return f"unreadable ({error.strerror})"


def processes():
    """Maps pid -> comm. comm is set by the executed binary (truncated to 15
    bytes); a command line is not evidence, since a launcher such as bwrap
    carries the web process path among its arguments."""
    found = {}
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            found[int(entry.name)] = (entry / "comm").read_text().strip()
        except OSError:
            continue
    return found


WEB_PROCESS = "WebKitWebProces"
INFORMATIONAL = ("WebKitNetworkPr", "WebKitGPUProces", "bwrap", "xdg-dbus-proxy")


def assess(pid):
    fields = status_fields(pid)
    differs = {kind: namespace(pid, kind) != namespace(os.getpid(), kind) for kind in NAMESPACES}
    confined = (
        fields.get("NoNewPrivs") == "1"
        and fields.get("Seccomp") == "2"
        and differs["user"]
        and differs["mnt"]
    )
    return confined, fields, differs


def describe(pid, comm):
    confined, fields, differs = assess(pid)
    print(
        f"pid {pid} ({comm}): NoNewPrivs={fields.get('NoNewPrivs')} Seccomp={fields.get('Seccomp')} "
        f"filters={fields.get('Seccomp_filters')} new_namespaces="
        + ",".join(kind for kind, d in differs.items() if d)
        + f" -> {'CONFINED' if confined else 'NOT CONFINED'}"
    )
    return confined


def report_and_quit(app):
    procs = processes()
    web = sorted(pid for pid, comm in procs.items() if comm == WEB_PROCESS)
    print(f"webkit version: {WebKit.get_major_version()}.{WebKit.get_minor_version()}.{WebKit.get_micro_version()}")
    print(f"web processes: {web}")
    all_confined = bool(web)
    for pid in web:
        all_confined &= describe(pid, WEB_PROCESS)
    for pid, comm in sorted(procs.items()):
        if comm in INFORMATIONAL:
            print("(not part of the verdict) ", end="")
            describe(pid, comm)
    print("verdict:", "browsing allowed (sandbox verified)" if all_confined else "BROWSING REFUSED (sandbox not verified)")
    app.exit_code = 0 if all_confined else 1
    app.quit()
    return False


def main():
    app = Gtk.Application(application_id="org.simulationrift.L1Probe")
    app.exit_code = 2

    def on_activate(application):
        window = Gtk.ApplicationWindow(application=application)
        view = WebKit.WebView()
        window.set_child(view)
        view.load_html("<html><body><h1>Rift L1 probe</h1><script>1+1</script></body></html>", "about:blank")
        window.present()
        GLib.timeout_add_seconds(5, report_and_quit, application)

    app.connect("activate", on_activate)
    app.run([])
    sys.exit(app.exit_code)


if __name__ == "__main__":
    main()
