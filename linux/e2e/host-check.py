"""End-to-end check of the Linux app's confinement, seen from the host.

Run while a session's page is open. Finds the controller (comm "rift"), the
browser host ("rift-browser") and the engine's processes
("QtWebEngineProc", the kernel's 15-byte truncation), and checks:

- the browser host is in a network namespace other than the controller's,
  with no interface but loopback (the no-network sub-sandbox);
- no engine process shares the controller's network namespace;
- every renderer is sandboxed by the engine: more seccomp filters than the
  browser host (Chromium stacks its own on bubblewrap's), NoNewPrivs=1, and
  mount and pid namespaces of its own.

A namespace that cannot be read is a problem, not evidence either way:
Chromium makes its zygotes non-dumpable, so the check runs as root.

Usage: sudo python3 -I host-check.py
Exit 0: all hold; 1: one does not; 2: a process was not found.
"""

import os
import pathlib
import sys

NAMESPACES = ("user", "mnt", "pid", "net", "ipc")


def read(path):
    try:
        return pathlib.Path(path).read_bytes()
    except OSError:
        return None


def comm(pid):
    return (read(f"/proc/{pid}/comm") or b"").decode(errors="replace").strip()


def status(pid):
    fields = {}
    for line in (read(f"/proc/{pid}/status") or b"").decode(errors="replace").splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.strip()
    return fields


def namespace(pid, kind):
    try:
        return os.readlink(f"/proc/{pid}/ns/{kind}")
    except OSError:
        return None


def differs(pid, other, kind):
    """True only when both are readable and differ: an unreadable
    namespace is no evidence of a new one."""
    mine, theirs = namespace(pid, kind), namespace(other, kind)
    return mine is not None and theirs is not None and mine != theirs


def filters(pid):
    try:
        return int(status(pid).get("Seccomp_filters", ""))
    except ValueError:
        return -1


def process_type(pid):
    raw = read(f"/proc/{pid}/cmdline") or b""
    # Chromium rewrites its title over argv, joined by spaces, not NULs.
    for arg in raw.replace(b"\0", b" ").split(b" "):
        if arg.startswith(b"--type="):
            return arg[len(b"--type="):].decode(errors="replace")
    return "browser"


def interfaces(pid):
    lines = (read(f"/proc/{pid}/net/dev") or b"").decode(errors="replace").splitlines()[2:]
    return sorted(line.split(":")[0].strip() for line in lines if ":" in line)


def main():
    pids = [p.name for p in pathlib.Path("/proc").iterdir() if p.name.isdigit()]
    controller = [p for p in pids if comm(p) == "rift"]
    browser = [p for p in pids if comm(p) == "rift-browser"]
    engine = sorted((p for p in pids if comm(p) == "QtWebEngineProc"), key=int)
    if len(controller) != 1 or len(browser) != 1:
        print(f"expected one controller and one browser host, found {controller} and {browser}")
        sys.exit(2)
    controller, browser = controller[0], browser[0]
    problems = []

    seen = interfaces(browser)
    print(f"browser host {browser}: net namespace own={differs(browser, controller, 'net')}, "
          f"interfaces={','.join(seen) or '-'}, filters={filters(browser)}")
    if not differs(browser, controller, "net"):
        problems.append("the browser host shares the controller's network namespace")
    if seen != ["lo"]:
        problems.append(f"the browser host sees interfaces {seen}")

    renderers = 0
    for pid in engine:
        unreadable = [k for k in NAMESPACES if namespace(pid, k) is None]
        if unreadable:
            problems.append(f"engine process {pid}: namespaces {unreadable} could not be read")
        kind = process_type(pid)
        fields = status(pid)
        own = [k for k in NAMESPACES if differs(pid, browser, k)]
        print(f"engine {pid} type={kind} Seccomp={fields.get('Seccomp')} filters={filters(pid)} "
              f"NoNewPrivs={fields.get('NoNewPrivs')} own_vs_browser_host={','.join(own) or '-'} "
              f"shares_controller_net={not differs(pid, controller, 'net')}")
        if not differs(pid, controller, "net"):
            problems.append(f"engine process {pid} ({kind}) shares the controller's network")
        if kind == "renderer":
            renderers += 1
            if not (fields.get("Seccomp") == "2" and fields.get("NoNewPrivs") == "1"
                    and filters(pid) > filters(browser) >= 1
                    and "mnt" in own and "pid" in own):
                problems.append(f"renderer {pid} is not sandboxed by the engine")
    if renderers == 0:
        print("no renderer found")
        sys.exit(2)
    for problem in problems:
        print(f"problem: {problem}")
    print(f"verdict: {renderers} renderers, {len(problems)} problems")
    sys.exit(1 if problems else 0)


main()
