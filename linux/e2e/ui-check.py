"""Drives the controller's window through accessibility (AT-SPI), as a user
would, and checks what it shows. Run while a session is open whose
quarantine holds the download case's file (with the demo database's
marker in it); with --no-download, only the vault's create,
lock and unlock are checked.

Steps: create a vault; preview the quarantined file (its text, escaped by
rift-core, holds the marker); keep it in the vault; open and cancel the
export warning; with --export, export it to that path through the file
chooser portal (its dialog is answered with XTest: it belongs to the
portal's backend, outside the app); allow a local host name; lock; refuse a
wrong passphrase; unlock; delete the kept file.

Text goes in through the accessible EditableText interface where Qt offers
it (6.11), or else (6.10) by focusing the field through accessibility,
giving the window X input focus and typing with XTest (xdotool), which
--keyboard forces.

Usage: python3 -I ui-check.py [--no-download] [--keyboard] [--export <path>]
Exit 0: every step as expected; 1: a step failed (it says which).
"""

import subprocess
import sys
import time

import pyatspi

PASSPHRASE = "rift end-to-end passphrase"
TIMEOUT = 60
WINDOW_TITLE = "Simulation-Rift"
CHOOSER_TITLE = "Export to"
KEYBOARD = "--keyboard" in sys.argv[1:]
EXPORT = sys.argv[sys.argv.index("--export") + 1] if "--export" in sys.argv[1:] else None


class Failed(Exception):
    pass


def application():
    desktop = pyatspi.Registry.getDesktop(0)
    for _ in range(TIMEOUT):
        for i in range(desktop.childCount):
            app = desktop.getChildAtIndex(i)
            if app is not None and app.name == "rift":
                return app
        time.sleep(1)
    raise Failed("the controller's window is not on the accessibility bus")


def showing(acc):
    return pyatspi.STATE_SHOWING in acc.getState().getStates()


def text_of(acc):
    try:
        return acc.queryText().getText(0, -1)
    except NotImplementedError:
        return ""


# Roles by their AT-SPI number: their names differ between Qt and at-spi2
# versions ("button" or "push button").
ROLES = {
    "button": {pyatspi.ROLE_PUSH_BUTTON},
    "label": {pyatspi.ROLE_LABEL},
    "text": {pyatspi.ROLE_TEXT, pyatspi.ROLE_ENTRY},
    "password text": {pyatspi.ROLE_PASSWORD_TEXT},
}


def find_all(app, role, predicate):
    roles = ROLES[role]
    return pyatspi.findAllDescendants(
        app, lambda a: a.getRole() in roles and showing(a) and predicate(a)
    )


def dump(app):
    """What the window shows, for a failed step."""
    for acc in pyatspi.findAllDescendants(app, showing):
        print(f"  {acc.getRoleName()} {acc.name!r} {text_of(acc)[:80]!r}")


def wait(what, probe):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        found = probe()
        if found:
            return found
        time.sleep(0.5)
    raise Failed(f"timed out waiting for {what}")


def button(app, name, index=0):
    found = wait(f"the button {name!r}", lambda: find_all(app, "button", lambda a: a.name == name))
    return found[index] if index < len(found) else found[0]


def press(app, name, index=0):
    acc = button(app, name, index)
    acc.queryAction().doAction(0)
    print(f"pressed {name!r}")


def label(app, part):
    """A visible label (or text) containing `part`."""
    return wait(
        f"a label containing {part!r}",
        lambda: find_all(app, "label", lambda a: part in a.name) or find_all(app, "text", lambda a: part in text_of(a)),
    )


def no_label(app, part):
    wait(f"no label containing {part!r}", lambda: not find_all(app, "label", lambda a: part in a.name) or None)


def type_into(app, role, name, value):
    # Qt gives a password field no accessible name; the window has one.
    wanted = (lambda a: True) if role == "password text" else (lambda a: a.name == name)
    field = wait(f"the field {name!r}", lambda: find_all(app, role, wanted))[0]
    if not KEYBOARD:
        try:
            field.queryEditableText().setTextContents(value)
            print(f"set the text of {name!r}")
            return
        except NotImplementedError:
            pass
    field.queryComponent().grabFocus()
    subprocess.run(["xdotool", "search", "--name", f"^{WINDOW_TITLE}$", "windowfocus", "--sync"], check=True)
    time.sleep(0.3)
    subprocess.run(["xdotool", "type", "--delay", "20", value], check=True)
    wait(f"{name!r} to hold what was typed", lambda: len(text_of(field)) == len(value) or None)
    print(f"typed into {name!r}")


def x_windows(title):
    found = subprocess.run(["xdotool", "search", "--name", f"^{title}$"], capture_output=True, text=True)
    return found.stdout.split()


def export_through_portal(app, path):
    press(app, "Export…")
    label(app, "leaves Rift's protection")
    press(app, "Export anyway")
    wait(f"the file chooser {CHOOSER_TITLE!r}", lambda: x_windows(CHOOSER_TITLE))
    subprocess.run(["xdotool", "search", "--name", f"^{CHOOSER_TITLE}$", "windowfocus", "--sync"], check=True)
    time.sleep(1)
    # The name field has the focus; a path in it also picks the folder.
    subprocess.run(["xdotool", "key", "ctrl+a"], check=True)
    subprocess.run(["xdotool", "type", "--delay", "20", path], check=True)
    time.sleep(0.5)
    subprocess.run(["xdotool", "key", "Return"], check=True)
    label(app, "Exported. The copy is outside Rift's protection")
    print(f"exported through the portal to {path}")


def main():
    no_download = "--no-download" in sys.argv[1:]
    app = application()

    label(app, "No vault yet")
    type_into(app, "password text", "Passphrase", PASSPHRASE)
    press(app, "Create")
    label(app, "The vault is unlocked")
    print("vault created and unlocked")

    if not no_download:
        press(app, "Preview")
        label(app, "RIFT-DEMO-MARKER")
        print("preview shows the file's text")
        press(app, "Close")

        press(app, "Keep in vault")
        label(app, "in the vault. It is the original file and is still untrusted.")
        kept = label(app, "last scan:")
        print(f"kept: {kept[0].name}")

        press(app, "Export…")
        label(app, "leaves Rift's protection")
        press(app, "Cancel")
        no_label(app, "leaves Rift's protection")
        print("export warning shown and cancelled")
        if EXPORT is not None:
            export_through_portal(app, EXPORT)

        type_into(app, "text", "Host name", "printer.local")
        press(app, "Allow")
        label(app, "allowed this session: printer.local")
        print("local host allowed")

    press(app, "Lock")
    label(app, "The vault is locked.")
    no_label(app, "last scan:")
    type_into(app, "password text", "Passphrase", "not the passphrase at all")
    press(app, "Unlock")
    label(app, "was not unlocked")
    print("a wrong passphrase is refused")
    type_into(app, "password text", "Passphrase", PASSPHRASE)
    press(app, "Unlock")
    label(app, "The vault is unlocked")
    print("unlocked again")

    if not no_download:
        label(app, "last scan:")
        press(app, "Delete")
        label(app, "deleted from the vault")
        no_label(app, "last scan:")
        print("the kept file was deleted")
    print("ui: all steps as expected")


try:
    main()
except Failed as failure:
    print("showing:")
    dump(application())
    windows = subprocess.run(["xdotool", "search", "--name", "."], capture_output=True, text=True)
    for window in windows.stdout.split():
        name = subprocess.run(["xdotool", "getwindowname", window], capture_output=True, text=True)
        print(f"  X window {window}: {name.stdout.strip()!r}")
    print(f"ui: FAILED: {failure}")
    sys.exit(1)
