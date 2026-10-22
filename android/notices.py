"""Writes the third-party notices for the Rust code in the controller APK.

    python3 -I android/notices.py <out-dir>

<out-dir>/rust/notices/rust-crates.txt lists every crate linked into
librift_ffi.so and librift_worker_ffi.so (normal dependencies for both
Android targets, the same feature set build.sh builds), each with its
licence expression and the licence and notice files it publishes; identical
texts are printed once and referred to by number. <out-dir>/common/notices/
apache-2.0.txt is the Apache License 2.0, which both APKs need for their
AndroidX libraries. A crate that publishes no licence file must be listed,
with its exact version, in android/licence-texts/crates.txt, which points to
the licence files of its repository; otherwise this fails.
"""

import hashlib
import json
import os
import re
import subprocess
import sys

PACKAGES = ("rift-ffi", "rift-worker-ffi")
TARGETS = ("aarch64-linux-android", "x86_64-linux-android")
LICENCE_FILE = re.compile(r"^(licen[cs]e|copying|notice|copyright|unlicense)([-._].*)?$", re.IGNORECASE)
LICENCE_DIRS = ("license", "licenses", "LICENSES")
APACHE_START = re.compile(r"^\s*Apache License\s*\n\s*Version 2\.0, January 2004", re.MULTILINE)
APACHE_END = "END OF TERMS AND CONDITIONS"
SUPPLIED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licence-texts")


def cargo(*args):
    return subprocess.run(("cargo",) + args, check=True, capture_output=True, text=True).stdout


def shipped_crates():
    """(name, version) of every crate linked into the two libraries."""
    selection = [arg for name in PACKAGES for arg in ("-p", name)]
    crates = set()
    for target in TARGETS:
        listing = cargo("tree", "--locked", *selection, "--target", target, "-e", "normal,no-proc-macro",
                        "--prefix", "none", "--format", "{p}")
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1].startswith("v"):
                crates.add((fields[0], fields[1][1:]))
    return crates


def licence_files(directory):
    found = []
    for entry in sorted(os.listdir(directory)):
        path = os.path.join(directory, entry)
        if os.path.isfile(path) and LICENCE_FILE.match(entry):
            found.append(path)
        elif os.path.isdir(path) and entry in LICENCE_DIRS:
            found.extend(os.path.join(path, f) for f in sorted(os.listdir(path)) if os.path.isfile(os.path.join(path, f)))
    return found


def supplied_texts():
    """(crate, version) -> licence files kept here for crates that publish none."""
    supplied = {}
    with open(os.path.join(SUPPLIED, "crates.txt"), encoding="utf-8") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                name, version, directory = line.split()
                supplied[(name, version)] = (directory, licence_files(os.path.join(SUPPLIED, directory)))
    return supplied


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().replace("\r\n", "\n").strip("\n").rstrip() + "\n"


def apache_text(texts):
    """The Apache License 2.0 terms, from one of the crates' own copies."""
    for text in texts:
        start = APACHE_START.search(text)
        if start and APACHE_END in text:
            return text[start.start():text.index(APACHE_END) + len(APACHE_END)].strip("\n") + "\n"
    sys.exit("notices: no crate publishes the Apache License 2.0 text")


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    metadata = json.loads(cargo("metadata", "--locked", "--format-version", "1"))
    members = set(metadata["workspace_members"])
    by_id = {(p["name"], p["version"]): p for p in metadata["packages"]}

    supplied = supplied_texts()
    texts = {}  # digest -> (number, text)
    entries = []
    missing = []
    for name, version in sorted(shipped_crates()):
        package = by_id[(name, version)]
        if package["id"] in members:
            continue
        refs = []
        published = licence_files(os.path.dirname(package["manifest_path"]))
        directory, files = ("", published) if published else supplied.get((name, version), ("", []))
        if not files:
            missing.append(f"{name} {version}")
        for path in files:
            text = read_text(path)
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest not in texts:
                texts[digest] = (len(texts) + 1, text)
            refs.append((os.path.basename(path), texts[digest][0]))
        expression = package.get("license") or "see its licence file"
        notes = []
        if directory.startswith("generic-"):
            holders = ", ".join(package.get("authors") or []) or "none listed"
            notes.append(f"Copyright holders, as listed in the crate's authors: {holders}")
            notes.append("Neither the crate nor its repository publishes a licence file; the standard text applies.")
        elif directory:
            notes.append(f"The crate publishes no licence file; these are its repository's ({directory}).")
        entries.append((name, version, expression, package.get("repository") or "", refs, notes))
    if missing:
        sys.exit("notices: no licence file, and none in licence-texts/crates.txt, for: " + ", ".join(missing))

    apache = apache_text(text for _, text in texts.values())

    lines = [
        "Third-party Rust code in Rift's native libraries",
        "(librift_ffi.so, librift_worker_ffi.so).",
        "",
        "Each crate is listed with its licence expression and the licence and notice",
        "files it publishes. Where a crate is offered under a choice of licences,",
        "Rift uses it under a permissive one (MIT, Apache-2.0, BSD, ISC,",
        "Zlib, Unicode-3.0) where offered, or under MPL-2.0. Identical texts are",
        "printed once, under \"Texts\", and referred to by number.",
        "",
        "Crates",
        "======",
        "",
    ]
    for name, version, expression, repository, refs, notes in entries:
        lines.append(f"{name} {version}: {expression}")
        if repository:
            lines.append(f"  Source: {repository}")
        lines += [f"  {note}" for note in notes]
        lines.append("  " + ", ".join(f"{file} [text {number}]" for file, number in refs))
        lines.append("")
    lines += ["Texts", "=====", ""]
    for number, text in sorted(texts.values()):
        lines += [f"[text {number}]", "", text, "-" * 72, ""]

    write(os.path.join(out, "rust", "notices", "rust-crates.txt"), "\n".join(lines))
    write(os.path.join(out, "common", "notices", "apache-2.0.txt"), apache)
    print(f"notices: {len(entries)} crates, {len(texts)} distinct texts, "
          f"{sum(bool(e[5]) for e in entries)} with texts from licence-texts/")


if __name__ == "__main__":
    main()
