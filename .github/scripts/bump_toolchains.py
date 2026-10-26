"""Moves the pinned toolchains Dependabot does not see to their latest
releases (toolchains.yml): stable Rust (rust-toolchain.toml), the fuzzing
nightly, cargo-ndk, OSV-Scanner (with the SHA-256 of the binary GitHub
serves) and the NDK (from sdkmanager, passed in). Prints what changed.

The MSRV (rust-version, ci.yml's MSRV) is not moved: it is the compiler the
Linux Flatpak builds with.

usage: python3 -I bump_toolchains.py <ndk version>
"""
import datetime
import hashlib
import json
import re
import sys
import urllib.request

UA = {"User-Agent": "simulation-rift toolchain bump (github actions)"}


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
        return r.read()


def edit(path, pattern, value, what):
    text = open(path).read()
    new, n = re.subn(pattern, lambda m: m.group(1) + value + m.group(3), text)
    if n == 0:
        sys.exit(f"{path}: no {what} found")
    if new != text:
        open(path, "w").write(new)
        print(f"{what} -> {value} ({path})")


ndk = sys.argv[1] if len(sys.argv) == 2 else ""
if not re.fullmatch(r"\d+\.\d+\.\d+", ndk):
    sys.exit(__doc__)

channel = get("https://static.rust-lang.org/dist/channel-rust-stable.toml").decode()
rust = re.search(r'\[pkg\.rust\]\nversion = "(\d+\.\d+\.\d+) ', channel).group(1)
nightly = "nightly-" + (datetime.date.today() - datetime.timedelta(days=3)).isoformat()
cargo_ndk = json.loads(get("https://crates.io/api/v1/crates/cargo-ndk"))["crate"]["max_stable_version"]
osv = json.loads(get("https://api.github.com/repos/google/osv-scanner/releases/latest"))["tag_name"]
for value, shape in ((cargo_ndk, r"\d+\.\d+\.\d+"), (osv, r"v\d+\.\d+\.\d+")):
    if not re.fullmatch(shape, value):
        sys.exit(f"unexpected version {value!r}")

edit("rust-toolchain.toml", r'(channel = ")([^"]+)(")', rust, "stable Rust")
# The workflows read the rest from this file: a workflow's token may not edit workflows.
PINS = ".github/toolchains.env"
edit(PINS, r"(?m)(^NIGHTLY=)(nightly-\d{4}-\d{2}-\d{2})($)", nightly, "fuzzing nightly")
edit(PINS, r"(?m)(^NDK_VERSION=)([\d.]+)($)", ndk, "NDK")
edit(PINS, r"(?m)(^CARGO_NDK_VERSION=)([\d.]+)($)", cargo_ndk, "cargo-ndk")
old_osv = re.search(r"(?m)^OSV_SCANNER_VERSION=(\S+)", open(PINS).read()).group(1)
if old_osv != osv:
    binary = get(f"https://github.com/google/osv-scanner/releases/download/{osv}/osv-scanner_linux_amd64")
    edit(PINS, r"(?m)(^OSV_SCANNER_VERSION=)(\S+)($)", osv, "OSV-Scanner")
    edit(PINS, r"(?m)(^OSV_SCANNER_SHA256=)([0-9a-f]{64})($)", hashlib.sha256(binary).hexdigest(), "OSV-Scanner SHA-256")
