"""Adds new Chromium bugs from CISA's Known Exploited Vulnerabilities
catalogue to KnownExploited.kt (architecture §8.4, INV-7).

Run weekly by .github/workflows/kev.yml:

    python3 -I .github/scripts/kev_update.py <KnownExploited.kt> <kev.json> [nvd.json]

A bug is new if the catalogue added it on or after the date in CHECKED and
the list does not have it. Its fixed version is the one NVD's description
gives ("Google Chrome [on Android] prior to X"); the Android one is preferred
when both are given. A new bug with no fixed version fails the run, so a gap
is never shipped silently. nvd.json (a map of CVE to description) replaces
the NVD lookups, for testing.

Prints the bugs added, one per line; prints nothing and leaves the file
alone if there are none.
"""

import json
import re
import sys
import time
import urllib.request

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
VERSION = r"(\d+\.\d+\.\d+\.\d+)"


def nvd_description(cve):
    # NVD allows 5 requests in 30 s without a key.
    time.sleep(6.5)
    with urllib.request.urlopen(NVD + cve, timeout=60) as reply:
        found = json.load(reply)["vulnerabilities"]
    if not found:
        return ""
    return next((d["value"] for d in found[0]["cve"]["descriptions"] if d["lang"] == "en"), "")


def fixed_in(description):
    android = re.search(r"Google Chrome on Android prior to " + VERSION, description)
    any_platform = re.search(r"Google Chrome prior to " + VERSION, description)
    match = android or any_platform
    return match.group(1) if match else None


def version_key(version):
    return tuple(int(part) for part in version.split("."))


def main(kotlin_path, kev_path, nvd_path=None):
    with open(kotlin_path, encoding="utf-8") as f:
        source = f.read()
    with open(kev_path, encoding="utf-8") as f:
        catalogue = json.load(f)
    descriptions = None
    if nvd_path:
        with open(nvd_path, encoding="utf-8") as f:
            descriptions = json.load(f)

    checked = re.search(r'const val CHECKED = "KEV (\d{4})\.(\d{2})\.(\d{2})"', source)
    block = re.search(r"(    val bugs = listOf\(\n)(.*?)(\n    \))", source, re.S)
    if not checked or not block:
        sys.exit("kev: KnownExploited.kt is not in the expected form")
    since = "-".join(checked.groups())
    bugs = dict(re.findall(r'Bug\("(CVE-[\d-]+)", "([\d.]+)"\)', block.group(2)))

    added = []
    for entry in catalogue["vulnerabilities"]:
        cve = entry["cveID"]
        if entry["vendorProject"] != "Google" or "Chromium" not in entry["product"]:
            continue
        if cve in bugs or entry["dateAdded"] < since:
            continue
        description = descriptions.get(cve, "") if descriptions is not None else nvd_description(cve)
        version = fixed_in(description)
        if version is None:
            sys.exit(f"kev: no fixed Chrome version for {cve} in NVD's description: {description!r}")
        bugs[cve] = version
        added.append(f"{cve} fixed in {version} ({entry['product']}, added {entry['dateAdded']})")

    if not added:
        return
    lines = ",\n".join(f'        Bug("{cve}", "{version}")'
                       for cve, version in sorted(bugs.items(), key=lambda b: (version_key(b[1]), b[0])))
    source = source[:block.start(2)] + lines + "," + source[block.end(2):]
    source = source.replace(checked.group(0), f'const val CHECKED = "KEV {catalogue["catalogVersion"]}"')
    with open(kotlin_path, "w", encoding="utf-8") as f:
        f.write(source)
    print("\n".join(added))


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    main(*sys.argv[1:])
