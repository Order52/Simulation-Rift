# Architecture 3.2: a relay for the user's address, fingerprinting named, fixed page rules, held list updates

**Date:** 27 October 2026. **Architecture:** 3.2 (§8.11, §8.12, §10.5, §10.12, §10.14). **Android:** 0.11.5 (the next weekly release). **Linux:** on hold ([TODO.md](../../TODO.md)).

## What changed

1. **Hide your IP address** (§8.12, Security tab). Pages' connections, downloads and Where it goes can go through Tor (Orbot) or a public SOCKS5 relay.
   - Names go to the relay unresolved (SOCKS5 domain type), so the phone's resolver sees nothing. Literal addresses are still checked, and private ones refused. Local names (`localhost`, `.local`, `.internal`, `home.arpa`, `.lan`, single labels) are refused rather than sent to the relay. Only the session's own local hosts (in tests, the fixture server) go direct.
   - **Nothing falls back to direct.** A relay that is down, refuses, or is not the pinned Orbot fails the connection with a "relay" refusal.
   - **Orbot is pinned.** Choosing it records the SHA-256 of the installed Orbot's signing certificate. Every connection checks that the package still has that certificate and that Orbot last said it is running on that port. Android cannot say who owns a loopback port, and Orbot's status comes by a broadcast any app could send: that gap is in §24.
   - A SOCKS5 relay must be a public `ip:port` (no name, which the phone would have to look up). A setting that cannot be read is a relay that cannot be used, so sessions fail closed.
   - Rift's own fetches (updates, lists, filter lists) go direct. A change starts a new session.
2. **Fingerprinting is named** (§10.14). The decoy script notices canvas read-back, WebGL renderer queries and read-back, off-screen audio rendering, and text measured in more than 20 fonts. It changes canvas, WebGL and audio readings faintly with a per-session seed and names the chip as a common one. The watch notes each technique and "is fingerprinting" for the host.
3. **Three fixed page rules** (§10.5) beside Rift AI's page score, only on a page with a password field, each a Warning that says what was seen: links that go nowhere (four in five of five or more, or none), a form to another site's `.php` script, the right-click menu blocked. They do not change when the model is retrained. Rules with too many false alarms were measured and left out ([page-model.md](page-model.md#fixed-rules-beside-the-model-32)).
4. **A list cannot be swapped at once** (§10.12). A threat list's new copy that keeps under 40% of the hosts in use, or has more than four times as many, is held: Check keeps the copy in use, and the card says how much changed, with **Use the new one** and **Keep the copy in use**. Lists of under 500 hosts are too small to judge.
5. **A store build** (§8.11, [distribution.md](../distribution.md)). Each release also has `rift-store-<version>.apk`, the same commit and key with `-Prift.store=true`, in which Rift's own update checks start off (IzzyOnDroid requires a self-updater to be opt-in). The guide lists what is ready for IzzyOnDroid and what F-Droid still needs (reproducible builds, because of the embedded browser's signature).
6. **Against Safe Browsing** ([check-accuracy.md](check-accuracy.md#against-safe-browsing)). `compare --safebrowsing`, `safebrowsing.py`, `compare.sh` and a weekly `compare.yml` measure Check against Google Safe Browsing and URLCheck's hosts check on OpenPhish links that appeared three hours after Check's lists were taken. The app still asks Google nothing.
7. **GitHub Pages as the update host** ([key-ceremony.md](key-ceremony.md#github-pages-as-the-update-host)). After the key ceremony, each offline-signed release is a bundle in an `intel-<version>` pre-release (`pages.sh bundle`); `intel-pages.yml` signs a new snapshot and timestamp with the online keys every 5 days, checks the repository from root v1 as the app does, and deploys it. Weekly app releases embed the production root once `intel/root-1.json` and the `RIFT_INTEL_URL` variable exist.

## Verified

- **On the API 34 arm64 emulator:**
  - R1: the in-test SOCKS5 relay receives `relay-test.example` and `relay-trace.example` by name and the fixture page loads through it; with Orbot's status off, and with a certificate that is not the app's, every connection is refused as "relay" and nothing reaches the fixture or the relay.
  - D2: each fingerprinting technique noted and "is fingerprinting" for the host; the canvas reads the same twice in a session and differently in the next.
  - N10: the kit page gets `page-form-elsewhere` and `page-no-right-click` beside Rift AI's warning. (Its four links are too few for the dead-links rule.)
  - V7: 1,000 hosts in use; a copy keeping 90% is used; a copy keeping 200 of 1,000 is held (Check still finds a host only the old copy has, not one only the new copy has) until `decideHeld`, then the new copy alone is used. V5 still passes.
  - The store build: after a clear, its first start leaves both update switches off (`self-update-off`, `self-update-launch-off`); the normal build's start leaves them on.
- **Rust:** 288 tests in the product workspace pass (the new ones in `relay`, `egress`, `download`, `hostlists`, `page` and `rift-ffi`), with `clippy -D warnings` and `fmt`.
- **`release.sh`** builds `rift-<version>.apk` and `rift-store-<version>.apk` (24.5 MB each, arm64), both signed with the release certificate `8b595271…ee8b` and verified by `apksigner`.
- **The page rules' rates** on the 80,000 pages of the 2021 dataset, from the counts the trainer made (table in page-model.md).
- **The comparison tool** on hand-made inputs gives the expected counts in its three new columns; `safebrowsing.py` refuses to run without a key.
- **The Pages path,** rehearsed with throwaway 1-of-1 keys and the demo pack: draft and sign a root, draft and sign targets, `pages.sh bundle`, `pages.sh publish`, and `verify` from root v1 ("OK … targets v1, timestamp v29885496"). The site has `rift/metadata/` and `rift/targets/` as the app expects.

## Unverified

- **No Safe Browsing figures yet:** `compare.yml` needs a `SAFE_BROWSING_KEY` secret.
- **The relay with a real Orbot or relay**, and on a phone: R1 uses an in-process SOCKS5 server and a pinned outsider app standing in for Orbot. Tor's own behaviour (circuits, exit refusals, speed) was not measured.
- **The page rules on today's pages:** the dataset is from 2020 to 2021, like the page model's.
- **The release workflow's store APK** has not run on GitHub; `release.sh` built it locally (above).
- **`intel-pages.yml`** has not run: there are no production keys. Its Pages deployment, and the app fetching from `github.io`, are untested.
- **No store submission** has been made.

## Could be improved

- Find who owns a loopback port on Android without the VPN API, to close the Orbot broadcast gap; or use Orbot's VPN mode for the browser's UID only.
- Route Rift's own fetches through the relay as a choice.
- Rerun the page rules' rates on the page memory of current pages once it is large enough.
- Reproducible release builds, for F-Droid.
