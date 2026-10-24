# To do

What is left, roughly in order. [STATUS.md](STATUS.md) says what works now and how it was tested.

## Needs a person

- **Hold the signing-key ceremony.** Generate the production root, targets and timestamp keys on offline drives with `tools/rift-pack/ceremony.sh`, following [key-ceremony.md](docs/reports/key-ceremony.md), and put the resulting root in the release build. Until then, packs are signed with demo keys that only debug builds trust.
- **Set up an update host** for signed threat-database packs (any static HTTPS host).
- **An external security review** before any release claim. The brief for the reviewer is [review-brief.md](docs/reports/review-brief.md).
- **Phones:** rerun the suite on the Huawei phone with Rift Browser allowed under Settings, Battery, App launch, and run it on phones from other makers. Fault rounds need `adb root`, which retail phones do not give.

## Android

- Rift's own fixed scriptlets for sign-in walls built only with scripts (LinkedIn, some of Quora), fed checked arguments, so list scripts still never run.
- A relay (Tor, or a VPN chained behind the proxy) so pages do not see the phone's IP address.
- Rift AI: compare it with Safe Browsing, and teach it to recognise tracking.
- Sign the threat lists' snapshots, or check them against a second source, so a list's server alone cannot decide what Check warns about (§10.12, §24).

## Linux, for later

The Linux app (Qt and Qt WebEngine in Flatpak, `linux/`) is kept but not supported now: it is not built on each push, so it may not build against the current core. It was last built and tested end to end in CI on 21 Oct 2026 ([report](docs/reports/phase-5-qt-design.md#the-app-built-21-oct-2026)). To bring it back:

1. Build it against the current core and run the `linux-app` workflow; fix what has drifted.
2. Bring over what Android gained since 2.3: Check and Rift AI, link tools, content filters and sign-in walls, decoys, the threat lists, Test-open, the weekly summary, and the history.
3. Test it on a desktop distribution with Wayland and a GPU, not only under Xvfb in CI.
4. An online update from a real server, and PDF previews.
5. L4, the Linux network lock, as a Phase 0 proof on a desktop.
