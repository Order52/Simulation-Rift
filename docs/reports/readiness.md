# Readiness: what "ready to present" means, and how far Rift is

Rift is a security product in development and is not audited. "Ready to present" here means a person can install it, see it work, and be told truthfully what it does and does not do. It does not mean "safe" or "audited".

## The threshold

A fixed list, so the work has an end. Every gate is a command or a file a reader can check. Work stops when all gates in the first table pass, or after three rounds in a row that change no gate; whatever is then left goes in the second table.

| # | Gate | How it is checked | State (17 Nov 2026) |
|---|---|---|---|
| G1 | CI is green on `main` (rust on two systems, MSRV, dependencies, fuzz, Android API 33 and 34) | `gh run list --branch main` | Passing at each merge |
| G2 | No open critical or high dependency alert | `gh api repos/Order52/Simulation-Rift/dependabot/alerts` | None open on 17 Nov 2026 (the last, a critical wasmtime alert on `poc/Cargo.lock`, was closed by PR #23) |
| G3 | `cargo fmt`, `clippy -D warnings`, `cargo test --workspace`, `cargo deny check` pass | CONTRIBUTING commands in CLAUDE.md | Pass on 17 Nov 2026: fmt and clippy clean, 297 tests passed, 0 failed, `cargo deny` ok |
| G4 | The device suite passes in full on the API 34 emulator, from a clean install | `sh android/run-tests.sh` | 69 of 69 |
| G5 | An upgrade over an older release starts a session and opens a page | `docs/demo.md`, step 0 | Pass on 17 Nov 2026 (API 34 arm64 emulator, release builds): 0.11.7 installed with its browser and started Session 1; updating in place to 0.11.9 (and its browser) started Session 2, and **New session** gave Session 3, with no cleanup failure. Done by hand with `adb`; not yet automated |
| G6 | Rift AI's gate passes for the bundled model, and fixed regression links stay caught | `tools/rift-train/gate.py`, `cargo test -p rift-ffi ai::` | Passing in CI |
| G7 | The README, STATUS, user guide and demo script say the same thing, and each limit is stated | read-through | Done once on 17 Nov 2026; recheck after any change to the files in `files/` |
| G8 | A written demo script exists that a person can follow in ten minutes | `docs/demo.md` | Written |

## Not reachable without a person (stated, not hidden)

| Item | Why it waits |
|---|---|
| The signing-key ceremony and the live signed model | It needs offline drives and several key holders ([key-ceremony.md](key-ceremony.md)). Until then, Rift AI updates only with each app release. |
| An external security review | Required before any security claim. [Brief](review-brief.md). |
| A run on more physical phones | One Android 12 phone and emulators so far. Phones from other makers can block the browser app from starting. |
| Fresh phishing data | Rift AI's main feed stopped updating on 2 Oct 2026; no licence-safe replacement was found ([report](rift-ai.md)). |

## Rules for what is claimed

- A check that cannot finish says "Not fully scanned", never "clean". Nothing is called "safe".
- Each claim names its boundary and a test. A claim without one is not made.
