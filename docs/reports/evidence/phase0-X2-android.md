# Evidence: PoC X2 — offline TUF verification on Android (emulators, API 30 and 36)

Build: `cargo ndk -t arm64-v8a -P 30 build --release -p tuf-offline` (from `poc/`), NDK 29.0.14206865, tough 0.24.0 with aws-lc-rs 1.18.2 (aws-lc-sys 0.46.0). It compiled with no source or build-configuration changes.

Command: `RIFT_X2_BINARY=poc/target/aarch64-linux-android/release/tuf-offline poc/tuf-offline/run-scenarios.sh poc/tuf-offline/adb-client.sh`. Repositories are published on the host with tuftool; `adb-client.sh` pushes each repository, root and expected file to the device and runs the Android binary there, so every verification below happened on Android. Devices: API 30 emulator (`google_apis`, arm64-v8a, kernel 5.4.249), captured 2026-10-17T19:20Z and shown below; API 36 emulator with the same result (16 pass, 3 informational, 0 failures), raw output in [`phase0-android-api36/x2.md`](phase0-android-api36/x2.md).

| scenario | expected | client output | result |
|---|---|---|---|
| valid repository + target | OK | `OK timestamp=v1 snapshot=v1 targets=v1; target pack.bin verified (65536 bytes)` | pass |
| target bytes modified | REJECTED:Hash mismatch | `REJECTED target verification: Failed to fetch d5bcec81bd6ffba0dce4fd78419fa2480e4d210b79359a2230f086c0f28ba67c.pack.bin: Transport 'other' error fetching 'd5bcec81bd6ffba0dce4fd78419fa2480e4d210b79359a2230f086c0f28ba67c.` | pass |
| targets.json modified (unsigned) | REJECTED:Hash mismatch | `REJECTED load: Failed to fetch 1.targets.json: Transport 'other' error fetching '1.targets.json': Hash mismatch for 1.targets.json: calculated e48c244413d09bdce8e515d8c8aabf131c454590aa1b82e0e47c104ee8f7954b, expected 5d` | pass |
| rollback: load v1 into fresh store | OK | `OK timestamp=v1 snapshot=v1 targets=v1` | pass |
| rollback: update to v2 | OK | `OK timestamp=v2 snapshot=v2 targets=v2; target pack.bin verified (65536 bytes)` | pass |
| rollback: replay v1 after v2 was trusted | REJECTED:Found version 1 of timestamp | `REJECTED load: Found version 1 of timestamp metadata when we had previously fetched version 2` | pass |
| expired timestamp | REJECTED:expired | `REJECTED load: timestamp metadata is expired` | pass |
| repository signed by an untrusted root | REJECTED:Signature threshold | `REJECTED load: Failed to verify timestamp metadata: Signature threshold of 1 not met for role timestamp (0 valid signatures)` | pass |
| timestamp.json above 16 KiB limit | REJECTED:Maximum size 16384 | `REJECTED load: Failed to fetch timestamp.json: Transport 'other' error fetching 'timestamp.json': Maximum size 16384 (specified by max_timestamp_size argument) exceeded` | pass |
| target not listed in metadata | REJECTED:not listed | `REJECTED target TargetName { raw: "missing.bin", resolved: None } not listed` | pass |
| tough TargetName ../../etc/passwd (informational) | — | `OK accepted as "etc/passwd"` | info |
| tough TargetName a/../../escape (informational) | — | `OK accepted as "escape"` | info |
| tough TargetName /etc/passwd (informational) | — | `OK accepted as "/etc/passwd"` | info |
| Rift policy: ../../etc/passwd | REJECTED:not in normal form | `REJECTED target name "../../etc/passwd" is not in normal form` | pass |
| Rift policy: a/../../escape | REJECTED:not in normal form | `REJECTED target name "a/../../escape" is not in normal form` | pass |
| Rift policy: /etc/passwd | REJECTED:not a known pack file | `REJECTED target name "/etc/passwd" is not a known pack file` | pass |
| Rift policy: ./url-hashes.bin | REJECTED:not in normal form | `REJECTED target name "./url-hashes.bin" is not in normal form` | pass |
| Rift policy: unknown.bin | REJECTED:not a known pack file | `REJECTED target name "unknown.bin" is not a known pack file` | pass |
| Rift policy: url-hashes.bin | OK | `OK staged as "url-hashes.bin"` | pass |

failures: 0

Each rejection is checked for its reason, not only for `REJECTED`. The first device run showed why that matters: tuftool writes targets as links to host paths, the links dangled on the device, and the two tamper scenarios were rejected only because the files were missing. Both the script and the reason checks were fixed before this run.

## Size

The stripped Android binary is 4,771,032 bytes (2,242,299 gzip-compressed). It contains tough, aws-lc (the static crypto archive alone is 6.2 MB before linking), rustls (a non-optional tough dependency), tokio's current-thread runtime and the Rust standard library. Linked into Rift's native library, the added size will be lower, because the standard library is already there. So 4.8 MB is an upper bound against the ~11 MB left in the arm64 budget (§18). It has not been measured inside the shared library.

## Not shown by this evidence

- x86_64 Android and a physical phone.
- Fetching over HTTPS (Rift V1 imports and verifies offline; online fetch goes through the core's transfer policy and is a separate test).
