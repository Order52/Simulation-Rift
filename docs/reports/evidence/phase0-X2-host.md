# Evidence: PoC X2 — offline TUF verification (host)

Command: `poc/tuf-offline/run-scenarios.sh poc/target/release/tuf-offline` with tuftool 0.17.0 and tough 0.24.0 on macOS 26.6.2 (arm64). Re-captured 2026-10-17T19:20Z with the stricter script: each rejection must now carry its expected reason (after `REJECTED:`), and target links written by tuftool are replaced by copies so tampering one repository copy cannot change another. Repositories are generated fresh on each run (RSA keys, 1-of-1 thresholds — production key policy is separate). Paths in the output are shortened to file names.

| scenario | expected | client output | result |
|---|---|---|---|
| valid repository + target | OK | `OK timestamp=v1 snapshot=v1 targets=v1; target pack.bin verified (65536 bytes)` | pass |
| target bytes modified | REJECTED:Hash mismatch | `REJECTED target verification: Failed to fetch 0c794e69e120d17872afc7f6174a342d88785eda00cb955afdbb80b225e6a7ce.pack.bin: Transport 'other' error fetching '0c794e69e120d17872afc7f6174a342d88785eda00cb955afdbb80b225e6a7ce.` | pass |
| targets.json modified (unsigned) | REJECTED:Hash mismatch | `REJECTED load: Failed to fetch 1.targets.json: Transport 'other' error fetching '1.targets.json': Hash mismatch for 1.targets.json: calculated 520194efbb9d3fb1df0182171a751582357313729e3bfe029a891694c5768d0f, expected 9a` | pass |
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

## Finding

`tough::TargetName` normalizes hostile names instead of rejecting them (`../../etc/passwd` → `etc/passwd`; `/etc/passwd` stays absolute). A consumer that joins `resolved()` onto a staging directory can escape it (an absolute path replaces the base in `Path::join`). Rift therefore never derives filesystem paths from repository target names: only allowlisted flat names that are already in normal form are staged (`rift_staging_name`).

## Android

The same scenarios against the Android build: [phase0-X2-android.md](phase0-X2-android.md).
