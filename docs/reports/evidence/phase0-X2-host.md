# Evidence: PoC X2 — offline TUF verification (host)

Command: `poc/tuf-offline/run-scenarios.sh poc/target/release/tuf-offline` with tuftool 0.17.0 and tough 0.24.0 on macOS 26.6.2 (arm64). Captured 2026-10-17T08:40Z. Repositories are generated fresh on each run (RSA keys, 1-of-1 thresholds — production key policy is separate).

| scenario | expected | client output | result |
|---|---|---|---|
| valid repository + target | OK | `OK timestamp=v1 snapshot=v1 targets=v1; target pack.bin verified (65536 bytes)` | pass |
| target bytes modified | REJECTED | `REJECTED target verification: Failed to fetch file:///private/var/folders/4_/6nyg48vd5kx7n0b776d2q0hc0000gn/T/tmp.qyPatRsIXf/repo-tamper-target/targets/bef8d455` | pass |
| targets.json modified (unsigned) | REJECTED | `REJECTED load: Failed to fetch file:///private/var/folders/4_/6nyg48vd5kx7n0b776d2q0hc0000gn/T/tmp.qyPatRsIXf/repo-tamper-meta/metadata/1.targets.json: Transpor` | pass |
| rollback: load v1 into fresh store | OK | `OK timestamp=v1 snapshot=v1 targets=v1` | pass |
| rollback: update to v2 | OK | `OK timestamp=v2 snapshot=v2 targets=v2; target pack.bin verified (65536 bytes)` | pass |
| rollback: replay v1 after v2 was trusted | REJECTED | `REJECTED load: Found version 1 of timestamp metadata when we had previously fetched version 2` | pass |
| expired timestamp | REJECTED | `REJECTED load: timestamp metadata is expired` | pass |
| repository signed by an untrusted root | REJECTED | `REJECTED load: Failed to verify timestamp metadata: Signature threshold of 1 not met for role timestamp (0 valid signatures)` | pass |
| timestamp.json above 16 KiB limit | REJECTED | `REJECTED load: Failed to fetch file:///private/var/folders/4_/6nyg48vd5kx7n0b776d2q0hc0000gn/T/tmp.qyPatRsIXf/repo-oversize/metadata/timestamp.json: Transport '` | pass |
| target not listed in metadata | REJECTED | `REJECTED target TargetName { raw: "missing.bin", resolved: None } not listed` | pass |
| tough TargetName ../../etc/passwd (informational) | — | `OK accepted as "etc/passwd"` | info |
| tough TargetName a/../../escape (informational) | — | `OK accepted as "escape"` | info |
| tough TargetName /etc/passwd (informational) | — | `OK accepted as "/etc/passwd"` | info |
| Rift policy: ../../etc/passwd | REJECTED | `REJECTED target name "../../etc/passwd" is not in normal form` | pass |
| Rift policy: a/../../escape | REJECTED | `REJECTED target name "a/../../escape" is not in normal form` | pass |
| Rift policy: /etc/passwd | REJECTED | `REJECTED target name "/etc/passwd" is not a known pack file` | pass |
| Rift policy: ./url-hashes.bin | REJECTED | `REJECTED target name "./url-hashes.bin" is not in normal form` | pass |
| Rift policy: unknown.bin | REJECTED | `REJECTED target name "unknown.bin" is not a known pack file` | pass |
| Rift policy: url-hashes.bin | OK | `OK staged as "url-hashes.bin"` | pass |

failures: 0

## Finding

`tough::TargetName` normalizes hostile names instead of rejecting them (`../../etc/passwd` → `etc/passwd`; `/etc/passwd` stays absolute). A consumer that joins `resolved()` onto a staging directory can escape it (an absolute path replaces the base in `Path::join`). Rift therefore never derives filesystem paths from repository target names: only allowlisted flat names that are already in normal form are staged (`rift_staging_name`).

## Not yet verified

- Cross-compilation of tough (aws-lc-rs) for aarch64/x86_64 Android and the binary-size cost — pending NDK installation.
