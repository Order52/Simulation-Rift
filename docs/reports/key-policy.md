# Intelligence signing keys: policy and response plan

**Status (21 Oct 2026):** the tooling and the client behaviour below are built and tested on the host. On Android, the same update code was rerun on the API 35 emulator (S16, S21, x1), and the device saved its trusted root. No production key exists yet. Making them is a ceremony for the maintainers, described here, and not something the repository can do. This document covers §13.2 of the [architecture](../architecture.md) and threat T5 (a compromised signing key).

## The policy

| Role | Signs | Keys | Threshold | Where the keys live | Expiry |
|---|---|---|---|---|---|
| root | which keys may sign each role | 3, one per holder | 2 | offline, each on its holder's own encrypted media | 365 d |
| targets | the pack files: names, lengths, SHA-256 | 2, one per holder | 2 | offline | 90 d |
| snapshot | the version of the targets metadata | 1 | 1 | the publishing machine | 14 d |
| timestamp | the version of the snapshot (freshness) | 1 | 1 | the publishing machine | 7 d |

- **One key per person.** No machine and no person holds two root keys, or two targets keys. `rift-pack key` writes one key, mode 0600, never inside a git work tree. Only the public half (`rift-pack public`) is passed around.
- **Offline and online keys never mix.** A root that lets one key sign both an offline role (root, targets) and an online role (snapshot, timestamp) is refused by `root-draft`, `root-check` and `publish-signed`. `publish-signed` also refuses to run when it is handed a root or targets key. A stolen publishing machine can therefore delay or freeze updates (until the timestamp expires), but it cannot sign a pack or a root.
- **Thresholds are checked where a client checks them.** `root-check` and `publish-signed` verify signatures with tough's own verifier. A release that a client would refuse is not published.
- **The app ships the newest root.** Release builds embed the root given at build time (`RIFT_INTEL_ROOT`). Each app release should carry the newest root, so that a fresh install does not start from a retired one.

The tool does not enforce the numbers in the table. A policy file can ask for 1 of 1. The table is the release rule, and `root-check` prints the thresholds so that a reviewer can compare them with it.

## Procedures

All commands are `rift-pack` (`cargo run -p rift-pack -- …`). Paths are examples.

**Making the first root (a ceremony, once).**

1. Each of the seven holders runs `rift-pack key alice-root.pk8` on their own machine, then `rift-pack public alice-root.pk8 alice-root.pub.json`, and hands over the `.pub.json` file and its key ID.
2. One person writes the policy and drafts the root:

   ```json
   {
     "version": 1,
     "expires": "2027-10-21T00:00:00Z",
     "root": {"threshold": 2, "keys": ["alice-root.pub.json", "bob-root.pub.json", "carol-root.pub.json"]},
     "targets": {"threshold": 2, "keys": ["dave-targets.pub.json", "erin-targets.pub.json"]},
     "snapshot": {"threshold": 1, "keys": ["publisher-snapshot.pub.json"]},
     "timestamp": {"threshold": 1, "keys": ["publisher-timestamp.pub.json"]}
   }
   ```

   `rift-pack root-draft policy.json root-1.json`
3. The draft goes to each root holder in turn: `rift-pack root-sign root-1.json alice-root.pk8`. Every holder checks the key IDs in the draft against the ones they were given before signing.
4. `rift-pack root-check root-1.json` must report the thresholds above. `root-1.json` is the root that release builds embed.

**Publishing a pack.**

1. `rift-pack targets-draft <pack-dir> <version> targets.json` validates the pack with the app's own validator and lists its four files.
2. Each targets holder runs `rift-pack targets-sign targets.json root-N.json dave-targets.pk8` on their own machine, after checking the pack's digest that `targets-draft` printed.
3. On the publishing machine: `rift-pack publish-signed targets.json <pack-dir> <repo-dir> <version> root-1.json … root-N.json -- publisher-snapshot.pk8 publisher-timestamp.pk8`. The command checks the chain of roots, the targets signatures, and that the pack's bytes match the signed targets. It then signs the snapshot and timestamp, and writes the timestamp last.

**Renewing the timestamp.** The timestamp expires after 7 days. Rerun `publish-signed` with the same signed targets and a higher version, at least every 6 days. Only online keys are used.

**Renewing or rotating the root.** A new root is a new version (N+1), drafted from a policy as above. It needs **two** thresholds: its own root keys (`root-sign root-N+1.json <new key>`) and the previous root's (`root-sign root-N+1.json <old key> root-N.json`). `rift-pack root-check root-N+1.json root-N.json` confirms both. Every repository keeps the whole chain `1.root.json … N+1.root.json`, and clients walk it from the root they trust. A yearly renewal with the same keys is the same procedure.

## What the client does

- **It starts from the newest root it has verified.** Until this change, every update started from the root built into the app. tough walks forward from the root it is given, and it keeps a copy (`root.json`) in its datastore that it never reads back. So after a rotation, a mirror could hide the newer roots and sign with the retired keys, and the device accepted it (finding 64, reproduced by `a_rotation_is_followed_and_the_retired_keys_cannot_return` before the fix). Rift now saves the newest verified root itself (`trusted-root.json`, written atomically) and starts from whichever is newer: the saved root or the built-in one.
- **It saves the root when the whole metadata chain has verified**, before any pack file is fetched. A rotation then holds even if a pack file turns out bad.
- **A saved root that cannot be read or does not verify is refused** ("unreadable"). It is not replaced by the built-in root, which could bring the retired keys back. Recovery is to clear the app's data, which also removes the vault, or to install an app build that embeds a newer root.

## Tests

`crates/rift-update/tests/rotation.rs`. Each test generates one key per holder and builds everything with the production commands, as a release would be built.

| Test | Shows |
|---|---|
| `a_threshold_root_installs_offline_signed_targets` | A 2-of-3 root with 2-of-2 offline targets installs a pack; `root-check` prints the thresholds. |
| `signatures_short_of_a_threshold_are_refused` | A root with 1 of its 2 required signatures is refused by `root-check` and by a client that embeds it ("signature"). Targets with 1 of 2 signatures are not published. |
| `a_rotation_is_followed_and_the_retired_keys_cannot_return` | A client that embeds root v1 follows a rotation to v2, in which every key is replaced. A newer release signed with all of v1's keys, with v2 hidden, is then refused ("signature"), and the installed pack stays. |
| `a_rotation_needs_the_previous_root_threshold` | A v2 cross-signed by only 1 of v1's root keys is refused by `root-check` and `publish-signed`. When a mirror serves it, the client refuses it too. |
| `a_damaged_saved_root_is_refused_not_replaced_by_the_built_in_one` | A torn `trusted-root.json` gives "unreadable", not a fall-back to the built-in root. |
| `the_tool_keeps_offline_and_online_keys_apart` | A policy that lets the timestamp key sign targets is refused. So is a stranger's key or a second signature by the same key, and a root key handed to `publish-signed`. |

The same flow was also run with the command-line tool, from seven new keys through a rotation, and checked with `cargo run -p rift-update --example verify`. Release 1 and the rotated release 2 verify from the built-in root v1. The replay signed with the retired keys gives "Signature threshold of 1 not met for role timestamp". Evidence: [`evidence/key-policy/cli-run.txt`](evidence/key-policy/cli-run.txt).

## Response plan

What to do when a key is lost or may be compromised. "Rotate" means the procedure above: a new root version that drops the key, signed by the new root threshold and by the old one.

| What happened | Impact | Response |
|---|---|---|
| Timestamp or snapshot key stolen (publishing machine compromised) | The attacker can replay an older release until it expires, or freeze updates for up to 7 days. They cannot sign a pack or a root. | Rotate the online keys onto a clean machine. Clients that fetch the new root drop their saved timestamp and snapshot (tough's fast-forward recovery), so versions inflated by the attacker do not stall later releases. |
| One targets key stolen | Nothing on its own: targets need 2 of 2. | Rotate it out. Until then, the other holder signs nothing they did not draft. |
| Both targets keys stolen | The attacker can sign packs. The online keys are still needed to publish, and the app still validates every pack and compiles its rules in the isolated worker. But a signed pack can mark files or sites as safe or as malicious. | Rotate the targets keys at once. Publish a new release with a higher targets version, so that clients replace whatever the attacker signed. Tell users. |
| One root key stolen or lost | Nothing on its own: 2 of 3. | Rotate it out with the other two. |
| Two root keys stolen | The attacker can sign new roots, and so take over updates for every client that fetches them. | Rotate at once with the remaining keys, if a root has not already been published by the attacker. Ship an app update that embeds the new root. A client that has already accepted the attacker's root can only be recovered by an app update and clearing its data. Treat this as a full compromise and say so publicly. |
| Root keys lost (not stolen) below threshold | No new root can be signed. Updates continue until the root expires (365 d). | Ship an app update with a new built-in root. Clients start from the newer of the two roots, so the new built-in root needs a higher version than any root published. |

**Retired keys and devices that never updated.** A device that has verified the new root ignores the retired keys (tested). A device that has not fetched since the rotation still trusts the old root. An attacker who holds the old keys **and** controls that device's view of the update server can keep the new root from it. App updates that embed the newest root close this for every device that updates the app.

## What is not covered

- **No production keys exist.** Nothing here is a ceremony that was performed. The tests use keys made for each test.
- **Keys are plain PKCS#8 files.** They are not on hardware tokens. tough's `KeySource` would allow a PKCS#11 or cloud KMS source, but `rift-pack` does not offer one. Holders must keep the files on encrypted, offline media.
- **tough's own saved state is not atomic.** tough rewrites its saved `timestamp.json` and `snapshot.json` in place, and skips the rollback check when it cannot parse them. A torn write after a power cut would therefore skip that check for one update. Rift's own root file is written atomically; the rollback state is still tough's.
- **The rotation tests run on the host only.** The client code is the same on Android, and the emulator run above shows the device saving its root, but no rotation was published to a device.
- **No delegated targets.** One targets role signs the whole pack.
- **Nothing reviews the pack's content.** Signatures prove who released a pack, not that its indicators are right (B6).
