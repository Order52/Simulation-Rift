# Production keys: the ceremony, step by step

**Status (24 Oct 2026):** not performed. The script (`tools/rift-pack/ceremony.sh`) and this guide are ready, and the whole ceremony plus a release was rehearsed with throwaway keys ([evidence](evidence/key-ceremony/rehearsal.txt)). Until a maintainer performs it, every pack is signed with the demo keys and says so (`demo: true` for the demo pack; the feeds pack is real data under the demo root, which only debug builds trust). The policy it carries out is [key-policy.md](key-policy.md) (§13.2).

## What you need

- **An offline machine.** A laptop with Wi-Fi off and no cable is enough; a live system started from a USB stick (Debian live, Tails) is better, because nothing else is installed on it. Every offline step refuses to run while the machine has a network route.
- **Five key drives**, one per offline key: `ROOT-A`, `ROOT-B`, `ROOT-C`, `TARGETS-A`, `TARGETS-B`. Encrypt each one (APFS encrypted, LUKS, or VeraCrypt) with its own passphrase. Label them.
- **One transfer drive**, not encrypted, for what travels between machines: the `rift-pack` binary, this script, the public halves of the keys, drafts, and signed metadata. Never a private key.
- **The publishing machine** (online), which keeps the snapshot and timestamp keys in `~/.local/share/simulation-rift/release-keys` (outside the repository, mode 0700).

**If you are the only maintainer.** The policy asks for one key per person. Alone, you hold all five drives, so 2 of 3 still protects against losing one drive or having one stolen, but not against you being coerced or your offline machine being compromised. Keep `ROOT-C` somewhere else (another building, a safe deposit box): it is the spare that lets you replace a lost drive. Each targets drive is needed for every release, so keep those two where you work, but apart.

## 0. Before going offline

On the publishing machine, in the repository:

```sh
cargo build --release --locked -p rift-pack
sh tools/rift-pack/ceremony.sh rehearse "$(mktemp -d)"      # must end with "rehearsal passed"
cp target/release/rift-pack tools/rift-pack/ceremony.sh /Volumes/TRANSFER/
```

The binary must be built for the offline machine's system (on a Linux live system, build it on Linux).

## 1. Make the offline keys (offline machine)

For each key drive in turn: mount it, run, then unmount it.

```sh
export RIFT_PACK=/Volumes/TRANSFER/rift-pack
sh /Volumes/TRANSFER/ceremony.sh key root a /Volumes/ROOT-A
sh /Volumes/TRANSFER/ceremony.sh key root b /Volumes/ROOT-B
sh /Volumes/TRANSFER/ceremony.sh key root c /Volumes/ROOT-C
sh /Volumes/TRANSFER/ceremony.sh key targets a /Volumes/TARGETS-A
sh /Volumes/TRANSFER/ceremony.sh key targets b /Volumes/TARGETS-B
```

Each prints the key ID and the SHA-256 of its public half. Write both down on paper, then copy only the `.pub.json` file to the transfer drive.

## 2. Make the online keys (publishing machine)

```sh
K=~/.local/share/simulation-rift/release-keys; mkdir -p $K && chmod 700 $K
sh tools/rift-pack/ceremony.sh key snapshot publisher $K
sh tools/rift-pack/ceremony.sh key timestamp publisher $K
cp $K/*.pub.json /Volumes/TRANSFER/
```

## 3. Draft and sign the root (offline machine)

```sh
cd /Volumes/TRANSFER
sh ceremony.sh policy policy.json 2027-10-01T00:00:00Z \
  rift-root-a.pub.json rift-root-b.pub.json rift-root-c.pub.json \
  rift-targets-a.pub.json rift-targets-b.pub.json \
  rift-snapshot-publisher.pub.json rift-timestamp-publisher.pub.json
sh ceremony.sh draft policy.json root-1.json
```

Compare every SHA-256 that `policy` printed with what you wrote down. Then mount `ROOT-A` and sign, unmount it, and do the same with `ROOT-B`:

```sh
sh ceremony.sh sign root-1.json /Volumes/ROOT-A/rift-root-a.pk8   # "not yet at its threshold"
sh ceremony.sh sign root-1.json /Volumes/ROOT-B/rift-root-b.pk8   # root 2 of 3, targets 2 of 2, snapshot 1 of 1, timestamp 1 of 1
```

`ROOT-C` does not sign. It goes to its other place.

## 4. Build the app with the production root (publishing machine)

```sh
RIFT_INTEL_ROOT=/Volumes/TRANSFER/root-1.json RIFT_INTEL_URL=https://<your host>/rift/ sh android/release.sh
```

Release builds then verify updates against this root only (§13.2). The update URL must be https, with `metadata/` and `targets/` under it.

## Each release

1. **Draft (publishing machine):** `sh tools/rift-pack/feeds.sh <work-dir> <version>` fetches Phishing.Database (not URLhaus: its terms forbid redistribution), builds the pack with Rift AI's model, and writes `targets-<version>.json`. `<version>` is one more than the last release. Copy the targets file and the pack's digest to the transfer drive.
2. **Sign (offline machine):** with each targets drive in turn: `sh ceremony.sh sign-targets targets-<version>.json root-1.json /Volumes/TARGETS-A/rift-targets-a.pk8` (then `TARGETS-B`). Check the digest it prints against the one from step 1.
3. **Publish (publishing machine):**

   ```sh
   K=~/.local/share/simulation-rift/release-keys
   cargo run --release -p rift-pack -- publish-signed /Volumes/TRANSFER/targets-<version>.json <work-dir>/pack <repo-dir> <version> \
     /Volumes/TRANSFER/root-1.json -- $K/rift-snapshot-publisher.pk8 $K/rift-timestamp-publisher.pk8
   cargo run -p rift-update --example verify -- /Volumes/TRANSFER/root-1.json <repo-dir> "$(mktemp -d)"
   ```

   Upload `<repo-dir>` to the update host.
4. **Every 6 days:** rerun `publish-signed` with the same signed targets and a higher version. The timestamp expires after 7 days, and only online keys are used.

The targets expire after 90 days, and the feeds pack asks to be refreshed after 7. A release every week or two keeps devices current, and each one needs the two targets drives.

## Each year, or after a loss

Follow "Renewing or rotating the root" in [key-policy.md](key-policy.md): draft `root-2.json` from a new policy, sign it with two new root keys **and** with two keys of root v1 (`sh ceremony.sh sign root-2.json <old key> root-1.json`), and check it with `sh ceremony.sh check root-2.json root-1.json`. Publish the whole chain, and ship an app release that embeds the newest root.

## What this does not cover

- The ceremony has not been performed; there is no production key.
- Keys are PKCS#8 files on encrypted drives, not on hardware tokens.
- The offline check looks for a default network route only. It does not prove that the machine is clean.
