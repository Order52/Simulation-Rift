# Architecture 2.7: Rift AI with factors and in packs, real feeds, key ceremony, a phone

**Date:** 24 October 2026. **Architecture:** 2.7 (§13.1, §13.3, §16). **Linux:** on hold, not touched.

## What changed

1. **Rift AI is a factorization machine** (`rift_core::urlmodel`, `tools/rift-train/src/fm.rs`). Besides one weight per feature, each feature has a 4-number vector, and every pair of features in an address adds the dot product of their vectors to the score. It was kept only because it beat the linear model on sites it never saw: never-seen phishing at High went up 1–2 points on two seeds and on the time-separated test, false alarms did not change, the file stays under 2 MiB (1.8 MB), and scoring stays near 2 µs ([rift-ai.md](rift-ai.md)).
2. **URLhaus is no longer used.** abuse.ch's terms, updated on 21 October 2026, forbid training AI models on its data and making derived works without consent. The malware-filter mirror's CC0 label does not change that. The model shipped on 24 October was trained without it, and it still rates 90.8% of a sample of never-seen URLhaus hosts High. The packs Rift publishes leave URLhaus out.
3. **A signed pack can carry Rift AI's model** (`url-model.bin`, optional). It is validated with the pack, covered by the pack's digest, and while that pack is installed it replaces the shipped model everywhere. The protection details say which model is on.
4. **Real feeds:** `tools/rift-pack/feeds.sh` builds a pack from Phishing.Database's ACTIVE links, with the model in it, and drafts the targets metadata for offline signing.
5. **Key ceremony:** `tools/rift-pack/ceremony.sh` and [key-ceremony.md](key-ceremony.md) cover the 2-of-3 root and 2-of-2 targets keys on offline drives, root signing, targets signing for each release, and a rehearsal with throwaway keys.
6. **Monthly retraining:** `tools/rift-train/retrain.sh` redoes the whole training from the downloads, `gate.py` refuses a worse model, and the `retrain rift ai` workflow opens a pull request with the result.
7. **Fuzzing:** a new target, `url_model`, covers the model parser. Model files now arrive inside packs, so they count as untrusted input. The fuzz-campaign workflow now runs every target by default.
8. **f2 explained.** Android runs every debuggable app with CheckJNI (logcat: "Late-enabling -Xcheck:jni"). On the emulator this makes each crossing of the UniFFI/JNA bridge cost 320–390 µs, even for a call that does nothing. A filter check crosses about four times (the call plus one buffer per string), hence 1.5–3.5 ms. f2 now measures an empty call next to the check. In a debuggable build, a check may cost at most eight empty calls; in other builds it must stay under 1 ms. Both numbers are reported.
9. **A misleading message.** When Android refused to start the browser app's session service, Rift said "the browser app is not installed". It now says so only when the browser app really is missing. Otherwise it says the system would not start the browser app, and names Huawei's App launch setting.

## Verified

- **Rust:** 229 tests in the product workspace, `clippy -D warnings`, `fmt` and `cargo deny` all pass. New tests:
  - Factors weigh features that appear together.
  - Damaged factor sections are refused.
  - A pack's model is optional, validated and covered by the pack's digest.
  - The snapshot store installs a model and reads it back.
  - A signed pack's model replaces the shipped one, and reopening keeps it.
  - A feeds pack names only the feeds it was built from.
- **Rift AI:** see [rift-ai.md](rift-ai.md).
  - The test split, the fit table, the time-separated table and the hand-checked addresses were all measured on 24 October.
  - `gate.py` passes the new model against the shipped one.
  - `cargo test -p rift-ffi ai::` passes on the new file.
- **Key ceremony rehearsal** ([evidence](evidence/key-ceremony/rehearsal.txt)):
  - A root with one signature is short of its 2-of-3 threshold; the second signature completes it.
  - A release signed 2 of 2 offline is published with the online keys.
  - An offline root key handed to the publishing step is refused.
  - The app's own verifier accepts the result.
  - On this online machine, the offline steps refused to run.
- **Feeds pack on the API 34 emulator** ([evidence](evidence/feeds-pack-api34/run.txt)):
  - 58,633 Phishing.Database entries were listed. 476 host-wide entries on popular sites were dropped.
  - The pack was imported with the system folder picker and installed.
  - The protection details show "the model from the installed threat database (d6c2bc607dfd)".
  - Checking a listed `pages.dev` link gives Known malicious.
  - The pack's notice names Phishing.Database only.
- **The full suite on the API 34 arm64 emulator** ([evidence](evidence/release-2.7-api34/)):
  - All 59 instrumented tests pass. The 6 that skip there run from the host or need extra isolation.
  - The host steps pass: S16d, S16f, S14, S13, H1 and H4.
  - The fault rounds pass: 8 of 8 kills in F4, and the full disk (F6).
- **Fuzz campaign:** 11 targets for 20 minutes each on macOS arm64, about 616 million runs in all, with no finding ([evidence](evidence/fuzz-campaign-2026-10-24/summary.txt)). `url_model` reached coverage 2,822 (267 before its inputs were shaped into whole models).
- **f2 on the API 34 emulator:** 1,528 µs per check, against 387 µs per empty call in the same run. The test passes.
- **A physical phone** (Huawei CHZ-LX1, Android 12, Huawei WebView 114, not rooted; [evidence](evidence/phone-huawei-chz-lx1/)):
  - 27 instrumented tests pass, including s01, s03–s08, n1–n7, n9, p1, p2, i1, h2, h3, l1 and r1.
  - 27 failures share one cause outside Rift: EMUI's launch manager refused to start the browser app's session service ("Service starting has been prevented by iaware or trustsbase"), so no new session could start.
  - 4 are fault rounds that need `adb root`.
  - s02 found POST_NOTIFICATIONS granted on this phone.

## Unverified

- **The phone run with Huawei's App launch setting allowed** for Rift Browser. The phone was locked, so the setting could not be changed.
- **The phone's fault rounds and host checks** (F3–F6, S13, S14, H1): they need `adb root`, which a retail phone does not give.
- **The ceremony itself.** No production key exists. Packs are signed with the demo keys, which only debug builds trust, so a release build cannot install the feeds pack yet.
- **The monthly retraining workflow** has not run on GitHub. `retrain.sh` was checked for syntax and its steps were run one by one, not as one script. The workflow needs "Allow GitHub Actions to create pull requests", and optionally a `RIFT_SEARCH_TOKEN` secret.
- **A release-build timing for f2.** The 1 ms limit for non-debuggable builds has not been measured.
- **The worker fuzz targets** (`worker_image`, `worker_scan`): they do not link on macOS and were not part of this campaign. They run in the Linux workflow.

## Could be improved

- **Fewer bridge crossings per filter check.** One packed string instead of three would save two crossings in every build.
- **"Open safely" and "View safely".** These labels say "safe", which §1's wording rules avoid. They predate this work and were left as they are.
- **Malware hosts:** with consent from abuse.ch, URLhaus could return to both the packs and the training. Until then, malware hosts are caught by resemblance only.
- **Hardware tokens for the offline keys,** instead of PKCS#8 files on encrypted drives.
