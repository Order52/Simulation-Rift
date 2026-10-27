# Listing Rift in app stores

Rift is published as GitHub releases, which Obtainium follows ([README](../README.md#install)). This page is for the maintainer who submits Rift to **IzzyOnDroid** and, later, **F-Droid**. The submissions have to come from the maintainer's own account; nothing here submits anything.

## What is ready

| Need | Where |
|---|---|
| Title, short and full description, screenshots, changelogs | `fastlane/metadata/android/en-US/` (the layout both stores read). A changelog is `changelogs/<versionCode>.txt`; a release's code is major × 1,000,000 + minor × 1,000 + patch (`release.yml`), so 0.11.5 is `11005` |
| An APK without Rift's own updater on | `rift-store-<version>.apk` in each release, from the same commit, signed with the same key (`release.sh`). It is built with `-Prift.store=true`: "Check when Rift opens" and "Update Rift by itself" start **off**, and the Updates card says the store updates Rift (§8.11). The user can turn them on |
| Licence | MIT or Apache 2.0, at the user's choice (`LICENSE-MIT`, `LICENSE-APACHE`) |
| Dependencies | Free software only: AndroidX, Jetpack Compose, Shizuku, JNA, and Rust crates checked by `cargo deny` ([dependencies.md](reports/dependencies.md)). No Google Play services, Firebase, analytics or ads |
| Size | About 24 MB (arm64 only), under IzzyOnDroid's usual 30 MB per app |

## IzzyOnDroid (recommended first)

IzzyOnDroid takes the APK from the GitHub release as it is, so Rift's signature, and the browser APK inside it signed with the same key, stay as they are.

1. Open a request in IzzyOnDroid's repository on Codeberg (`codeberg.org/IzzyOnDroid/repo`, "issues"), as its template asks. Give:
   - the package name `org.simulationrift.app` and the repository `https://github.com/Order52/Simulation-Rift`;
   - the APK to take: the release asset matching `^rift-store-.*\.apk$` (not `rift-<version>.apk`, which has the updater on, nor `rift-browser-…`, which Rift installs itself);
   - the signing certificate's SHA-256, printed in every release's notes.
2. Expect questions about these permissions, and answer them:
   - **`REQUEST_INSTALL_PACKAGES`**: Rift installs its own sealed browser, a second APK carried inside it, on first start (§8.10), and reinstalls it if it is missing. In the store APK, Rift does not install its own updates unless the user turns that on.
   - **`BIND_VPN_SERVICE`** (the VPN service): it applies to the browser's UID only and drops everything, so the browser's only route out is Rift's checked proxy (INV-14). It does not carry the user's other traffic.
   - **`HIDE_OVERLAY_WINDOWS`**: other apps' overlays are hidden over Rift's warnings (tapjacking).
   - **`moe.shizuku.manager.permission.API_V23`**, from the Shizuku library: Shizuku's own permission, granted only through Shizuku's prompt, for the optional Extra isolation, which uses Shizuku to tighten the browser's app-ops and firewall (§8.9). Without Shizuku it does nothing.
   - **`QUERY_ALL_PACKAGES`** is not used; Rift declares the packages it asks about (Orbot, its browser).
3. IzzyOnDroid's scanner reads the APK for trackers and proprietary libraries; there should be none. If it flags something, compare with [dependencies.md](reports/dependencies.md).
4. Once listed, every release's `rift-store-…apk` reaches IzzyOnDroid users within a day or so. Nothing more to do per release, except a changelog file when the changes matter to users.

## F-Droid (later)

F-Droid builds every app from source on its own servers and signs it with its own key, unless the build reproduces the developer's APK bit for bit. Rift has two problems with that today:

- **The embedded browser.** Rift installs its browser only if it carries Rift's certificate (§8.10). An F-Droid build would have to sign the browser APK with F-Droid's key *before* building the app around it, which F-Droid's build recipes cannot do. The way out is **reproducible builds** with Rift's own signature (F-Droid's `AllowedAPKSigningKeys` and the developer-signed APK). That needs `release.sh`'s output to be byte-identical when rebuilt elsewhere, which has not been tested (Rust's paths, the NDK, R8 and the build timestamps would all have to be pinned).
- **The toolchain.** The build needs Rust (pinned in `rust-toolchain.toml`), the Android Rust targets, `cargo-ndk`, the NDK and the UniFFI bindgen run by `build.sh`. F-Droid supports this in a recipe (`sudo:` and `prebuild:` steps), but it is long and must be kept in step with `toolchains.yml`.

When reproducibility has been shown (build twice in clean containers and compare with `apksigner` and `diffoscope`), open a merge request to `fdroiddata` on GitLab with `metadata/org.simulationrift.app.yml`, using the store build (`-Prift.store=true`) and the release certificate in `AllowedAPKSigningKeys`.

## Unverified

- No submission has been made, so neither store's reviewers have answered yet.
- IzzyOnDroid's rules are as found on 27 October 2026 ([inclusion policy](https://izzyondroid.org/docs/general/AppInclusionPolicy/)); they may ask for more.
- The store build was checked on the API 34 emulator (both switches start off, the normal build's start on), not on a phone.
