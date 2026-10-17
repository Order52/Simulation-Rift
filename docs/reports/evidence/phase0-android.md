# Evidence: PoCs A1–A7 — Android (emulators, API 30 and 36)

Commands: `poc/android-feasibility/build.sh`, then `poc/android-feasibility/run-poc.sh <out-dir>` against one booted emulator. Host: macOS on Apple silicon, Android emulator with `google_apis` arm64-v8a images, 3 GB RAM, software GPU. Captured 2026-10-17. Raw files: [`phase0-android-api36/`](phase0-android-api36/) and [`phase0-android-api30/`](phase0-android-api30/) (logcat omitted: it duplicates the result files).

| | API 36 | API 30 |
|---|---|---|
| Android | 16, patch 2025-07-05 | 11, patch 2021-08-05 |
| WebView | 133.0.6943.137 | 91.0.4472.114 (the image's stock version, never updated) |
| Page size | 4 KB | 4 KB |
| APK | 56.7 MB debug, unstripped arm64 + x86_64 libraries | same APK |

`adb root` is used only to read the renderer's `/proc` from outside. An app cannot do this on Android, so Rift's runtime precondition is `isMultiProcessEnabled()` on an API ≥ 30 device (§8.4), and this inspection is the evidence that the precondition implies a sandboxed renderer.

## Results

| PoC | Check | API 36 | API 30 |
|---|---|---|---|
| A1 | `isMultiProcessEnabled()` | true | true |
| A1 | Renderer label, UID | `isolated_app`, 99005 | `isolated_app`, 99003 |
| A1 | Renderer CapEff / NoNewPrivs / Seccomp | 0 / 1 / 2 (4 filters) | 0 / 1 / 2 |
| A1 | Page: `fetch(file://)`, `fetch(content://)` | denied | denied |
| A1 | Page: geolocation, clipboard read, getUserMedia | denied | denied |
| A1 | Page: `window.open`, `intent://` navigation | blocked, blocked | blocked, blocked |
| A2 | Same session: cookie, server cookie, localStorage, IndexedDB, Cache Storage, service worker | all present | all present |
| A2 | After reset (new generation) | all absent; 0 leftovers | all absent; 0 leftovers |
| A2 | Controller killed after killing `:browser`, before deleting | `app_webview_s2` with cookies and IndexedDB left on disk | same |
| A2 | Recovery on next launch, then probe | marker found, all deleted, generation 2→3, all absent | same |
| A2 | App-level WebView prefs outside the suffix | `WebViewChromiumPrefs.xml`, **`AwOriginVisitLoggerPrefs.xml`** | `WebViewChromiumPrefs.xml` |
| A3 | Plain GET, Content-Disposition, redirect, cookie-gated | listener called; re-fetch OK, hashes match the server | same |
| A3 | Display name `../../evil‮gpj.pdf` (RLO, traversal) | normalized to `evilgpj.pdf` | same |
| A3 | POST form response | listener called; re-fetch **HTTP 405** | same |
| A3 | `blob:` and `data:` downloads | **listener never called** | same |
| A4/A7 | PdfRenderer in the isolated service, from a file fd | 791×1024, validated, 781 ms (first use) | 791×1024, 52.9 ms |
| A4/A7 | Same, from a sealed RAM-backed memfd | identical pixels (12,212 inked), 10.8 ms | identical, 20.1 ms |
| A5 | YARA-X (pulley) compile; marker matched by both rules | 24.5 ms; yes | 4.1 ms; yes |
| A5 | 16 MiB scan, no match | 1.6 ms | 2.0 ms |
| A6 | Worker: `isolatedProcess`, UID, label | true, 99004, `isolated_app` | true, 99000, `isolated_app` |
| A6 | Worker: CapEff / NoNewPrivs / Seccomp | 0 / **0** / 2 | 0 / **0** / 2 |
| A6 | Worker: canary in app files, app data dir, `/sdcard` | denied | denied |
| A6 | Worker: `socket(AF_INET)`, TCP connect, DNS, clipboard | denied | denied |
| A6 | Worker: `socket(AF_UNIX)`, executable page mapping | **allowed** | **allowed** |
| A6 | `bindService` to connected (no app zygote) | 339 ms | 167 ms |

The 16 MiB scan is fast because no rule atom occurs in the zero-filled input. It is a floor, not a throughput figure for real files.

## Size (A5)

`librift_poc_native.so` as cargo first built it: 22,987,192 bytes for arm64-v8a, of which about 9 MB is the symbol table. The Android Gradle plugin strips native libraries when packaging, so the APKs tested above already contained the stripped library: **14,053,656 bytes for arm64-v8a and 18,290,320 for x86_64**. The libraries are stored uncompressed in the APK (needed for loading in place), so this is the size each ABI adds to the APK; gzip would bring arm64 to 5.1 MB for download. The budget is ≤ 25 MB per ABI (§18). Cargo release builds now also strip symbols (`strip = "symbols"`), so `build.sh` reports the shipped size; a rebuilt APK still loads the library and passes the worker test on API 30. Both ABIs have 16 KB-aligned LOAD segments (checked by `build.sh`), but no 16 KB page-size device or image was run.

## Not shown by this evidence

- Physical devices, OEM WebView builds, API 33/34/35, x86_64 images, and 16 KB page-size devices.
- An updated WebView on API 30: the image's WebView 91 is years old. Real API 30 devices update WebView through Play.
- That the app cannot kill or signal its isolated worker, and that the in-process YARA-X timeout fires (no scan ran long enough).
- Worker cold start with `useAppZygote`. The PoC binds without it and API 36 already misses the 300 ms budget.
- The harness picks the newest `sandboxed_process` in `ps` as the renderer. On API 36 a second renderer (UID 99000) from an earlier run was also listed. The selected one (pid 8022) started after our `:browser` process (pid 7997) and the other (pid 3888) before it, so the selection was right this time. Selection by order is still fragile.
