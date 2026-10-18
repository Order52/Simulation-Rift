# Evidence: PoCs A1–A7 and the worker lifecycle — Android (emulators, API 30, 35 with 16 KB pages, and 36)

Commands: `poc/android-feasibility/build.sh`, then `poc/android-feasibility/run-poc.sh <out-dir>` against one booted emulator. Host: macOS on Apple silicon, Android emulator with `google_apis` arm64-v8a images, 3 GB RAM, software GPU. Captured 2026-10-17 (second run, with the lifecycle test). Raw files: [`phase0-android-api36/`](phase0-android-api36/) and [`phase0-android-api30/`](phase0-android-api30/) (logcat omitted: it duplicates the result files). PIDs and UIDs differ between runs. Timings are from one run on an emulator with a software GPU, so they show orders of magnitude, not device performance.

| | API 36 | API 30 |
|---|---|---|
| Android | 16, patch 2025-07-05 | 11, patch 2021-08-05 |
| WebView | 133.0.6943.137 | 91.0.4472.114 (the image's stock version, never updated) |
| Page size | 4 KB | 4 KB |
| APK | 56.6 MB debug build, arm64 + x86_64 libraries | same APK |

`adb root` is used only to read the renderer's `/proc` from outside. An app cannot do this on Android, so Rift's runtime precondition is `isMultiProcessEnabled()` on an API ≥ 30 device (§8.4), and this inspection is the evidence that the precondition implies a sandboxed renderer.

## Results

| PoC | Check | API 36 | API 30 |
|---|---|---|---|
| A1 | `isMultiProcessEnabled()` | true | true |
| A1 | Renderer label, UID | `isolated_app`, 99010 | `isolated_app`, 99024 |
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
| A4/A7 | PdfRenderer in the isolated service, from a file fd | 791×1024, validated, 1172 ms (first use) | 791×1024, 86.6 ms |
| A4/A7 | Same, from a sealed RAM-backed memfd | identical pixels (12,212 inked), 12.0 ms | identical, 27.2 ms |
| A5 | YARA-X (pulley) compile; marker matched by both rules | 14.1 ms; yes | 7.8 ms; yes |
| A5 | 16 MiB scan, no match | 3.2 ms | 4.0 ms |
| A6 | Worker: `isolatedProcess`, UID, label | true, 99001, `isolated_app` | true, 99015, `isolated_app` |
| A6 | Worker: CapEff / NoNewPrivs / Seccomp | 0 / **0** / 2 | 0 / **0** / 2 |
| A6 | Worker: canary in app files, app data dir, `/sdcard` | denied | denied |
| A6 | Worker: `socket(AF_INET)`, TCP connect, DNS, clipboard | denied | denied |
| A6 | Worker: `socket(AF_UNIX)`, executable page mapping | **allowed** | **allowed** |

The 16 MiB scan is fast because no rule atom occurs in its repeating byte pattern. It is a floor, not a throughput figure for real files. The first PDF render includes loading PdfRenderer in a new process.

## Worker lifecycle (`lifecycle.txt`)

Each sample binds a new isolated process with `bindIsolatedService` and a unique instance name, makes one call, unbinds, and waits for the binder death notification.

| Check | API 36 | API 30 |
|---|---|---|
| Bind to connected, system zygote: first / median of 5 | 698 ms / **304 ms** | 442 ms / 91 ms |
| Bind to connected, app zygote (`useAppZygote`, native library preloaded): first / median of 5 | 157 ms / **45 ms** | 113 ms / 26 ms |
| Native library loaded in the app zygote | yes | yes |
| App `kill(pid, 0)` and `kill(pid, SIGKILL)` on the worker | **EPERM**; worker still alive | same |
| YARA-X in-process timeout (2 s) on a runaway rule | `TIMEOUT` after 2001 ms | `TIMEOUT` after 2001 ms |
| Worker stuck in a scan with no timeout, then unbound | died 4 ms after unbind; blocked call got `DeadObjectException` | died 3 ms after unbind; same |
| Every worker after unbind | died within 28 ms | died within 54 ms |
| Isolated processes left after the test | none | none |

Consequences for the design (architecture §8.6, §18):

- **`useAppZygote` is required, not optional.** Without it the median cold start on API 36 already misses the 300 ms budget. With it, the first worker (which also starts the app zygote) takes 113–157 ms and later ones 26–45 ms.
- **The app cannot signal its worker**, as assumed. The in-process timeout is therefore needed, and it works under Pulley.
- **Unbinding is a reliable kill switch.** Android ends an isolated process as soon as its last binding goes, even mid-scan, so the controller can always retire a worker that ignores its deadline.

## Size (A5)

`librift_poc_native.so` as cargo first built it: 22,987,192 bytes for arm64-v8a, of which about 9 MB is the symbol table. The Android Gradle plugin strips native libraries when packaging, so the APKs tested above contain the stripped library: **14,053,784 bytes for arm64-v8a and 18,290,512 for x86_64**. The libraries are stored uncompressed in the APK (needed for loading in place), so this is the size each ABI adds to the APK; gzip would bring arm64 to 5.1 MB for download. The budget is ≤ 25 MB per ABI (§18). Cargo release builds now also strip symbols (`strip = "symbols"`), so `build.sh` reports the shipped size. Both ABIs have 16 KB-aligned LOAD segments (checked by `build.sh`), and the arm64 library loaded and ran on a 16 KB page-size emulator image (API 35, above).

## API 35 with 16 KB pages (added 18 Oct 2026)

The same APK and `run-poc.sh`, on a `google_apis_ps16k` arm64 image (Android 15, `sdk_gphone16k_arm64`, patch 2024-09-05, WebView 124.0.6367.219, `getconf PAGE_SIZE` = 16384). Raw files: [`phase0-android-api35-16k/`](phase0-android-api35-16k/) (logcat omitted, as above).

| PoC | Result |
|---|---|
| Loading | Both native libraries (16 KB-aligned) loaded and ran: worker, PdfRenderer and YARA-X all answered. |
| A1 | `isMultiProcessEnabled()` true; renderer `isolated_app`, UID 99009, CapEff 0, NoNewPrivs 1, Seccomp 2 (4 filters); `file:`/`content:` fetches, geolocation, clipboard, getUserMedia denied; `window.open` and `intent://` blocked. |
| A2 | All six stores present in the session, absent after reset and after crash recovery, 0 leftovers. Both app-level prefs files appear here too, **including `AwOriginVisitLoggerPrefs.xml`** (as on API 36, unlike API 30). |
| A3 | As on API 30/36: GET, Content-Disposition, redirect and cookie-gated re-fetches match; the RLO/traversal name becomes `evilgpj.pdf`; POST re-fetch gets HTTP 405; `blob:` and `data:` never reach the listener. |
| A4/A7 | 791×1024, 12,212 inked pixels from both a file fd and a sealed memfd. |
| A5 | Marker matched by both rules; 16 MiB scan 6.9 ms. |
| A6 | Worker isolated (UID 99000), CapEff 0, **NoNewPrivs 0**, Seccomp 2; files, data dir, `/sdcard`, `AF_INET`, TCP, DNS and clipboard denied (EACCES, as on API 30); `AF_UNIX` and an executable mapping allowed. |
| Lifecycle | App `kill()` on the worker: EPERM. In-process YARA-X timeout: `TIMEOUT` after 2001 ms. A stuck worker died 3 ms after unbind. No isolated process left. |

Worker start times were noisy right after boot. In the first run the app-zygote median was 252.5 ms (system zygote 311.5 ms); in a second run minutes later it was **30.8 ms** (system zygote 116.9 ms; `lifecycle-run2.txt`). Both are under the 300 ms budget, but only just in the first run, so cold-start figures from a freshly booted emulator should not be used alone.

## Not shown by this evidence

- Physical devices, OEM WebView builds, API 33/34 and x86_64 images. A 16 KB page-size *emulator* image was run (above), not a 16 KB device.
- An updated WebView on API 30: the image's WebView 91 is years old. Real API 30 devices update WebView through Play.
- The harness picks the newest `sandboxed_process` in `ps` as the renderer. On API 36 a second renderer from before the run was also listed (pid 2628, UID 99000). The selected one (pid 4019) started after our `:browser` process (pid 3994), so the selection was right. Selection by order is still fragile.
