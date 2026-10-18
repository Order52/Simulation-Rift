# Phase 2 report: Android vertical slice

**Status:** built and tested on emulators (18 Oct 2026): the full suite passes on API 36 and on API 35 with 16 KB pages, and a shrunk release build passed a smoke test. **The gate is not met yet:** §22 asks for S1–S12 on the device matrix, and API 33/34, x86_64 and a physical phone are still missing (see Unverified). API 30 results are recorded below. S11 needs the scanner, so it moves to Phase 3. "Verified" means tested in the stated environment only. Nothing here claims complete isolation or the absence of vulnerabilities.

Raw evidence was produced by `android/build.sh`, then `android/run-tests.sh <dir>`, on each emulator:

| Environment | WebView | Pages | Evidence |
|---|---|---|---|
| API 36 (Android 16, `sdk_gphone64_arm64`, patch 2025-07-05) | 133.0.6943.137 | 4 KB | [`evidence/phase2-android-api36/`](evidence/phase2-android-api36/) |
| API 35 (Android 15, `sdk_gphone16k_arm64`, patch 2024-09-05) | 124.0.6367.219 | **16 KB** | [`evidence/phase2-android-api35-16k/`](evidence/phase2-android-api35-16k/) |
| API 30 (Android 11) | 91.0.4472.114 (below the minimum of 100) | 4 KB | [`evidence/phase2-android-api30/`](evidence/phase2-android-api30/) |

All runs use the debug build, with `adb root` for S13/S14. The results table below gives the API 36 figures; API 35 was run before N4 was added and matched the rest test for test (19 + 2 pass; rendered previews 59–442 ms; hang ended at 12.2 s; reset 126 ms; same S3/S4 denials; clean inventory).

## What was built

| Part | What it does | Where |
|---|---|---|
| `rift-ffi` | UniFFI interface of the controller: navigation decisions with explained reasons, sessions (start, reset, recovery), downloads into quarantine, preview jobs with reply validation. Plain values only cross into Kotlin; keys and stores stay in Rust. | `crates/rift-ffi` |
| `rift-core::download` | The core's own re-fetch of a download (INV-13): destination check on every resolved address of every hop, manual redirects, streamed limit, cookies only to their origin, cancellation at reset. | `crates/rift-core/src/download.rs` |
| `rift-worker-ffi` | UniFFI interface of the worker, loaded only in the isolated process: frames requests for `rift-worker`, and frames the results of platform PDF rendering. It links no core code. | `crates/rift-worker-ffi` |
| Compose shell | Home screen (session state, failure and retry, quarantine with previews, local-host allowance, protection coverage) and a trusted browser bar (session, protection summary, reset, address). | `android/app/src/main/kotlin/…/MainActivity.kt`, `BrowserActivity.kt` |
| `:browser` | WebView host in its own process. It registers with the core before any WebView use, and every call carries its session generation. §8.4 settings, Media Integrity API disabled, no JavaScript bridges. | `BrowserActivity.kt`, `CoreService.kt` |
| Disposal | Ends `:browser`, waits for the process to disappear, deletes the generation's engine directories and all shared preferences, then checks the data directory against an allowlist. | `AndroidBrowserDisposal.kt` |
| Isolated preview | Images and PDFs: one fresh `isolatedProcess` worker per preview, forked from the app zygote. Checks before input; sealed memfd in, controller-owned region out; deadlines with unbinding as the kill switch. Text: the first 64 KiB decoded in the core as plain text, with control and bidi characters escaped (§11.2). | `PreviewService.kt`, `Previewer.kt`, `rift-core::text` |
| Tests | 20 instrumented tests, two host-driven tests (S13, S14), and a process sampler that records worker lifetimes from outside the app. | `android/app/src/androidTest`, `android/run-tests.sh`, `android/fixtures` |

## Results

| ID | Test | Result on API 36 | Evidence |
|---|---|---|---|
| S1 | A page probes for native bridges | **Pass.** The only global is WebView's own `window.android.webview` (Media Integrity API). The test asserts its exact members and that it answers "API disabled by application". | `instrumented-results.txt` |
| S2 | Camera, microphone, geolocation, clipboard, `file:`/`content:` fetches, pop-ups | **Pass.** All denied; the manifest requests only `INTERNET`. | same |
| S3 | Worker opens a canary file | **Pass.** Read, list and write in the app's files fail. The directory is not even visible from the worker (ENOENT, app data isolation). External storage cannot be listed either. | `logcat-instrumented.txt` (`result s03`) |
| S4 | Worker opens a socket or connects | **Pass.** TCP and UDP `socket()` fail with EPERM, DNS is refused, there is no clipboard service, and binding the core's service throws SecurityException. `isolated_app` alone still allows `AF_UNIX` sockets and executable mappings; on a thread with the parser filter both fail with EPERM, and a check inside the product worker's render path confirms the filter is in force there. | `result s04` |
| S5 | Worker returns oversized or malformed output | **Pass.** A bitmap header larger than the box, a frame whose length prefix claims 4 GiB (rejected before allocation), and a valid reply to a different job are each rejected and the worker is stopped. | `result s05` |
| S6 | Worker crashes or hangs | **Pass.** A crash fails the job ("stopped unexpectedly"). A hang ends at the 12 s deadline (12.1 s measured): the worker is unbound and its process disappears (sampler: seen for 11.8 s). The UI thread answered within 2 ms throughout. The next preview works. | `result s06`, `workers.txt` |
| S7 | Confinement unavailable (simulated) | **Pass.** A non-isolated copy of the worker is refused before binding, and its process never starts. A worker reporting no seccomp is refused after Hello, before any input. There is no fallback. | `result s07` |
| S8 | Oversized download with no length | **Pass.** Stopped at the 100 MiB limit. | `result download: /files/big` |
| S9 | Redirect or name resolving to loopback | **Pass.** Refused by default. The per-host allowance does not extend to `127.0.0.1` reached by redirect. | same |
| S10 | Traversal and bidi override in a filename | **Pass.** Displayed as `evilgpj.pdf`; storage uses a random id. | same |
| S10b | Cookie-gated download | **Pass.** Re-fetched with its cookie; same bytes. | same |
| S11 | Bytes change after a scan | **Not applicable yet** (scanner is Phase 3). | — |
| S12 | Reset destroys session state | **Pass.** Cookies (script and server), localStorage, IndexedDB, Cache Storage, a service worker and the HTTP cache are present before and absent after; `:browser` is gone; the quarantine directory is deleted. Reset took 154 ms in this run (42–235 ms across runs). The vault half of S12 is Phase 4. | `result s12` |
| S13 | Kill during reset | **Pass.** The main process was killed while the marker said RESETTING. On restart, recovery deleted that generation before the next session started. | `s13.txt` |
| S14 | Renderer crash | **Pass.** SIGSEGV to this app's renderer: session torn down, a new one started, same main process. | `s14.txt` |
| S15 | Unsupported WebView configuration | **Pass.** Every simulated bad configuration is refused, and an unverified generation blocks everything. | `instrumented-results.txt` |
| S19 | Plaintext on disk after preview | **Pass for preview** (lock and kill come with the vault). After previewing the PNG, the PDF and the text file, a marker embedded in all three was found in no file of the app's data directory. | `result s19` |
| P1 | Image and PDF preview | **Pass.** PNG 300×200 with the expected gradient; PDF page 1582×2048 with the expected blue box on white; a broken PNG gives a typed error. Rendered previews took 77–395 ms end to end in this run, including the worker's start, except the first preview in a fresh session at 1089 ms (42–442 ms in earlier runs). | `result p1`, `logcat-instrumented.txt`, `screenshot-image-pdf-previews.png` |
| P2 | Text preview | **Pass.** CRLF becomes a line break; a terminal escape and a right-to-left override are shown as `\u{1b}` and `\u{202e}` instead of acting on the text. | `result p2`, `screenshot-text-preview.png` (the "ty ty ty" in the host field was typed by the scripted swipes that took the screenshot) |
| N1–N3 | Navigation policy in the UI | **Pass.** `intent:` links blocked with a sentence; a lookalike needs confirmation; HTTP is marked unencrypted. | `instrumented-results.txt` |
| N4 | Trusted bar before any page | **Pass.** A fresh browser window says "No page checked yet" (or "Browsing refused on this device" where the engine is unsupported), never a summary of a check that did not happen. | `result n4` |

### API 30 (WebView 91)

WebView 91 is below the supported minimum of 100, so `:browser` refuses to browse and shows why ([screenshot](evidence/phase2-android-api30/screenshot-unsupported.png)). That is the intended result, and it makes most of the suite fail, because those tests need a page or a captured download:

- **Pass:** S3, S15, S13. The S3 probe also ran on this image: files, storage, network, DNS, clipboard and the core's service are all denied, and the filtered thread denies `AF_UNIX` sockets and executable mappings with EPERM. One difference: TCP and UDP `socket()` fail with EACCES here, not EPERM.
- **Fail by design (17):** every test that opens a page or previews a downloaded file. Each one failed waiting for a page report or a finished download, not on a security assertion.
- **S14 not applicable:** a WebView renderer process existed, although no WebView had been created (finding 11). Killing it changed nothing in the app, because no page was attached to it, so the script's "new session" never came.
- **Inventory after the run:** `files/rift/session.marker` only.

Before the trusted-bar fix (finding 10), the refused window's bar read "Not flagged · threat database current".

Final inventory after all tests: `files/profileInstalled` and `files/rift/session.marker` only (`inventory.txt`).

APK libraries (all LOAD segments 0x4000-aligned): `librift_ffi.so` 3.15 MB (arm64) / 3.52 MB (x86_64); `librift_worker_ffi.so` 11.6 MB / 15.5 MB, mostly YARA-X, which Phase 3 uses; `libjnidispatch.so` 177 KB / 127 KB. Debug APK: about 70 MB, mostly unminified dex. Release APK (R8, resources shrunk): 36.6 MB, both ABIs. On the 16 KB page-size kernel every library loaded and the full suite passed, so the alignment is confirmed at runtime as well as statically.

## Findings that changed the design

1. **WebView exposes a page-reachable Media Integrity API by default (S1).** `window.android.webview` appeared to the bridge probe. It is WebView's own API, not an app bridge. Its token provider would call Play Integrity on behalf of any page, which is network traffic to Google that INV-11 does not allow by default. It is now disabled through `WebSettingsCompat`, and S1 asserts the refusal.
2. **`files/profileInstalled` appears after the first launch (S12).** It is written by `androidx.profileinstaller`, contains no browsing data, and is now on the allowlist. The default-deny inventory found it, as designed.
3. **The provider is loaded by `isMultiProcessEnabled()`.** `setDataDirectorySuffix` must therefore run before the sandbox check, not after it.
4. **Killing the main process while `:browser` is bound restarts main at once (S13).** Recovery runs in that restart, before any session is shown. S13 now waits for the recovery log rather than for a manual relaunch.
5. **Isolated service instance names are restricted.** `bindIsolatedService` rejects `preview-1` ("Illegal instanceName"); letters, digits and `_` work.
6. **Workers from the app zygote run with `NoNewPrivs: 1`** on this image (Phase 0 recorded 0 for system-zygote workers). This is an observation about one image, not a guarantee, so the controller does not rely on it.
7. **PdfRenderer loads PDFium on first use.** With the parser-thread filter installed first, `dlopen` of `libpdfclient`/`libft2` failed ("couldn't map segment: Operation not permitted") and the worker died. The worker now renders a built-in one-page PDF before installing the filter.
8. **Release builds write another profileinstaller file (release smoke test).** `files/profileinstaller_profileWrittenFor_lastUpdateTime.dat` made the first release reset fail closed ("unexpected file remains"); the session was not presented as fresh. It holds the APK update time the ART profile was written for, no browsing data, and is now allowlisted.
9. **The app freezer can freeze a backgrounded `:browser`.** A synchronous `shutdown()` to a frozen process fails (`DeadObjectException`, "Sync transaction while frozen") and the system kills it. Disposal already treats an unanswered shutdown as "kill and verify", so the result is the same; the log line says so.
10. **The trusted bar summarized checks that never ran (API 30).** On a refused engine, and before any page had loaded, the bar read "Not flagged · threat database current". It now says "Browsing refused on this device" or "No page checked yet" until the core has actually decided on a page. N4 asserts this.
11. **WebView 91 starts a renderer as soon as the provider loads.** On API 30 the sandbox check (`isMultiProcessEnabled()`) alone left a `sandboxed_process` renderer running for `:browser`, with no WebView. It ends with `:browser` at reset (S13 and the final inventory were clean), but it means "browsing refused" still runs some engine code.
12. **Loading WebView in the main process breaks disposal, as it should.** The first version of N4 asked WebView for its sandbox facts from the test, i.e. in the main process. That created an unsuffixed `app_webview/` directory outside any session. The next reset failed closed on it ("unexpected file remains: app_webview/…"), and the later tests failed with it. The test now uses the report from `:browser`. So the main process must never touch WebView, and the default-deny inventory catches it when it does.

## Verified (emulators only)

- The full suite on API 36 (20 instrumented tests, S13, S14) and on API 35 with 16 KB pages (19 tests, before N4 was added; S13, S14).
- On API 30 the refusal itself: browsing is refused with a reason, the worker probe (S3) and S15 pass, and S13 recovery works.
- Every test in the table above marked Pass, with the evidence named there.
- Host side: `cargo test --workspace` passes (rift-core 75 + 1 ignored network test, rift-ffi 7, rift-protocol 11, rift-worker 8, rift-worker-ffi 4; its fifth test, for the thread filter, runs on Linux and Android only and passed on the API 36 emulator as a native test binary). `clippy --all-targets` and `cargo fmt --check` are clean, and `cargo deny check` passes. The ignored test, `https_verifies_with_the_bundled_roots` (example.com accepted, wrong.host.badssl.com rejected), passed when run by hand.
- The release manifest contains only `CoreService` and `PreviewService` as services. The debug test workers are absent (checked in the merged release manifest).
- Every native library in the APK is 16 KB-aligned (checked statically by `build.sh`).

## Unverified

- **The rest of the device matrix.** API 33 and 34, x86_64, and physical phones with OEM WebView builds. Until these run, the Phase 2 gate is not met. API 30 is covered only as far as its old WebView allows (below).
- **Formats.** PNG, JPEG, WebP, PDF (first page) and UTF-8 text are previewed. UTF-16 text, and anything with a NUL byte in its first 8 KiB, counts as binary and shows "preview not supported".
- **The renderer sandbox at runtime** is inferred from the API level and `isMultiProcessEnabled()`, as in Phase 0. The app cannot inspect the renderer's `/proc`. S14 found the renderer with `adb root`, which a release build cannot do.
- **Hostile content against the worker's parsers.** S5 and S6 test misbehaving *workers* (simulated) and malformed fixtures, not real exploits. The `image` decoders and PDFium run with limits but have not been fuzzed in this setting.
- **Release build, beyond a smoke test.** The R8-shrunk release APK (signed locally with the SDK's debug key, outside the repository) was installed on API 36 and driven through the UI: session start, three captured downloads, image, PDF and text previews, and a reset that left only allowlisted files. The instrumented suite runs against the debug build only, because its test workers exist only there.
- **UI behaviour under real use** (rotation, low memory, background kills other than S13) beyond what the tests drive.
- **Downloads through the platform's TLS stack are not used.** Rift's fetches use the bundled roots; enterprise or user CAs are deliberately not trusted for them, which may break downloads behind TLS-inspecting proxies.

## Could be improved

- The parser-thread filter is a denylist. An allowlist like the Linux worker's would be stronger, but ART and PDFium make many syscalls on that thread, so it needs a measured syscall profile first.
- Previews hold the decrypted file in the controller's Java heap (≤ 32 MiB) before it goes into the memfd. Writing from Rust into the memfd directly would remove that copy.
- The preview UI shows one page. Paging through a PDF needs `PdfInfo` and one job per page.
- `librift_worker_ffi.so` carries YARA-X before the scanner uses it. Phase 3 should check that the 25 MB budget still holds with the intelligence code added.
- `run-tests.sh` samples processes every ~200 ms, so most workers (which live < 200 ms) are not seen at all. A worker that is seen does disappear when expected. An app-side "worker retired" event would give exact lifetimes.
- The instrumented tests share one fixture server and a single session lifecycle, so a failure in one test can disturb later ones (finding 12 caused six follow-on failures). Isolating them (a reset before each) would make failures easier to read.
- A lint check that no main-process code references `android.webkit`/`androidx.webkit` would catch finding 12 at build time, not at reset.
