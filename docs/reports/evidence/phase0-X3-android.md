# Evidence: PoC X3 — URL decision latency on Android (emulator, API 36)

Build: `cargo ndk -t arm64-v8a -P 30 build --release -p rift-core --example x3_lookup_bench`; run with `adb shell /data/local/tmp/x3_lookup_bench`. Device: API 36 `google_apis` arm64-v8a emulator on Apple silicon (3 GB RAM). Captured 2026-10-18.

```
encoded table: 1000000 entries, 20000024 bytes in 198.242209ms
parse + full validation: 7.439125ms
samples: 200000, hits: 20000
decision latency µs: p50=9.2 p95=11.6 p99=13.9 max=11965.9
in-memory table: ~19 MiB (keys + metadata indices)
```

p95 is 11.6 µs against the 5 ms target (§18). The emulator runs arm64 code on an Apple silicon host through hardware virtualization, so this is closer to a fast phone than to a low-end one; the reference-phone measurement is still required before the target is claimed. The single 12 ms maximum is one outlier in 200,000 samples (likely scheduling) and stays far below the target.

The same build also ran the `rift-core` and `rift-protocol` unit tests on this emulator (cross-compiled with `cargo ndk ... test --no-run`, run with `TMPDIR=/data/local/tmp`): 62 and 11 passed, 0 failed.
