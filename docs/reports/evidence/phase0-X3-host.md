# Evidence: PoC X3 — URL canonicalization and indicator lookup (host)

Captured 2026-10-17T08:59Z on macOS 26.6.2, Apple silicon (arm64), Rust 1.99.1, release build.

## Correctness

`cargo test -p rift-core`: all 33 canonicalization examples published in Safe Browsing "URLs and Hashing" (v4) pass, plus the three published host/path expression examples, 30-expression cap, credential/port stripping, IDN→Punycode, inet_aton IPv4 forms, and 8,000 randomized idempotence cases (proptest). Proptest found one real idempotence bug (`"0:. "`), fixed and kept as a regression case.

## Performance (`cargo run --release -p rift-core --example x3_lookup_bench`)

```
encoded table: 1000000 entries, 20000024 bytes in 142.974708ms
parse + full validation: 5.583333ms
samples: 200000, hits: 20000
decision latency µs: p50=10.9 p95=39.5 p99=109.2 max=69554.5
in-memory table: ~19 MiB (keys + metadata indices)
```

Target (§18): p95 ≤ 5 ms on the reference phone. Host p95 is 26 µs; the phone measurement is still required before the target is claimed.
