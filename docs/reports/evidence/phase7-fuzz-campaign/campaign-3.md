# Fuzz campaign 3 (60 minutes per target, with coverage)

`fuzz-campaign` run 39511324301 on aaa41eb (which has 9354fad's fix for finding 65 and 2162932's
coverage path), all ten targets, GitHub ubuntu-latest, nightly-2026-10-17. Each target ran alone
on one runner, starting from an empty corpus (`-max_total_time=3600 -rss_limit_mb=2048`), then
`cargo fuzz cmin` and `cargo fuzz coverage` over the minimized corpus. Artifacts per target:
`run.log`, `coverage.txt` (`llvm-cov report`, Rift's own sources only) and `corpus.tar.gz`.

**No target crashed, leaked past the RSS limit, or failed its property.**

| target | runs in 3600 s | runs/s | corpus units added | peak RSS (MB) | lines covered in the code under test |
|---|---:|---:|---:|---:|---|
| url_canonicalize | 5,710,050 | 1,585 | 12,517 | 742 | `urlcanon.rs` 288 of 306 (94.1 %) |
| navigation | 4,529,777 | 1,257 | 14,692 | 727 | `urlcanon.rs` 297/306 (97.1 %), `heuristics.rs` 120/155 (77.4 %), `intel.rs` 72/100, `policy.rs` 53/102 |
| trusted_text | 5,135,549 | 1,426 | 17,435 | 680 | `text.rs` 43/43 (100 %), `heuristics.rs` 135/155 (87.1 %), `urlcanon.rs` 243/306 |
| egress_head | 20,258,143 | 5,625 | 33,324 | 581 | `egress.rs` 98 of 482 (20.3 %) |
| display_name | 178,281,100 | 49,508 | 4,330 | 521 | `transfer.rs` 26/128, `text.rs` 6/43 |
| protocol_response | 1,163,612,307 | 323,135 | 2,757 | 622 | `rift-protocol/src/lib.rs` 102/140 (72.9 %) |
| worker_scan | 1,315,377 | 365 | 1,504 | 360 | `rift-worker/src/lib.rs` 64/121, `rift-protocol/src/lib.rs` 70/140 |
| worker_image | 37,850,691 | 10,511 | 10,224 | 748 | `rift-worker/src/lib.rs` 62/121, `rift-protocol/src/lib.rs` 55/140 |
| intel_table | 2,053,651,330 | 570,300 | 46 | 632 | `intel.rs` 60/100 |
| vault_index | 8,862,604 | 2,461 | 16 | 555 | `vault.rs` 22/219 |

Coverage is per file, so a file's figure includes functions the target never calls: `egress.rs`
holds the whole proxy, while `egress_head` drives only its request-head parser; `display_name`
reaches only the naming functions of `transfer.rs`; `policy.rs` includes the download policy.
The figures are of the corpus each target built in its hour, not of the unit tests.

## What the two slow-growing targets do and do not reach

Campaigns 1 and 2 left open why `vault_index` and `intel_table` added so few units (31 and 45).

- **intel_table** (46 units in 2.05 billion runs) covers 60 of `intel.rs`'s 100 lines, which also
  hold the snapshot store and the pack's freshness checks that this target does not call. Its
  input is a whole indicator table: one header and fixed 20-byte records, all parsed by
  `UrlTable::parse` and checked by lookup of every record. The code is small and straight-line,
  so few distinct paths exist; the low unit count is saturation, not early rejection.
- **vault_index** (16 units) covers 22 of `vault.rs`'s 219 lines: `read_index` up to the point where
  age refuses to decrypt. This is the property the target states — bytes written by someone
  without the vault identity are never accepted — and it held for 8.9 million inputs. But it
  means **the index decoder behind the MAC is not fuzzed**: no input got past authentication,
  and none can without the key. A target that seals fuzzer bytes with the vault key before
  reading them would exercise that decoder (to do). The age crate's own parser is exercised
  here, but its coverage is not in the report, which lists Rift's sources only.

## Read with care

An hour per target on one runner is a first campaign, not a release-grade one: the corpora are
still growing for `navigation`, `trusted_text`, `egress_head` and `url_canonicalize` (thousands of
units added late in the hour). The parts with low coverage (`policy.rs`, `egress.rs`'s parser,
the worker's request handling) need either longer runs or narrower targets.
