# Fuzz campaigns 1 and 2 (60 minutes per target, GitHub ubuntu-latest, nightly-2026-10-17)

Campaign 1: `fuzz-campaign` run 39500409152 on 23d4629, all ten targets.
Campaign 2: run 39501688643 on bbc887e, the two worker targets after their harness fix.
Each target ran alone on one runner with an empty starting corpus (`-max_total_time=3600 -rss_limit_mb=2048`).

In both runs the coverage step failed for every target after fuzzing had finished: it looked for the
coverage binary under `fuzz/target/`, while `cargo fuzz coverage` writes it under the repository's
`target/` (fixed in 2162932). So these runs give no coverage figures; campaign 3 (run 39511324301) repeats
all ten targets with coverage.

| target | runs in 3600 s | runs/s | corpus units added | corpus after cmin | peak RSS (MB) | result |
|---|---:|---:|---:|---:|---:|---|
| vault_index | 18,526,638 | 5,144 | 31 | 5 | 563 | no finding |
| display_name | 183,424,464 | 50,937 | 8,186 | 356 | 546 | no finding |
| navigation | 6,332,351 | 1,758 | 18,849 | 3,783 | 731 | no finding |
| egress_head | 22,016,690 | 6,114 | 32,031 | 3,271 | 534 | no finding |
| trusted_text | 6,035,910 | 1,676 | 17,747 | 4,022 | 691 | no finding |
| intel_table | 1,973,717,655 | 548,102 | 45 | 22 | 763 | no finding |
| protocol_response | 846,279,877 | 235,012 | 983 | 346 | 588 | no finding |
| url_canonicalize (campaign 1) | stopped after 21 min | | | | | **finding**: idempotence broken by `TooLong` on re-canonicalization; led to the proxy bypass, finding 65 |
| worker_scan (campaign 1) | stopped at input 2 | | | | | harness bug: the frame's length prefix was passed to `decode_response` (finding 66) |
| worker_image (campaign 1) | stopped at input 9 | | | | | the same harness bug |
| worker_scan (campaign 2) | 848,118 | 235 | 661 | 160 | 343 | no finding |
| worker_image (campaign 2) | 31,968,363 | 8,877 | 10,237 | 929 | 672 | no finding |

"Corpus after cmin" is the number of files `cargo fuzz cmin` kept (its MERGE-OUTER line).

**Read with care.** `vault_index` (31 units) and `intel_table` (45 units) found very little new
coverage in an hour. Either their inputs are rejected early (both start with a format check), or the
code is small. Campaign 3's coverage report is needed to tell which; until then, an hour without a
finding says little about them.
