# Fuzz campaign 4 (30 minutes each, the two newest targets)

Run locally on macOS arm64 (nightly-2026-10-17, `cargo fuzz run <target> -- -max_total_time=1800`)
on 4a5ac56, where the fuzzed code and both targets are as 32ff1dd added them, starting from an
empty corpus; the two ran at the same time. No coverage report was made.

**Neither target crashed, leaked or failed its property.**

| target | what it checks | runs in 1800 s | runs/s | coverage (libFuzzer `cov`) | corpus |
|---|---|---:|---:|---:|---:|
| vault_index_payload | the vault index decoder behind its MAC: no duplicate ids accepted, and `decode(encode(index)) == index` | 43,332,867 | 24,060 | 982 | 653 units |
| session_from_browser | the controller's decoder for the Linux browser host's messages: every bound holds, and accepted messages re-encode to the same bytes | 1,083,411,400 | 601,561 | 575 | 306 units |

What this does not show: a run on CI's x86_64 runners, a run longer than 30 minutes, or line
coverage. `session_from_browser`'s corpus stopped growing early (its messages are small and
postcard is simple); `vault_index_payload`'s was still growing.
