# How well Check finds phishing, compared with URLCheck

**Date:** 24 October 2026. **Architecture:** 2.9 (§10.12). **Tool:** `tools/rift-train/src/bin/compare.rs`, which runs Check's own code (the policy, the address checks, Rift AI and the threat lists) on files of links, with the same configuration as the Android app.

URLCheck, the app this is measured against, checks a link's host against StevenBlack's hosts file and can send it to VirusTotal. Rift sends nothing anywhere (INV-11), so only its on-device check is compared here: URLCheck's hosts check is StevenBlack's file matched on the exact host, which is what the "URLCheck" column measures.

## Data

- **Phishing:** the 300 links in OpenPhish's public feed, fetched 24 October 2026 at 12:49 (+03:00). These are phishing pages reported in the last hours.
- **Ordinary pages:** 20,000 links picked at random from Common Crawl CC-MAIN-2026-39 (pages that answered 200 with HTML). A few may be malicious; they are counted as false alarms anyway.
- **Threat lists,** downloaded the same day: HaGeZi Threat Intelligence Feeds medium (623,471 hosts), Phishing Army (154,763), uBlock Origin badware (3,454) and StevenBlack hosts (71,493).
- **Threat database:** the Phishing.Database pack built that morning (2.7), signed with the demo keys.

## Result

"Red" is what the app shows as *Known malicious*, *Listed as dangerous* or *Looks dangerous* (Rift AI High). "Any warning" adds *Warning signs*: the address checks, Rift AI Elevated, and the two warning lists.

| Set | Links | URLCheck (StevenBlack hosts) | Rift 2.8: red | Rift 2.8: any warning | Rift 2.9: red | Rift 2.9: any warning | Each list |
|---|---|---|---|---|---|---|---|
| phishing | 300 | 0.0% (0) | 20.0% (60) | 70.0% (210) | 97.7% (293) | 98.3% (295) | Phishing Army 97.0% (291); HaGeZi 9.0% (27) |
| ordinary | 20,000 | 0.0% (0) | 0.1% (10) | 0.5% (99) | 0.1% (23) | 0.6% (112) | HaGeZi 0.1% (13) |

## What it means, and what it does not

- **URLCheck's hosts check found none of the 300.** StevenBlack's file is an ad, tracker and malware list, and new phishing sites are not on it.
- **The database found none either.** Phishing.Database is days behind OpenPhish, and its pack is a snapshot from that morning.
- **Phishing Army's 97% is circular.** Phishing Army builds its list from OpenPhish among other feeds, so it already held these links. The figure shows that the lists reach Check and match as they should, not how well Check does on phishing nobody has reported yet. The time-separated test below is the honest figure for that: 33.7% red and 63.7% any warning.
- **Rift AI's false alarms here are flattering.** These ordinary pages come from the same Common Crawl collection Rift AI was trained on, and about 80% of their sites were in its training split. Its figures on sites it never saw are in [rift-ai.md](rift-ai.md): 0.08% of ordinary pages at High, 0.89% at Elevated. The lists' false alarms are not affected, since nothing was trained on them.
- **The 13 ordinary pages HaGeZi lists** were looked at by their addresses only. Several look like scam sites (casino spam on an unrelated domain, an odd Pokémon shop), so some of that 0.1% is probably right; the pages themselves were not opened.
- **The lists do not flag the 10,000 most visited sites** (§10.12). Without that rule, every Google Forms link would be "Listed as dangerous", because both danger lists name `docs.google.com`.

## Time-separated test

OpenPhish's public feed was fetched every 30 minutes after 12:49. It stayed the same until 15:25, when it brought **190 links whose hosts were not in the 12:49 fetch**. Check ran on them with the lists as downloaded at 12:55, about two and a half hours earlier, so no list could have taken these hosts from that OpenPhish update. The ordinary pages and the lists are the same as above.

| Set | Links | URLCheck (StevenBlack hosts) | Rift 2.8: red | Rift 2.8: any warning | Rift 2.9: red | Rift 2.9: any warning | Each list |
|---|---|---|---|---|---|---|---|
| new phishing | 190 | 0.0% (0) | 17.9% (34) | 58.4% (111) | 33.7% (64) | 63.7% (121) | Phishing Army 16.3% (31); HaGeZi 7.9% (15) |

- **This is the honest figure.** On phishing reported after the lists were taken, Check shows a third of the links red and warns about nearly two thirds. URLCheck's hosts check flags none.
- **The lists add about 16 points of red** (from 17.9% to 33.7%). They had some of these hosts from other sources (PhishTank, CERT.PL) before OpenPhish named them. Most of the catch on new phishing is still Rift AI and the address checks, and a third of these links get no warning at all.
- **Two and a half hours is a short gap.** In the app the lists update once a day, so on average they are older than this; the figure may be optimistic for that reason. It is also one afternoon's feed, 190 links.

## How to run it

```sh
cargo build --release -p rift-train --bin compare
target/release/compare models/url-model.bin <pack-dir> phishing.txt ordinary.txt \
  tif=tif.medium-onlydomains.txt:wildcard phishing-army=phishing-army-domains.txt \
  badware=badware.min.txt:wildcard stevenblack=hosts
```

The lists come from the addresses in `ThreatLists.kt`. The feeds, the lists and the samples are not committed (their licences, and they go stale in hours).
