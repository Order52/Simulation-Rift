//! A pack of real indicators from public feeds (docs/architecture.md §13.3):
//! Phishing.Database (MIT) and, for a pack kept for oneself, URLhaus
//! (through malware-filter's urlhaus-filter). abuse.ch's terms allow
//! URLhaus only for not-for-profit use and forbid derived works without
//! consent, so packs Rift publishes leave it out (`feeds.sh`). The pack's
//! metadata names only the feeds it was built from.
//!
//! Each feed line becomes one URL expression: the address's most specific
//! one (`host/path?query`), or `host/` for a bare host, which covers every
//! address on that host and its subdomains. A whole popular site is never
//! listed: a host-wide entry on one of the sites Rift AI leaves unscored
//! (the 10,000 most visited, by the Public Suffix List, §16) is dropped and
//! counted, as a feed's mistake there would block a site people rely on.
//! Entries on such a site's specific addresses are kept, and so are sites
//! on hosting platforms (`someone.pages.dev` is a site of its own).
//!
//! The model goes into the pack too: while the pack is current, the app
//! uses it in place of the one it ships (§16).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rift_core::intel::{FileTable, UrlTable};
use rift_core::pack::{self, Pack, PackError};
use rift_core::urlcanon::{self, ExpressionHash};
use rift_core::urlmodel::UrlModel;

use crate::{Result, ToolError, io, tuf, write_pack};

/// One feed: where its lines come from and what a match says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feed {
    /// malware-filter's `urlhaus-filter-online.txt`: hosts, IPs and `||host/path^$all`.
    Urlhaus,
    /// Phishing.Database's `phishing-links-ACTIVE` files: one address per line.
    PhishingDatabase,
}

impl Feed {
    /// Its source and indicator entries in the pack's metadata, and its notice.
    fn metadata(self) -> (serde_json::Value, serde_json::Value, &'static str) {
        match self {
            Feed::Urlhaus => (
                serde_json::json!({"id": "urlhaus", "name": "URLhaus by abuse.ch, through malware-filter's urlhaus-filter",
                    "license": "abuse.ch terms of use (not-for-profit use)"}),
                serde_json::json!({"id": "urlhaus", "source": "urlhaus", "confidence": "high",
                    "description": "Listed by URLhaus as spreading malware."}),
                "URLhaus data by abuse.ch, under abuse.ch's terms of use (https://abuse.ch/terms-of-use/), through malware-filter's urlhaus-filter. Not endorsed by abuse.ch; not for redistribution.",
            ),
            Feed::PhishingDatabase => (
                serde_json::json!({"id": "phishing-database", "name": "Phishing.Database", "license": "MIT"}),
                serde_json::json!({"id": "phishing-database", "source": "phishing-database", "confidence": "high",
                    "description": "Listed by Phishing.Database as an active phishing page."}),
                "Phishing.Database: Copyright (c) 2018-2025 Mitchell Krog, Nissar Chababy and Phishing.Database Contributors. MIT License.",
            ),
        }
    }
}

/// What [`write_feeds_pack`] did with the lines it read.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FeedCounts {
    /// Entries written, per feed in the order given.
    pub listed: Vec<usize>,
    /// Lines that are not an address Rift can canonicalise.
    pub unreadable: usize,
    /// Host-wide entries on popular sites, dropped.
    pub popular: usize,
    /// Entries another feed (or the same one) already listed.
    pub repeated: usize,
}

/// The address on a feed line, or None for comments and blank lines.
fn address(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return None;
    }
    // Adblock syntax: `||host/path^$all` means that address on any scheme.
    let line = line.strip_prefix("||").unwrap_or(line);
    let line = line.split_once('^').map_or(line, |(address, _)| address);
    Some(if line.contains("://") {
        line.to_owned()
    } else {
        format!("http://{line}")
    })
}

/// The expression a feed line lists, None if it is unreadable, and
/// Err(()) if it is a host-wide entry on a popular site.
fn expression(line: &str, popular: &UrlModel) -> Option<std::result::Result<String, ()>> {
    let address = address(line)?;
    // No feed address has whitespace in it.
    if address.contains(char::is_whitespace) {
        return None;
    }
    let canonical = urlcanon::canonicalize(address.as_bytes()).ok()?;
    let most_specific = canonical.expressions().into_iter().next()?;
    let host_wide = most_specific == format!("{}/", canonical.host());
    if host_wide && popular.abstains(&canonical) {
        return Some(Err(()));
    }
    Some(Ok(most_specific))
}

/// Builds a pack from `feeds` (each a feed and its text) and Rift AI's
/// model file `model`, and writes it into `dir`. The sites the model leaves
/// unscored are never listed whole. Refuses a pack with no entries.
pub fn write_feeds_pack(
    dir: &Path,
    feeds: &[(Feed, String)],
    model: &[u8],
    created: jiff::Timestamp,
) -> Result<(Pack, FeedCounts)> {
    let popular = &UrlModel::parse(model).map_err(PackError::Model)?;
    let mut counts = FeedCounts::default();
    let mut entries: BTreeMap<ExpressionHash, u32> = BTreeMap::new();
    // Each feed's metadata index is its place among the feeds given.
    let mut kinds: Vec<Feed> = Vec::new();
    for (feed, text) in feeds {
        let index = match kinds.iter().position(|k| k == feed) {
            Some(i) => i,
            None => {
                kinds.push(*feed);
                kinds.len().saturating_sub(1)
            }
        };
        let index = u32::try_from(index).map_err(tuf)?;
        let mut listed = 0usize;
        for line in text.lines() {
            if address(line).is_none() {
                continue;
            }
            match expression(line, popular) {
                None => counts.unreadable = counts.unreadable.saturating_add(1),
                Some(Err(())) => counts.popular = counts.popular.saturating_add(1),
                Some(Ok(e)) => {
                    if entries
                        .insert(urlcanon::expression_hash(&e), index)
                        .is_some()
                    {
                        counts.repeated = counts.repeated.saturating_add(1);
                    } else {
                        listed = listed.saturating_add(1);
                    }
                }
            }
        }
        counts.listed.push(listed);
    }
    if entries.is_empty() {
        return Err(ToolError::Refused("the feeds hold no address".into()));
    }
    let created_unix = u64::try_from(created.as_second()).map_err(tuf)?;
    let metadata = serde_json::json!({
        "format": 1,
        "snapshot": format!("feeds-{}", created.strftime("%Y%m%dT%H%M%SZ")),
        "created_unix": created_unix,
        "refresh_after_unix": created_unix.saturating_add(7 * 24 * 3600),
        "demo": false,
        "sources": kinds.iter().map(|k| k.metadata().0).collect::<Vec<_>>(),
        "indicators": kinds.iter().map(|k| k.metadata().1).collect::<Vec<_>>(),
        "rules": [],
        "notices": kinds.iter().map(|k| k.metadata().2).collect::<Vec<_>>()
    });
    let table = |name: &'static str, error| ToolError::Pack(PackError::Table { name, error });
    let files = [
        (
            pack::METADATA,
            serde_json::to_vec_pretty(&metadata).map_err(tuf)?,
        ),
        (
            pack::URL_TABLE,
            UrlTable::encode(entries.into_iter().collect())
                .map_err(|e| table(pack::URL_TABLE, e))?,
        ),
        (
            pack::FILE_TABLE,
            FileTable::encode(Vec::new()).map_err(|e| table(pack::FILE_TABLE, e))?,
        ),
        (pack::RULES, Vec::new()),
        (pack::MODEL, model.to_vec()),
    ];
    Ok((write_pack(dir, &files)?, counts))
}

/// Reads a feed file.
pub fn read_feed(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(io(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The model the apps ship: google.com is among its popular sites.
    fn model() -> Vec<u8> {
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/url-model.bin")).unwrap()
    }

    fn popular() -> UrlModel {
        UrlModel::parse(&model()).unwrap()
    }

    fn build(feeds: &[(Feed, &str)]) -> (Pack, FeedCounts) {
        let dir = tempfile::tempdir().unwrap();
        let feeds: Vec<(Feed, String)> = feeds.iter().map(|(f, t)| (*f, (*t).to_owned())).collect();
        write_feeds_pack(dir.path(), &feeds, &model(), jiff::Timestamp::UNIX_EPOCH).unwrap()
    }

    #[test]
    fn feed_lines_become_expressions() {
        let p = popular();
        let e = |l| expression(l, &p);
        assert_eq!(e("! Title: list"), None);
        assert_eq!(e("1.2.3.4"), Some(Ok("1.2.3.4/".into())));
        assert_eq!(e("bad.example"), Some(Ok("bad.example/".into())));
        assert_eq!(
            e("||bad.example/x/y.exe^$all"),
            Some(Ok("bad.example/x/y.exe".into()))
        );
        assert_eq!(
            e("https://Bad.Example/login?a=1"),
            Some(Ok("bad.example/login?a=1".into()))
        );
        assert_eq!(
            e("||drive.google.com/uc?export=download&id=1abc^$all"),
            Some(Ok("drive.google.com/uc?export=download&id=1abc".into()))
        );
        // A whole popular site is never listed; a site on a hosting platform is.
        assert_eq!(e("https://drive.google.com/"), Some(Err(())));
        assert_eq!(e("google.com"), Some(Err(())));
        assert_eq!(
            e("evil-login.pages.dev"),
            Some(Ok("evil-login.pages.dev/".into()))
        );
    }

    #[test]
    fn the_pack_is_real_and_counts_what_it_dropped() {
        let (pack, counts) = build(&[
            (
                Feed::Urlhaus,
                "! comment\n1.2.3.4\n||bad.example/x.exe^$all\ndocs.google.com\n",
            ),
            (
                Feed::PhishingDatabase,
                "https://phish.example/login\nhttp://1.2.3.4/\nnot a url at all\n",
            ),
        ]);
        assert!(!pack.metadata.demo);
        assert_eq!(pack.model.unwrap().digest_hex(), popular().digest_hex());
        assert_eq!(counts.listed, vec![2, 1]);
        assert_eq!(counts.popular, 1);
        assert_eq!(counts.repeated, 1);
        assert_eq!(counts.unreadable, 1);
    }

    #[test]
    fn the_metadata_names_only_the_feeds_given() {
        let (pack, _) = build(&[(Feed::PhishingDatabase, "https://phish.example/login\n")]);
        let ids: Vec<_> = pack
            .metadata
            .sources
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        assert_eq!(ids, ["phishing-database"]);
        assert_eq!(pack.metadata.notices.len(), 1);
    }

    #[test]
    fn listed_addresses_are_found_and_others_are_not() {
        let (pack, _) = build(&[
            (Feed::Urlhaus, "bad.example\n"),
            (Feed::PhishingDatabase, "https://phish.example/login\n"),
        ]);
        let found = |url: &str| {
            let canonical = urlcanon::canonicalize(url.as_bytes()).unwrap();
            pack.urls
                .matches(&canonical)
                .into_iter()
                .map(|(_, meta)| pack.indicator(meta).unwrap().id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(found("https://cdn.bad.example/any/path"), vec!["urlhaus"]);
        assert_eq!(
            found("https://phish.example/login?session=9"),
            vec!["phishing-database"]
        );
        assert!(found("https://phish.example/").is_empty());
        assert!(found("https://example.com/").is_empty());
    }
}
