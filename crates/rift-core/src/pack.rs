//! Intelligence packs (docs/architecture.md §13.1): validation of the files a
//! snapshot is made of, before any of them is used.
//!
//! A pack is exactly these files, under these names and no others:
//!
//! | name | content | limit |
//! |---|---|---|
//! | `metadata.json` | [`PackMetadata`], strict schema | 1 MiB |
//! | `url-hashes.bin` | [`UrlTable`] | 64 MiB |
//! | `file-hashes.bin` | [`FileTable`] | 64 MiB |
//! | `rules.yar` | YARA source, UTF-8, compiled only inside a worker | 8 MiB |
//!
//! Every table record points into `metadata.indicators`, and every rule the
//! worker reports is looked up in `metadata.rules`. Nothing in a pack is
//! executed by the core, and no path is derived from anything inside it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::intel::{FileTable, TableError, UrlTable};

pub const METADATA: &str = "metadata.json";
pub const URL_TABLE: &str = "url-hashes.bin";
pub const FILE_TABLE: &str = "file-hashes.bin";
pub const RULES: &str = "rules.yar";
/// The complete, fixed set of pack files (also the TUF staging allowlist).
pub const FILES: [&str; 4] = [METADATA, URL_TABLE, FILE_TABLE, RULES];

pub const MAX_METADATA_BYTES: usize = 1024 * 1024;
pub const MAX_TABLE_BYTES: usize = 64 * 1024 * 1024;
/// The worker's own limit (rift-worker `MAX_RULES_SOURCE_BYTES`).
pub const MAX_RULES_BYTES: usize = 8 * 1024 * 1024;
const MAX_TEXT: usize = 512;
const MAX_ENTRIES: usize = 1 << 20;
const FORMAT: u32 = 1;

/// Size limit for each pack file, by name; `None` for names not in a pack.
pub fn size_limit(name: &str) -> Option<usize> {
    match name {
        METADATA => Some(MAX_METADATA_BYTES),
        URL_TABLE | FILE_TABLE => Some(MAX_TABLE_BYTES),
        RULES => Some(MAX_RULES_BYTES),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackError {
    #[error("pack file {0} is missing")]
    Missing(&'static str),
    #[error("{0:?} is not a pack file")]
    UnknownFile(String),
    #[error("pack file {name} is {size} bytes, over its limit of {limit}")]
    TooLarge {
        name: &'static str,
        size: usize,
        limit: usize,
    },
    #[error("metadata does not match the schema: {0}")]
    Schema(String),
    #[error("metadata: {0}")]
    Metadata(String),
    #[error("{name}: {error}")]
    Table {
        name: &'static str,
        error: TableError,
    },
    #[error("rules are not UTF-8")]
    RulesEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Enough to call an object "known malicious" (§12.3).
    High,
    /// Enough to call it "suspicious", not more.
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub name: String,
    pub license: String,
}

/// What a table record or a rule means, shown with every finding.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    pub id: String,
    pub source: String,
    pub confidence: Confidence,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMetadata {
    pub format: u32,
    /// Human-readable snapshot name, e.g. `demo-2026-10-18.1`.
    pub snapshot: String,
    pub created_unix: u64,
    /// After this time the snapshot is still used, but shown as stale.
    pub refresh_after_unix: u64,
    /// A demo pack is never presented as real coverage (§13.3).
    pub demo: bool,
    pub sources: Vec<Source>,
    /// Referenced by index from both tables.
    pub indicators: Vec<Indicator>,
    /// One entry per rule in `rules.yar`; `id` is the YARA identifier.
    pub rules: Vec<Indicator>,
    #[serde(default)]
    pub notices: Vec<String>,
}

/// SHA-256 over every pack file (name, length, content digest), in a fixed
/// order. Two packs with the same snapshot name but different bytes differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackDigest(pub [u8; 32]);

impl PackDigest {
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// A fully validated pack.
#[derive(Debug, Clone)]
pub struct Pack {
    pub metadata: PackMetadata,
    pub urls: UrlTable,
    pub files: FileTable,
    /// The YARA source, for a worker to compile.
    pub rules_source: Vec<u8>,
    /// SHA-256 of `rules_source`, which scan requests reference.
    pub rules_digest: [u8; 32],
    pub digest: PackDigest,
    rule_index: BTreeMap<String, usize>,
}

impl Pack {
    /// Validates a pack from its files, given as (name, bytes). Every file
    /// must be present exactly once, within its limit; unknown names fail.
    pub fn validate<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> Result<Self, PackError> {
        let mut found: BTreeMap<&'static str, &'a [u8]> = BTreeMap::new();
        for (name, bytes) in files {
            let known = FILES
                .iter()
                .find(|known| **known == name)
                .ok_or_else(|| PackError::UnknownFile(name.to_owned()))?;
            let limit = size_limit(known).ok_or_else(|| PackError::UnknownFile(name.to_owned()))?;
            if bytes.len() > limit {
                return Err(PackError::TooLarge {
                    name: known,
                    size: bytes.len(),
                    limit,
                });
            }
            if found.insert(known, bytes).is_some() {
                return Err(PackError::Metadata(format!("{known} given twice")));
            }
        }
        let get = |name: &'static str| found.get(name).copied().ok_or(PackError::Missing(name));

        let metadata: PackMetadata =
            serde_json::from_slice(get(METADATA)?).map_err(|e| PackError::Schema(e.to_string()))?;
        let rule_index = check_metadata(&metadata)?;
        let meta_count = u32::try_from(metadata.indicators.len())
            .map_err(|_| PackError::Metadata("too many indicators".into()))?;
        let urls =
            UrlTable::parse(get(URL_TABLE)?, meta_count).map_err(|error| PackError::Table {
                name: URL_TABLE,
                error,
            })?;
        let files_table =
            FileTable::parse(get(FILE_TABLE)?, meta_count).map_err(|error| PackError::Table {
                name: FILE_TABLE,
                error,
            })?;
        let rules_source = get(RULES)?;
        std::str::from_utf8(rules_source).map_err(|_| PackError::RulesEncoding)?;

        let mut digest = Sha256::new();
        for name in FILES {
            let bytes = get(name)?;
            digest.update(name.as_bytes());
            digest.update([0]);
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(Sha256::digest(bytes));
        }
        Ok(Self {
            metadata,
            urls,
            files: files_table,
            rules_source: rules_source.to_vec(),
            rules_digest: Sha256::digest(rules_source).into(),
            digest: PackDigest(digest.finalize().into()),
            rule_index,
        })
    }

    /// What a table record's metadata index refers to.
    pub fn indicator(&self, meta: u32) -> Option<&Indicator> {
        self.metadata.indicators.get(usize::try_from(meta).ok()?)
    }

    /// The pack's entry for a rule the worker reported.
    pub fn rule(&self, identifier: &str) -> Option<&Indicator> {
        self.metadata.rules.get(*self.rule_index.get(identifier)?)
    }

    /// Whether the pack should be refreshed (it is still used either way).
    pub fn is_stale(&self, now_unix: u64) -> bool {
        now_unix >= self.metadata.refresh_after_unix
    }
}

fn check_metadata(m: &PackMetadata) -> Result<BTreeMap<String, usize>, PackError> {
    if m.format != FORMAT {
        return bad(format!("format {} (expected {FORMAT})", m.format));
    }
    if !is_name(&m.snapshot) {
        return bad("snapshot name must be 1–64 of A–Z a–z 0–9 . _ -".into());
    }
    if m.refresh_after_unix <= m.created_unix {
        return bad("refresh_after_unix must be after created_unix".into());
    }
    if m.indicators.len() > MAX_ENTRIES || m.rules.len() > MAX_ENTRIES || m.sources.len() > 256 {
        return bad("too many entries".into());
    }
    let mut sources = BTreeSet::new();
    for s in &m.sources {
        text(&s.name, "source name")?;
        text(&s.license, "source license")?;
        if !is_name(&s.id) || !sources.insert(s.id.as_str()) {
            return bad(format!("source id {:?} is invalid or repeated", s.id));
        }
    }
    let check = |entry: &Indicator, ids: &mut BTreeSet<String>, what: &str| {
        text(&entry.description, "description")?;
        if !sources.contains(entry.source.as_str()) {
            return bad(format!(
                "{what} {:?} names unknown source {:?}",
                entry.id, entry.source
            ));
        }
        if !ids.insert(entry.id.clone()) {
            return bad(format!("{what} id {:?} repeated", entry.id));
        }
        Ok(())
    };
    let mut ids = BTreeSet::new();
    for entry in &m.indicators {
        if !is_name(&entry.id) {
            return bad(format!("indicator id {:?} is invalid", entry.id));
        }
        check(entry, &mut ids, "indicator")?;
    }
    let mut rule_ids = BTreeSet::new();
    let mut index = BTreeMap::new();
    for (i, entry) in m.rules.iter().enumerate() {
        if !is_yara_identifier(&entry.id) {
            return bad(format!("rule id {:?} is not a YARA identifier", entry.id));
        }
        check(entry, &mut rule_ids, "rule")?;
        index.insert(entry.id.clone(), i);
    }
    for notice in &m.notices {
        text(notice, "notice")?;
    }
    Ok(index)
}

fn bad<T>(what: String) -> Result<T, PackError> {
    Err(PackError::Metadata(what))
}

fn text(value: &str, what: &str) -> Result<(), PackError> {
    if value.is_empty() || value.len() > MAX_TEXT || value.chars().any(char::is_control) {
        return Err(PackError::Metadata(format!(
            "{what} must be 1–{MAX_TEXT} bytes without control characters"
        )));
    }
    Ok(())
}

fn is_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_yara_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    (1..=128).contains(&value.len())
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const RULES_SRC: &str =
        "rule rift_demo_marker { strings: $a = \"RIFT-DEMO-MARKER\" condition: $a }\n";

    pub(crate) fn metadata(rules: &str) -> String {
        format!(
            r#"{{"format":1,"snapshot":"demo-1","created_unix":100,"refresh_after_unix":200,"demo":true,
            "sources":[{{"id":"rift-demo","name":"Rift demo","license":"CC0-1.0"}}],
            "indicators":[{{"id":"demo-file","source":"rift-demo","confidence":"high","description":"Demo file indicator"}},
                          {{"id":"demo-url","source":"rift-demo","confidence":"low","description":"Demo URL indicator"}}],
            "rules":[{rules}]}}"#
        )
    }

    pub(crate) fn demo_rule() -> &'static str {
        r#"{"id":"rift_demo_marker","source":"rift-demo","confidence":"high","description":"Demo marker string"}"#
    }

    pub(crate) fn pack_files(
        metadata: &str,
        files: &[([u8; 32], u32)],
    ) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            (METADATA, metadata.as_bytes().to_vec()),
            (URL_TABLE, UrlTable::encode(vec![([7; 16], 1)]).unwrap()),
            (FILE_TABLE, FileTable::encode(files.to_vec()).unwrap()),
            (RULES, RULES_SRC.as_bytes().to_vec()),
        ]
    }

    pub(crate) fn validate(files: &[(&'static str, Vec<u8>)]) -> Result<Pack, PackError> {
        Pack::validate(files.iter().map(|(n, b)| (*n, b.as_slice())))
    }

    #[test]
    fn a_valid_pack_is_accepted_and_indexed() {
        let pack = validate(&pack_files(&metadata(demo_rule()), &[([1; 32], 0)])).unwrap();
        assert_eq!(pack.files.lookup(&[1; 32]), Some(0));
        assert_eq!(pack.indicator(0).unwrap().id, "demo-file");
        assert_eq!(
            pack.rule("rift_demo_marker").unwrap().confidence,
            Confidence::High
        );
        assert!(pack.rule("other").is_none());
        assert!(!pack.is_stale(199) && pack.is_stale(200));
        assert_eq!(
            pack.rules_digest,
            <[u8; 32]>::from(Sha256::digest(RULES_SRC))
        );
    }

    #[test]
    fn the_digest_covers_every_file() {
        let base = pack_files(&metadata(demo_rule()), &[([1; 32], 0)]);
        let digest = validate(&base).unwrap().digest;
        for i in 0..base.len() {
            let mut changed = base.clone();
            changed[i].1.push(b'\n');
            // A table with a trailing byte is invalid instead, which is also fine.
            if let Ok(pack) = validate(&changed) {
                assert_ne!(pack.digest, digest, "{}", changed[i].0);
            }
        }
    }

    #[test]
    fn file_set_is_fixed() {
        let base = pack_files(&metadata(demo_rule()), &[]);
        for i in 0..base.len() {
            let mut missing = base.clone();
            let (name, _) = missing.remove(i);
            assert_eq!(validate(&missing).unwrap_err(), PackError::Missing(name));
        }
        let mut extra = base.clone();
        extra.push(("../rules.yar", vec![]));
        assert!(matches!(validate(&extra), Err(PackError::UnknownFile(_))));
        let mut twice = base.clone();
        twice.push((RULES, vec![]));
        assert!(matches!(validate(&twice), Err(PackError::Metadata(_))));
        let mut big = base;
        big[3].1 = vec![b' '; MAX_RULES_BYTES + 1];
        assert!(matches!(
            validate(&big),
            Err(PackError::TooLarge { name: RULES, .. })
        ));
    }

    #[test]
    fn metadata_is_strict() {
        let cases = [
            metadata(demo_rule()).replace("\"format\":1", "\"format\":2"),
            metadata(demo_rule()).replace("demo-1", "../x"),
            metadata(demo_rule())
                .replace("\"refresh_after_unix\":200", "\"refresh_after_unix\":100"),
            metadata(demo_rule()).replace(
                "\"source\":\"rift-demo\",\"confidence\":\"low\"",
                "\"source\":\"nobody\",\"confidence\":\"low\"",
            ),
            metadata(demo_rule()).replace("demo-url", "demo-file"),
            metadata(demo_rule()).replace("Demo marker string", "bad\u{1b}[2J"),
            metadata(&demo_rule().replace("rift_demo_marker", "1rule")),
            metadata(&format!("{},{}", demo_rule(), demo_rule())),
            metadata(demo_rule()).replace("\"demo\":true", "\"demo\":true,\"extra\":1"),
            metadata(demo_rule()).replace("\"confidence\":\"high\"", "\"confidence\":\"certain\""),
        ];
        for case in cases {
            let error = validate(&pack_files(&case, &[])).unwrap_err();
            assert!(
                matches!(error, PackError::Metadata(_) | PackError::Schema(_)),
                "{case}: {error:?}"
            );
        }
    }

    #[test]
    fn table_records_must_point_into_the_metadata() {
        let error = validate(&pack_files(&metadata(demo_rule()), &[([1; 32], 2)])).unwrap_err();
        assert!(matches!(
            error,
            PackError::Table {
                name: FILE_TABLE,
                error: TableError::MetaOutOfRange { .. }
            }
        ));
        let mut bad_rules = pack_files(&metadata(demo_rule()), &[]);
        bad_rules[3].1 = vec![0xff, 0xfe];
        assert_eq!(validate(&bad_rules).unwrap_err(), PackError::RulesEncoding);
    }
}
