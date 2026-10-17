//! Indicator tables from intelligence packs (docs/architecture.md §13.1).
//!
//! On-disk format (little-endian), validated in full before use:
//!
//! ```text
//! 0   magic        b"RIFTIDX1"
//! 8   version      u16 = 1
//! 10  key_len      u16 (16 for URL expression hashes, 32 for file SHA-256)
//! 12  reserved     u32 = 0
//! 16  count        u64
//! 24  records      count × (key: [u8; key_len], meta_index: u32), strictly ascending by key
//! ```
//!
//! The format is deliberately trivial: a signed pack can be checked in O(n)
//! with no parser state, and lookups are a binary search.

use crate::urlcanon::{CanonicalUrl, ExpressionHash};

pub const MAGIC: &[u8; 8] = b"RIFTIDX1";
pub const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 24;
const META_LEN: usize = 4;

/// URL indicators: truncated SHA-256 of a canonical lookup expression.
pub type UrlTable = IndicatorTable<16>;
/// File indicators: full SHA-256 of the file content.
pub type FileTable = IndicatorTable<32>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TableError {
    #[error("table shorter than its header")]
    TooShort,
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    #[error("key length {found}, expected {expected}")]
    KeyLength { expected: usize, found: usize },
    #[error("reserved header field is not zero")]
    ReservedNonZero,
    #[error("record count does not match table length")]
    LengthMismatch,
    #[error("records not strictly ascending at index {0}")]
    NotStrictlySorted(usize),
    #[error("record {index} references metadata {meta}, but only {available} entries exist")]
    MetaOutOfRange {
        index: usize,
        meta: u32,
        available: u32,
    },
}

/// A validated, immutable indicator table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndicatorTable<const K: usize> {
    keys: Vec<[u8; K]>,
    metas: Vec<u32>,
}

impl<const K: usize> IndicatorTable<K> {
    /// Validates `bytes` completely; `meta_count` is the number of metadata
    /// entries in the same pack, which every record must reference in range.
    pub fn parse(bytes: &[u8], meta_count: u32) -> Result<Self, TableError> {
        let (header, body) = bytes
            .split_at_checked(HEADER_LEN)
            .ok_or(TableError::TooShort)?;
        let field = |range: std::ops::Range<usize>| header.get(range).ok_or(TableError::TooShort);
        if field(0..8)? != MAGIC {
            return Err(TableError::BadMagic);
        }
        let version = u16::from_le_bytes(array(field(8..10)?)?);
        if version != FORMAT_VERSION {
            return Err(TableError::UnsupportedVersion(version));
        }
        let key_len = usize::from(u16::from_le_bytes(array(field(10..12)?)?));
        if key_len != K {
            return Err(TableError::KeyLength {
                expected: K,
                found: key_len,
            });
        }
        if u32::from_le_bytes(array(field(12..16)?)?) != 0 {
            return Err(TableError::ReservedNonZero);
        }
        let count = usize::try_from(u64::from_le_bytes(array(field(16..24)?)?))
            .map_err(|_| TableError::LengthMismatch)?;
        let record_len = K.checked_add(META_LEN).ok_or(TableError::LengthMismatch)?;
        if count.checked_mul(record_len) != Some(body.len()) {
            return Err(TableError::LengthMismatch);
        }

        let mut keys: Vec<[u8; K]> = Vec::with_capacity(count);
        let mut metas = Vec::with_capacity(count);
        for (index, record) in body.chunks_exact(record_len).enumerate() {
            let (key, meta) = record
                .split_at_checked(K)
                .ok_or(TableError::LengthMismatch)?;
            let key: [u8; K] = array(key)?;
            let meta = u32::from_le_bytes(array(meta)?);
            if keys.last().is_some_and(|previous| *previous >= key) {
                return Err(TableError::NotStrictlySorted(index));
            }
            if meta >= meta_count {
                return Err(TableError::MetaOutOfRange {
                    index,
                    meta,
                    available: meta_count,
                });
            }
            keys.push(key);
            metas.push(meta);
        }
        Ok(Self { keys, metas })
    }

    /// Serializes entries into the table format (maintainer tooling and tests).
    /// Duplicate keys are rejected: a pack must say exactly one thing per key.
    pub fn encode(mut entries: Vec<([u8; K], u32)>) -> Result<Vec<u8>, TableError> {
        entries.sort_unstable_by_key(|entry| entry.0);
        if let Some(index) = entries
            .windows(2)
            .position(|w| matches!(w, [a, b] if a.0 == b.0))
        {
            return Err(TableError::NotStrictlySorted(index.saturating_add(1)));
        }
        let key_len = u16::try_from(K).map_err(|_| TableError::KeyLength {
            expected: K,
            found: K,
        })?;
        let count = u64::try_from(entries.len()).map_err(|_| TableError::LengthMismatch)?;
        let mut out = Vec::with_capacity(
            HEADER_LEN.saturating_add(entries.len().saturating_mul(K.saturating_add(META_LEN))),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&key_len.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        for (key, meta) in &entries {
            out.extend_from_slice(key);
            out.extend_from_slice(&meta.to_le_bytes());
        }
        Ok(out)
    }

    /// Metadata index for `key`, if present.
    pub fn lookup(&self, key: &[u8; K]) -> Option<u32> {
        let index = self.keys.binary_search(key).ok()?;
        self.metas.get(index).copied()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl UrlTable {
    /// Every indicator matching any lookup expression of `url`, with the
    /// expression that matched (host-only expressions are domain-scoped).
    pub fn matches(&self, url: &CanonicalUrl) -> Vec<(String, u32)> {
        url.expressions()
            .into_iter()
            .filter_map(|expression| {
                let hash: ExpressionHash = crate::urlcanon::expression_hash(&expression);
                self.lookup(&hash).map(|meta| (expression, meta))
            })
            .collect()
    }
}

fn array<const N: usize>(slice: &[u8]) -> Result<[u8; N], TableError> {
    slice.try_into().map_err(|_| TableError::LengthMismatch)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic on known-small values
mod tests {
    use super::*;
    use crate::urlcanon::{canonicalize, expression_hash};

    fn url_table(expressions: &[&str]) -> Vec<u8> {
        let entries = expressions
            .iter()
            .zip(0u32..)
            .map(|(e, meta)| (expression_hash(e), meta))
            .collect();
        UrlTable::encode(entries).unwrap_or_default()
    }

    #[test]
    fn round_trip_and_lookup() {
        let bytes = url_table(&["evil.example/", "good.example/phish/login.html"]);
        let table = UrlTable::parse(&bytes, 2);
        assert!(table.as_ref().is_ok_and(|t| t.len() == 2));
        let table = table.unwrap_or_else(|_| UrlTable {
            keys: vec![],
            metas: vec![],
        });
        assert_eq!(table.lookup(&expression_hash("evil.example/")), Some(0));
        assert_eq!(table.lookup(&expression_hash("other.example/")), None);
    }

    #[test]
    fn domain_indicator_matches_any_path_and_subdomain() {
        let table = UrlTable::parse(&url_table(&["evil.example/"]), 1).ok();
        let url = canonicalize(b"https://login.evil.example/account/verify?id=7").ok();
        let hits = table
            .zip(url)
            .map(|(t, u)| t.matches(&u))
            .unwrap_or_default();
        assert_eq!(hits, vec![("evil.example/".to_owned(), 0)]);
    }

    #[test]
    fn path_indicator_does_not_flag_the_whole_domain() {
        let table = UrlTable::parse(&url_table(&["shared.example/phish/login.html"]), 1).ok();
        let check = |u: &[u8]| {
            let url = canonicalize(u).ok();
            table
                .as_ref()
                .zip(url)
                .map(|(t, u)| t.matches(&u).len())
                .unwrap_or(usize::MAX)
        };
        assert_eq!(check(b"http://shared.example/phish/login.html?x=1"), 1);
        assert_eq!(check(b"http://shared.example/"), 0);
        assert_eq!(check(b"http://shared.example/other.html"), 0);
    }

    #[test]
    fn rejects_malformed_tables() {
        let good = url_table(&["a/", "b/", "c/"]);
        let with = |offset: usize, value: u8| {
            let mut bad = good.clone();
            if let Some(b) = bad.get_mut(offset) {
                *b = value;
            }
            UrlTable::parse(&bad, 3)
        };
        assert_eq!(UrlTable::parse(&good[..10], 3), Err(TableError::TooShort));
        assert_eq!(with(0, b'X'), Err(TableError::BadMagic));
        assert_eq!(with(8, 2), Err(TableError::UnsupportedVersion(2)));
        assert_eq!(
            with(10, 32),
            Err(TableError::KeyLength {
                expected: 16,
                found: 32
            })
        );
        assert_eq!(with(12, 1), Err(TableError::ReservedNonZero));
        assert_eq!(with(16, 4), Err(TableError::LengthMismatch));
        assert_eq!(
            UrlTable::parse(&good[..good.len() - 1], 3),
            Err(TableError::LengthMismatch)
        );
        assert!(matches!(
            UrlTable::parse(&good, 2),
            Err(TableError::MetaOutOfRange { .. })
        ));
        assert_eq!(
            FileTable::parse(&good, 3),
            Err(TableError::KeyLength {
                expected: 32,
                found: 16
            })
        );
    }

    #[test]
    fn rejects_unsorted_and_duplicate_records() {
        let mut bytes = url_table(&["a/", "b/"]);
        // Swap the two 20-byte records.
        let (first, second) = (
            HEADER_LEN..HEADER_LEN + 20,
            HEADER_LEN + 20..HEADER_LEN + 40,
        );
        let a: Vec<u8> = bytes[first.clone()].to_vec();
        let b: Vec<u8> = bytes[second.clone()].to_vec();
        bytes[first].copy_from_slice(&b);
        bytes[second].copy_from_slice(&a);
        assert_eq!(
            UrlTable::parse(&bytes, 2),
            Err(TableError::NotStrictlySorted(1))
        );
        let duplicate = vec![([7u8; 16], 0), ([7u8; 16], 1)];
        assert!(UrlTable::encode(duplicate).is_err());
    }

    #[test]
    fn huge_declared_count_is_rejected_without_allocation() {
        let mut bytes = url_table(&["a/"]);
        if let Some(count) = bytes.get_mut(16..24) {
            count.copy_from_slice(&u64::MAX.to_le_bytes());
        }
        assert_eq!(UrlTable::parse(&bytes, 1), Err(TableError::LengthMismatch));
    }
}
