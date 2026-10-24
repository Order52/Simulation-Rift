//! Rift AI: a learned URL classifier (docs/architecture.md §16).
//!
//! Logistic regression over hashed features of the canonical URL: character
//! n-grams and words of the host, words of the path, query keys, and a few
//! counts. A model may also hold factors (a factorization machine): a short
//! vector per feature, whose dot products weigh pairs of features that
//! appear together, such as a brand's name in the host with "login" in the
//! path. The model is numeric data only (a fixed header, one weight per hash
//! bucket, and the optional factor table); scoring is sums and a sigmoid, so
//! a URL is scored in microseconds and nothing in the file is ever executed.
//!
//! The trainer (tools/rift-train) calls [`for_each_feature`], the same code
//! that scores a URL here, so what was learned is what is applied.
//!
//! The score is advisory. It can add a warning; it never blocks, never
//! overrides an indicator match, and a low score is never shown as "safe".

use std::collections::HashSet;

use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};

use crate::text::escape_for_display;
use crate::urlcanon::CanonicalUrl;

/// The model's file name inside an intelligence pack (optional there).
pub const MODEL_FILE: &str = "url-model.bin";
/// Version of [`for_each_feature`]. A model trained for another one is
/// refused: its weights would be read against different features.
pub const FEATURE_SCHEMA: u32 = 1;
pub const MIN_BITS: u32 = 16;
pub const MAX_BITS: u32 = 20;
/// §16's budget for the whole file: weights, suffix rules and sites.
pub const MAX_MODEL_BYTES: usize = 2 * 1024 * 1024;
/// The suffix rules' text (the Public Suffix List is about 140 KiB).
pub const MAX_SUFFIX_BYTES: usize = 512 * 1024;
pub const MAX_POPULAR_SITES: usize = 100_000;
/// Factors per feature, at most.
pub const MAX_FACTORS: usize = 8;
/// Rows of the factor table, as a power of two.
pub const FACTOR_BITS: std::ops::RangeInclusive<u32> = 10..=18;

const MAGIC: &[u8; 8] = b"RIFTURL1";
const HEADER_BYTES: usize = 8 + 4 * 6;
/// Bytes of path and query read for words; the rest of a long URL is not.
const MAX_PATH_BYTES: usize = 512;
const MAX_WORDS: usize = 40;
const MAX_QUERY_KEYS: usize = 20;
/// Bytes at the start of the path whose n-grams are features.
const PATH_GRAM_BYTES: usize = 64;
/// Character n-grams of the host, between these lengths.
const GRAMS: std::ops::RangeInclusive<usize> = 3..=5;
const SIGNALS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    #[error("not a Rift URL model")]
    Magic,
    #[error("the model is for feature schema {0}, this build reads {FEATURE_SCHEMA}")]
    Schema(u32),
    #[error("the model's size is wrong: {0}")]
    Size(String),
    #[error("the model's {0} is out of range")]
    Value(&'static str),
}

/// Which part of an address was seen. A page's own requests over HTTPS are
/// seen by the network lock as a host only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Address,
    HostOnly,
}

/// What a feature is, for hashing (its byte is part of the hash) and for
/// explaining a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    HostGram = 1,
    HostLabel = 2,
    Tld = 3,
    Domain = 4,
    HostWord = 5,
    HostShape = 6,
    Scheme = 7,
    PathWord = 8,
    PathExtension = 9,
    PathShape = 10,
    QueryKey = 11,
    Embedded = 12,
    HostOnly = 13,
    /// A subdomain on a given domain, by depth (free hosting platforms).
    DomainDepth = 14,
    /// The name before the ending: how random it looks.
    NameShape = 15,
    PathGram = 16,
    PathPair = 17,
}

impl Kind {
    /// A reason a user can read, or None for features that only mean
    /// something together (n-grams, counts in buckets).
    fn describe(self, token: &str) -> Option<String> {
        let t = escape_for_display(token);
        Some(match (self, token) {
            (Self::HostLabel, _) => format!("the host part \u{201c}{t}\u{201d}"),
            (Self::Tld, _) => format!("the ending .{t}"),
            (Self::Domain, _) => format!("the domain {t}"),
            (Self::DomainDepth, _) => {
                let domain = token.rsplit_once(' ').map_or(token, |(domain, _)| domain);
                format!("a subdomain of {}", escape_for_display(domain))
            }
            (Self::HostWord, _) => format!("the word \u{201c}{t}\u{201d} in the host"),
            (Self::HostShape, "an IP address") => "a bare IP address instead of a name".to_owned(),
            (Self::HostShape, "international") => "an international (punycode) name".to_owned(),
            (Self::NameShape, "letters and digits") => {
                "a site name mixing letters and digits".to_owned()
            }
            (Self::Scheme, _) => format!("an unencrypted {t} link"),
            (Self::PathWord, _) => format!("the word \u{201c}{t}\u{201d} in the path"),
            (Self::PathPair, _) => format!("the words \u{201c}{t}\u{201d} in the path"),
            (Self::PathExtension, _) => format!("a .{t} page"),
            (Self::PathShape, "a double slash") => "a double slash in the path".to_owned(),
            (Self::PathShape, "an @") => "an @ in the path".to_owned(),
            (Self::QueryKey, _) => format!("the parameter \u{201c}{t}\u{201d}"),
            (Self::Embedded, _) => "another address inside the link".to_owned(),
            _ => return None,
        })
    }
}

/// One feature: its kind, its token, and its value (1, or less for one of
/// many n-grams so a long host does not outweigh everything else).
#[derive(Debug, Clone, Copy)]
pub struct Feature<'a> {
    pub kind: Kind,
    pub token: &'a str,
    pub value: f32,
}

impl Feature<'_> {
    /// The weight bucket and sign for a table of 2^bits weights (signed
    /// feature hashing, so collisions cancel rather than accumulate).
    pub fn bucket(&self, bits: u32) -> (usize, f32) {
        let h = self.hash();
        let mask = (1u64 << bits).wrapping_sub(1);
        let sign = if h >> 63 == 0 { 1.0 } else { -1.0 };
        (usize::try_from(h & mask).unwrap_or(0), sign)
    }

    /// FNV-1a over the kind's byte and the token, then splitmix64's
    /// finalizer (FNV's low bits alone are weak).
    fn hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in std::iter::once(self.kind as u8).chain(self.token.bytes()) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        h ^ (h >> 31)
    }
}

/// Calls `f` with every feature of `url` as seen in `view`. The trainer
/// and the app both use this; change it only with [`FEATURE_SCHEMA`].
pub fn for_each_feature(url: &CanonicalUrl, view: View, mut f: impl FnMut(Feature<'_>)) {
    let mut emit = |kind, token: &str, value| f(Feature { kind, token, value });
    if view == View::HostOnly {
        emit(Kind::HostOnly, "", 1.0);
    }
    if url.scheme() == "http" {
        emit(Kind::Scheme, "http", 1.0);
    }
    host_features(url, &mut emit);
    if view == View::Address {
        path_features(url, &mut emit);
    }
}

fn host_features(url: &CanonicalUrl, emit: &mut impl FnMut(Kind, &str, f32)) {
    let host = url.host().trim_end_matches('.');
    if url.host_is_ip() {
        emit(Kind::HostShape, "an IP address", 1.0);
        return;
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if let Some(tld) = labels.last() {
        emit(Kind::Tld, tld, 1.0);
    }
    if let [.., second, last] = labels.as_slice() {
        let domain = format!("{second}.{last}");
        emit(Kind::Domain, &domain, 1.0);
        let below = labels.len().saturating_sub(2);
        if below > 0 {
            emit(
                Kind::DomainDepth,
                &format!("{domain} {}", count_bucket(below)),
                1.0,
            );
        }
        name_shape(second, emit);
    }
    for label in &labels {
        emit(Kind::HostLabel, label, 1.0);
        if label.starts_with("xn--") {
            emit(Kind::HostShape, "international", 1.0);
        }
    }
    for word in words(host) {
        emit(Kind::HostWord, word, 1.0);
    }
    emit(
        Kind::HostShape,
        &format!("{} labels", count_bucket(labels.len())),
        1.0,
    );
    emit(
        Kind::HostShape,
        &format!("{} long", length_bucket(host.len())),
        1.0,
    );
    let digits = host.bytes().filter(u8::is_ascii_digit).count();
    emit(
        Kind::HostShape,
        &format!("{} digits", count_bucket(digits)),
        1.0,
    );
    let hyphens = host.bytes().filter(|b| *b == b'-').count();
    emit(
        Kind::HostShape,
        &format!("{} hyphens", count_bucket(hyphens)),
        1.0,
    );

    // Character n-grams of "^host$", each weighted 1/sqrt(n) so the group
    // has the weight of about one feature whatever the host's length.
    let marked = format!("^{host}$");
    let bytes = marked.as_bytes();
    let total: usize = GRAMS
        .clone()
        .map(|n| bytes.len().saturating_sub(n).saturating_add(1))
        .sum();
    if total == 0 {
        return;
    }
    let value = 1.0 / (total as f32).sqrt();
    for n in GRAMS {
        for start in 0..bytes.len().saturating_sub(n).saturating_add(1) {
            // The host is ASCII (canonical form), so byte ranges are characters.
            if let Some(gram) = marked.get(start..start.saturating_add(n)) {
                emit(Kind::HostGram, gram, value);
            }
        }
    }
}

/// How random the site's name looks: generated names (long, few vowels,
/// letters and digits mixed) are common in throwaway domains.
fn name_shape(name: &str, emit: &mut impl FnMut(Kind, &str, f32)) {
    let letters = name.bytes().filter(u8::is_ascii_alphabetic).count();
    let digits = name.bytes().filter(u8::is_ascii_digit).count();
    let vowels = name.bytes().filter(|b| b"aeiouy".contains(b)).count();
    let mut run = 0usize;
    let mut longest = 0usize;
    for b in name.bytes() {
        if b.is_ascii_alphabetic() && !b"aeiouy".contains(&b) {
            run = run.saturating_add(1);
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    emit(
        Kind::NameShape,
        &format!("{} long", length_bucket(name.len())),
        1.0,
    );
    if letters > 0 && digits > 0 {
        emit(Kind::NameShape, "letters and digits", 1.0);
    }
    if letters >= 6 {
        // Vowels per ten letters, in buckets.
        let tenths = vowels.saturating_mul(10).checked_div(letters).unwrap_or(0);
        emit(
            Kind::NameShape,
            &format!("{} vowels in ten", count_bucket(tenths)),
            1.0,
        );
    }
    emit(
        Kind::NameShape,
        &format!("{} consonants in a row", count_bucket(longest)),
        1.0,
    );
}

fn path_features(url: &CanonicalUrl, emit: &mut impl FnMut(Kind, &str, f32)) {
    let path = prefix(url.path(), MAX_PATH_BYTES);
    let decoded = percent_decode_str(path).decode_utf8_lossy().to_lowercase();
    let segments: Vec<&str> = decoded.split('/').filter(|s| !s.is_empty()).collect();
    emit(
        Kind::PathShape,
        &format!("{} deep", count_bucket(segments.len())),
        1.0,
    );
    emit(
        Kind::PathShape,
        &format!("{} long", length_bucket(url.path().len())),
        1.0,
    );
    let path_words: Vec<&str> = words(&decoded).take(MAX_WORDS).collect();
    for word in &path_words {
        emit(Kind::PathWord, word, 1.0);
    }
    for pair in path_words.windows(2) {
        if let [a, b] = pair {
            emit(Kind::PathPair, &format!("{a} {b}"), 1.0);
        }
    }
    // The path's spelling, as for the host: 3- and 4-grams of its start.
    let start = prefix(&decoded, PATH_GRAM_BYTES);
    let grams: Vec<&str> = (3..=4)
        .flat_map(|n| {
            (0..start.len().saturating_sub(n).saturating_add(1))
                .filter_map(move |i| start.get(i..i.saturating_add(n)))
        })
        .collect();
    if !grams.is_empty() {
        let value = 1.0 / (grams.len() as f32).sqrt();
        for gram in grams {
            emit(Kind::PathGram, gram, value);
        }
    }
    if let Some(last) = segments.last()
        && let Some((_, extension)) = last.rsplit_once('.')
        && (1..=5).contains(&extension.len())
        && extension.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        emit(Kind::PathExtension, extension, 1.0);
    }
    if decoded.contains("//") {
        emit(Kind::PathShape, "a double slash", 1.0);
    }
    if decoded.contains('@') {
        emit(Kind::PathShape, "an @", 1.0);
    }
    if decoded.contains('~') {
        emit(Kind::PathShape, "a ~", 1.0);
    }
    let query = url.query().map(|q| prefix(q, MAX_PATH_BYTES)).unwrap_or("");
    let query_text = percent_decode_str(query).decode_utf8_lossy().to_lowercase();
    if decoded.contains("http")
        || decoded.contains("www.")
        || query_text.contains("http")
        || query_text.contains("www.")
    {
        emit(Kind::Embedded, "", 1.0);
    }
    if url.query().is_some() {
        let keys: Vec<&str> = query_text
            .split('&')
            .filter_map(|pair| pair.split('=').next())
            .filter(|k| !k.is_empty() && k.len() <= 30)
            .take(MAX_QUERY_KEYS)
            .collect();
        emit(
            Kind::PathShape,
            &format!("{} parameters", count_bucket(keys.len())),
            1.0,
        );
        for key in keys {
            emit(Kind::QueryKey, key, 1.0);
        }
        emit(
            Kind::PathShape,
            &format!("a {} query", length_bucket(query.len())),
            1.0,
        );
    }
    let escapes = url.path().bytes().filter(|b| *b == b'%').count();
    if escapes > 0 {
        emit(
            Kind::PathShape,
            &format!("{} escapes", count_bucket(escapes)),
            1.0,
        );
    }
}

/// Lower-case alphabetic runs of 2 to 30 letters.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_alphabetic())
        .filter(|w| (2..=30).contains(&w.chars().count()))
}

fn prefix(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or("")
}

fn count_bucket(n: usize) -> &'static str {
    match n {
        0 => "0",
        1 => "1",
        2 => "2",
        3..=4 => "3-4",
        5..=8 => "5-8",
        _ => "9+",
    }
}

fn length_bucket(n: usize) -> &'static str {
    match n {
        0..=8 => "short",
        9..=16 => "9-16",
        17..=32 => "17-32",
        33..=64 => "33-64",
        65..=128 => "65-128",
        _ => "very",
    }
}

/// How strongly the model leans towards "malicious".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Nothing the model recognises. Not a statement that the link is safe.
    Low,
    /// Shown in a check's result and the live watch; does not interrupt.
    Elevated,
    /// Warrants a trusted interstitial before loading.
    High,
}

/// A score with the features that raised it most.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    /// The model's probability that the URL is malicious, 0 to 1.
    pub score: f32,
    /// The score Rift shows, 0 to 99, in bands that match the levels: Low
    /// is below 50, Elevated 50 to 89, High 90 and above. Never 100, which
    /// would read as certainty.
    pub risk: u8,
    pub level: Level,
    /// Up to three readable reasons, strongest first; empty when low.
    pub signals: Vec<String>,
    /// The address is on one of the most visited sites, which the model
    /// does not judge: a page hosted there (a form on Google Docs) has the
    /// same kind of address whether it is real or an attack, so the model
    /// was not trained on attacks there. Level is Low and nothing else is set.
    pub abstained: bool,
}

/// The Public Suffix List's rules, which browsers use to tell sites apart:
/// `bank.example.co.uk` is on the site `example.co.uk`, and
/// `evil.workers.dev` is a site of its own, not part of `workers.dev`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Suffixes {
    rules: HashSet<String>,
    /// `*.x` rules, by `x`.
    wildcards: HashSet<String>,
    /// `!x` rules, by `x`.
    exceptions: HashSet<String>,
}

impl Suffixes {
    /// Reads rules, one per line, in ASCII (international names in their
    /// `xn--` form); blank lines and `//` comments are skipped.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let mut out = Self::default();
        for line in text.lines() {
            let rule = line.split_whitespace().next().unwrap_or("");
            if rule.is_empty() || rule.starts_with("//") {
                continue;
            }
            let valid = rule.len() <= 253
                && rule
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.*!".contains(&b));
            if !valid {
                return Err(ModelError::Value("suffix rules"));
            }
            let (set, name) = if let Some(rest) = rule.strip_prefix("*.") {
                (&mut out.wildcards, rest)
            } else if let Some(rest) = rule.strip_prefix('!') {
                (&mut out.exceptions, rest)
            } else {
                (&mut out.rules, rule)
            };
            // A wildcard only as the whole first label, as the list has them.
            if name.is_empty() || name.contains(['*', '!']) || name.split('.').any(str::is_empty) {
                return Err(ModelError::Value("suffix rules"));
            }
            set.insert(name.to_owned());
        }
        Ok(out)
    }

    /// The rules as text, sorted: what [`UrlModel::encode`] stores.
    pub fn to_text(&self) -> String {
        let mut lines: Vec<String> = self
            .rules
            .iter()
            .cloned()
            .chain(self.wildcards.iter().map(|w| format!("*.{w}")))
            .chain(self.exceptions.iter().map(|e| format!("!{e}")))
            .collect();
        lines.sort();
        lines.join("\n")
    }

    /// The site `host` is on: its public suffix and one more label (the
    /// list's algorithm; with no matching rule the suffix is the last
    /// label). A host that is itself a public suffix is its own site.
    pub fn site(&self, host: &str) -> String {
        let host = host.trim_end_matches('.');
        let labels: Vec<&str> = host.split('.').collect();
        let n = labels.len();
        let mut suffix_len = 1usize;
        for i in 0..n {
            let candidate = labels.get(i..).unwrap_or_default().join(".");
            if self.exceptions.contains(&candidate) {
                return candidate;
            }
            let parent = labels
                .get(i.saturating_add(1)..)
                .unwrap_or_default()
                .join(".");
            if self.rules.contains(&candidate)
                || (i.saturating_add(1) < n && self.wildcards.contains(&parent))
            {
                suffix_len = n.saturating_sub(i);
                break;
            }
        }
        let start = n.saturating_sub(suffix_len.saturating_add(1));
        labels.get(start..).unwrap_or_default().join(".")
    }
}

/// A site's key in the model's set of most visited sites.
fn site_key(site: &str) -> u64 {
    Feature {
        kind: Kind::Domain,
        token: site,
        value: 1.0,
    }
    .hash()
}

/// A parsed, validated model.
#[derive(Clone)]
pub struct UrlModel {
    bits: u32,
    scale: f32,
    bias: f32,
    elevated: f32,
    high: f32,
    weights: Vec<i16>,
    suffixes: Suffixes,
    /// Keys of the most visited sites, sorted.
    popular: Vec<u64>,
    factors: Option<QuantizedFactors>,
    digest: [u8; 32],
}

/// A factor table as stored: `k` values per row, against one scale.
#[derive(Clone)]
struct QuantizedFactors {
    k: usize,
    bits: u32,
    scale: f32,
    values: Vec<i16>,
}

/// A model's factor table (see the module's notes).
#[derive(Debug, Clone, PartialEq)]
pub struct Factors {
    /// Values per feature, 1..=[`MAX_FACTORS`].
    pub k: usize,
    /// 2^bits rows; a feature's row is the low bits of its weight bucket.
    pub bits: u32,
    /// Row-major, 2^bits × k.
    pub values: Vec<f32>,
}

impl Factors {
    /// The first value of `bucket`'s row.
    pub fn row(k: usize, bits: u32, bucket: usize) -> usize {
        (bucket & ((1usize << bits).wrapping_sub(1))).wrapping_mul(k)
    }
}

impl std::fmt::Debug for UrlModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlModel")
            .field("bits", &self.bits)
            .field("elevated", &self.elevated)
            .field("high", &self.high)
            .field("popular", &self.popular.len())
            .field("factors", &self.factors.as_ref().map(|f| (f.k, f.bits)))
            .field("digest", &hex::encode(self.digest))
            .finish_non_exhaustive()
    }
}

/// The parts of a model file, for the trainer.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelParts {
    pub bits: u32,
    pub bias: f32,
    /// Score at or above which a URL is [`Level::Elevated`].
    pub elevated: f32,
    /// Score at or above which a URL is [`Level::High`].
    pub high: f32,
    /// 2^bits weights.
    pub weights: Vec<f32>,
    pub suffixes: Suffixes,
    /// The most visited sites (as [`Suffixes::site`] names them), on
    /// which the model abstains.
    pub popular: Vec<String>,
    /// The factor table, if the model has one.
    pub factors: Option<Factors>,
}

impl UrlModel {
    /// Reads a model file. Everything is checked before use: the schema,
    /// the exact size for its table, and that every number is finite and in
    /// range.
    pub fn parse(bytes: &[u8]) -> Result<Self, ModelError> {
        if bytes.len() > MAX_MODEL_BYTES {
            return Err(ModelError::Size(format!("{} bytes", bytes.len())));
        }
        let (header, rest) = bytes
            .split_at_checked(HEADER_BYTES)
            .ok_or_else(|| ModelError::Size("no header".into()))?;
        let (magic, fields) = header.split_at_checked(8).ok_or(ModelError::Magic)?;
        if magic != MAGIC {
            return Err(ModelError::Magic);
        }
        let word = |i: usize| -> [u8; 4] {
            let mut out = [0u8; 4];
            if let Some(src) =
                fields.get(i.saturating_mul(4)..i.saturating_mul(4).saturating_add(4))
            {
                out.copy_from_slice(src);
            }
            out
        };
        let schema = u32::from_le_bytes(word(0));
        if schema != FEATURE_SCHEMA {
            return Err(ModelError::Schema(schema));
        }
        let bits = u32::from_le_bytes(word(1));
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return Err(ModelError::Value("table size"));
        }
        let [scale, bias, elevated, high] = [2, 3, 4, 5].map(|i| f32::from_le_bytes(word(i)));
        if !(scale.is_finite() && scale > 0.0) {
            return Err(ModelError::Value("scale"));
        }
        if !bias.is_finite() {
            return Err(ModelError::Value("bias"));
        }
        if !(elevated > 0.0 && elevated <= high && high < 1.0) {
            return Err(ModelError::Value("thresholds"));
        }
        let (table, rest) = rest
            .split_at_checked(2usize << bits)
            .ok_or_else(|| ModelError::Size("the weight table is cut short".into()))?;
        let (suffix_text, rest) = section(rest, MAX_SUFFIX_BYTES, 1)?;
        let suffix_text =
            std::str::from_utf8(suffix_text).map_err(|_| ModelError::Value("suffix rules"))?;
        let suffixes = Suffixes::parse(suffix_text)?;
        let (popular_bytes, rest) = section(rest, MAX_POPULAR_SITES, 8)?;
        let (factors, rest) = if rest.is_empty() {
            (None, rest)
        } else {
            let (factors, rest) = parse_factors(rest)?;
            (Some(factors), rest)
        };
        if !rest.is_empty() {
            return Err(ModelError::Size(format!(
                "{} bytes after the last section",
                rest.len()
            )));
        }
        let popular: Vec<u64> = popular_bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|b| u64::from_le_bytes(*b))
            .collect();
        if popular.windows(2).any(|w| matches!(w, [a, b] if a >= b)) {
            return Err(ModelError::Value("popular sites (not sorted)"));
        }
        let weights = table
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_le_bytes(*pair))
            .collect();
        Ok(Self {
            bits,
            scale,
            bias,
            elevated,
            high,
            weights,
            suffixes,
            popular,
            factors,
            digest: Sha256::digest(bytes).into(),
        })
    }

    /// Writes a model file (the trainer). Weights are quantized to 16 bits
    /// against the largest one.
    pub fn encode(parts: &ModelParts) -> Result<Vec<u8>, ModelError> {
        if !(MIN_BITS..=MAX_BITS).contains(&parts.bits)
            || parts.weights.len() != 1usize << parts.bits
        {
            return Err(ModelError::Size(
                "weights do not match the table size".into(),
            ));
        }
        let largest = parts.weights.iter().fold(0f32, |m, w| m.max(w.abs()));
        if !largest.is_finite() {
            return Err(ModelError::Value("weights"));
        }
        let scale = if largest > 0.0 {
            largest / f32::from(i16::MAX)
        } else {
            1.0
        };
        let mut out =
            Vec::with_capacity(HEADER_BYTES.saturating_add(parts.weights.len().saturating_mul(2)));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FEATURE_SCHEMA.to_le_bytes());
        out.extend_from_slice(&parts.bits.to_le_bytes());
        for value in [scale, parts.bias, parts.elevated, parts.high] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for w in &parts.weights {
            // In range by construction: |w| <= largest.
            let q = (w / scale)
                .round()
                .clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16;
            out.extend_from_slice(&q.to_le_bytes());
        }
        let rules = parts.suffixes.to_text();
        out.extend_from_slice(
            &u32::try_from(rules.len())
                .map_err(|_| ModelError::Value("suffix rules"))?
                .to_le_bytes(),
        );
        out.extend_from_slice(rules.as_bytes());
        let mut popular: Vec<u64> = parts.popular.iter().map(|site| site_key(site)).collect();
        popular.sort_unstable();
        popular.dedup();
        out.extend_from_slice(
            &u32::try_from(popular.len())
                .map_err(|_| ModelError::Value("popular sites"))?
                .to_le_bytes(),
        );
        for key in popular {
            out.extend_from_slice(&key.to_le_bytes());
        }
        if let Some(factors) = &parts.factors {
            encode_factors(factors, &mut out)?;
        }
        Self::parse(&out)?;
        Ok(out)
    }

    /// The site `url` is on (see [`Suffixes::site`]); an address literal is its own.
    pub fn site(&self, url: &CanonicalUrl) -> String {
        if url.host_is_ip() {
            url.host().to_owned()
        } else {
            self.suffixes.site(url.host())
        }
    }

    /// Whether the model abstains on `url`'s site.
    pub fn abstains(&self, url: &CanonicalUrl) -> bool {
        self.popular
            .binary_search(&site_key(&self.site(url)))
            .is_ok()
    }

    /// `probability` as [`Assessment::risk`]: linear within each level's band.
    pub fn risk(&self, probability: f32) -> u8 {
        let p = if probability.is_nan() {
            0.0
        } else {
            probability.clamp(0.0, 1.0)
        };
        let band = |p: f32, from: f32, to: f32, low: f32, high: f32| {
            let span = (to - from).max(f32::EPSILON);
            low + (high - low) * ((p - from) / span).clamp(0.0, 1.0)
        };
        let risk = if p < self.elevated {
            band(p, 0.0, self.elevated, 0.0, 49.0)
        } else if p < self.high {
            band(p, self.elevated, self.high, 50.0, 89.0)
        } else {
            band(p, self.high, 1.0, 90.0, 99.0)
        };
        // In range by construction: the cast cannot truncate.
        risk.floor().clamp(0.0, 99.0) as u8
    }

    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// The model's probability that `url` is malicious, with reasons.
    pub fn assess(&self, url: &CanonicalUrl, view: View) -> Assessment {
        if self.abstains(url) {
            return Assessment {
                score: 0.0,
                risk: 0,
                level: Level::Low,
                signals: Vec::new(),
                abstained: true,
            };
        }
        let mut sum = self.bias;
        // (contribution, readable reason) of the explainable features;
        // the host's n-grams are summed into one reason.
        let mut reasons: Vec<(f32, String)> = Vec::new();
        let mut spelling = 0f32;
        let mut path_spelling = 0f32;
        // Σ v·x per factor and Σ (v·x)², for the pairs' sum.
        let mut factor_sums = [0f32; MAX_FACTORS];
        let mut factor_squares = 0f32;
        for_each_feature(url, view, |feature| {
            let (index, sign) = feature.bucket(self.bits);
            if let Some(f) = &self.factors {
                let row = Factors::row(f.k, f.bits, index);
                let x = sign * feature.value;
                for (i, total) in factor_sums.iter_mut().take(f.k).enumerate() {
                    let v = f
                        .values
                        .get(row.wrapping_add(i))
                        .copied()
                        .map_or(0.0, |q| f32::from(q) * f.scale);
                    *total += v * x;
                    factor_squares += v * x * v * x;
                }
            }
            let weight = self
                .weights
                .get(index)
                .copied()
                .map_or(0.0, |q| f32::from(q) * self.scale);
            let contribution = weight * sign * feature.value;
            sum += contribution;
            if feature.kind == Kind::HostGram {
                spelling += contribution;
            } else if feature.kind == Kind::PathGram {
                path_spelling += contribution;
            } else if contribution > 0.0
                && let Some(text) = feature.kind.describe(feature.token)
            {
                reasons.push((contribution, text));
            }
        });
        // Each pair counted once: ((Σ v·x)² − Σ (v·x)²) / 2.
        let pairs = 0.5 * (factor_sums.iter().map(|t| t * t).sum::<f32>() - factor_squares);
        sum += pairs;
        let score = sigmoid(sum);
        let level = if score >= self.high {
            Level::High
        } else if score >= self.elevated {
            Level::Elevated
        } else {
            Level::Low
        };
        let signals = if level == Level::Low {
            Vec::new()
        } else {
            if spelling > 0.0 {
                reasons.push((spelling, "the spelling of the host name".to_owned()));
            }
            if path_spelling > 0.0 {
                reasons.push((path_spelling, "the spelling of the path".to_owned()));
            }
            if pairs > 0.0 {
                reasons.push((pairs, "how the parts of the address go together".to_owned()));
            }
            reasons.sort_by(|a, b| b.0.total_cmp(&a.0));
            reasons.dedup_by(|a, b| a.1 == b.1);
            reasons
                .into_iter()
                .take(SIGNALS)
                .map(|(_, text)| text)
                .collect()
        };
        Assessment {
            score,
            risk: self.risk(score),
            level,
            signals,
            abstained: false,
        }
    }
}

/// A model whose only non-zero weights are for the given features (tests).
#[cfg(test)]
pub(crate) fn model_for_tests(weights: &[(Kind, &str, f32)], bias: f32) -> UrlModel {
    let bits = MIN_BITS;
    let mut table = vec![0f32; 1 << bits];
    for (kind, token, w) in weights {
        let (i, sign) = Feature {
            kind: *kind,
            token,
            value: 1.0,
        }
        .bucket(bits);
        if let Some(slot) = table.get_mut(i) {
            *slot += w * sign;
        }
    }
    let parts = ModelParts {
        bits,
        bias,
        elevated: 0.5,
        high: 0.9,
        weights: table,
        suffixes: Suffixes::default(),
        popular: Vec::new(),
        factors: None,
    };
    UrlModel::encode(&parts)
        .and_then(|bytes| UrlModel::parse(&bytes))
        .unwrap_or_else(|e| unreachable!("a test model is valid: {e}"))
}

/// A length-prefixed section: a u32 count of `unit`-byte items (at most
/// `max`), then the items; returns them and what follows.
fn section(bytes: &[u8], max: usize, unit: usize) -> Result<(&[u8], &[u8]), ModelError> {
    let (count, rest) = bytes
        .split_first_chunk::<4>()
        .ok_or_else(|| ModelError::Size("a section is missing".into()))?;
    let count = usize::try_from(u32::from_le_bytes(*count))
        .map_err(|_| ModelError::Size("a section is too long".into()))?;
    if count > max {
        return Err(ModelError::Size(format!(
            "a section of {count} items (at most {max})"
        )));
    }
    rest.split_at_checked(count.saturating_mul(unit))
        .ok_or_else(|| ModelError::Size("a section is cut short".into()))
}

/// The factor section: u32 k, u32 bits, f32 scale, then 2^bits × k i16.
fn parse_factors(bytes: &[u8]) -> Result<(QuantizedFactors, &[u8]), ModelError> {
    let (head, rest) = bytes
        .split_first_chunk::<12>()
        .ok_or_else(|| ModelError::Size("the factor section is cut short".into()))?;
    let [a, b, c] = [0usize, 4, 8].map(|i| {
        let mut w = [0u8; 4];
        if let Some(src) = head.get(i..i.saturating_add(4)) {
            w.copy_from_slice(src);
        }
        w
    });
    let k = usize::try_from(u32::from_le_bytes(a)).map_err(|_| ModelError::Value("factors"))?;
    let bits = u32::from_le_bytes(b);
    let scale = f32::from_le_bytes(c);
    if !(1..=MAX_FACTORS).contains(&k) || !FACTOR_BITS.contains(&bits) {
        return Err(ModelError::Value("factor table size"));
    }
    if !(scale.is_finite() && scale > 0.0) {
        return Err(ModelError::Value("factor scale"));
    }
    let (table, rest) = rest
        .split_at_checked((1usize << bits).saturating_mul(k).saturating_mul(2))
        .ok_or_else(|| ModelError::Size("the factor table is cut short".into()))?;
    let values = table
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| i16::from_le_bytes(*pair))
        .collect();
    Ok((
        QuantizedFactors {
            k,
            bits,
            scale,
            values,
        },
        rest,
    ))
}

fn encode_factors(factors: &Factors, out: &mut Vec<u8>) -> Result<(), ModelError> {
    if !(1..=MAX_FACTORS).contains(&factors.k)
        || !FACTOR_BITS.contains(&factors.bits)
        || factors.values.len() != (1usize << factors.bits).saturating_mul(factors.k)
    {
        return Err(ModelError::Size(
            "factors do not match their table size".into(),
        ));
    }
    let largest = factors.values.iter().fold(0f32, |m, v| m.max(v.abs()));
    if !largest.is_finite() {
        return Err(ModelError::Value("factors"));
    }
    let scale = if largest > 0.0 {
        largest / f32::from(i16::MAX)
    } else {
        1.0
    };
    // In range by construction: k <= MAX_FACTORS and bits <= 18.
    out.extend_from_slice(&(factors.k as u32).to_le_bytes());
    out.extend_from_slice(&factors.bits.to_le_bytes());
    out.extend_from_slice(&scale.to_le_bytes());
    for v in &factors.values {
        let q = (v / scale)
            .round()
            .clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16;
        out.extend_from_slice(&q.to_le_bytes());
    }
    Ok(())
}

pub fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urlcanon::canonicalize;

    fn url(s: &str) -> CanonicalUrl {
        canonicalize(s.as_bytes()).unwrap()
    }

    fn tokens(s: &str, view: View) -> Vec<(Kind, String)> {
        let mut out = Vec::new();
        for_each_feature(&url(s), view, |f| out.push((f.kind, f.token.to_owned())));
        out
    }

    use super::model_for_tests as model_with;

    #[test]
    fn features_are_what_the_schema_says() {
        let all = tokens(
            "http://secure-paypal.account.example.xyz/Login/verify.php?user=a&token=b",
            View::Address,
        );
        let has = |kind, token: &str| all.iter().any(|(k, t)| *k == kind && t == token);
        assert!(has(Kind::Scheme, "http"));
        assert!(has(Kind::Tld, "xyz"));
        assert!(has(Kind::Domain, "example.xyz"));
        assert!(has(Kind::HostLabel, "secure-paypal"));
        assert!(has(Kind::HostWord, "paypal"));
        assert!(has(Kind::HostShape, "1 hyphens"));
        assert!(has(Kind::HostGram, "^se"));
        assert!(has(Kind::HostGram, "xyz$"));
        assert!(has(Kind::PathWord, "login"));
        assert!(has(Kind::PathWord, "verify"));
        assert!(has(Kind::PathExtension, "php"));
        assert!(has(Kind::QueryKey, "token"));
        assert!(!has(Kind::HostOnly, ""));
        // A host seen alone has no path features, and says so.
        let host = tokens(
            "https://secure-paypal.account.example.xyz/Login",
            View::HostOnly,
        );
        assert!(host.iter().any(|(k, _)| *k == Kind::HostOnly));
        assert!(
            !host
                .iter()
                .any(|(k, _)| matches!(k, Kind::PathWord | Kind::PathShape | Kind::Scheme))
        );
    }

    #[test]
    fn an_ip_host_has_no_name_features() {
        let all = tokens("http://192.0.2.7/a", View::Address);
        assert!(
            all.iter()
                .any(|(k, t)| *k == Kind::HostShape && t == "an IP address")
        );
        assert!(
            !all.iter()
                .any(|(k, _)| matches!(k, Kind::HostGram | Kind::Tld | Kind::Domain))
        );
    }

    #[test]
    fn an_embedded_address_is_seen_after_decoding() {
        let all = tokens(
            "https://example.org/r?u=https%3A%2F%2Fevil.example",
            View::Address,
        );
        assert!(all.iter().any(|(k, _)| *k == Kind::Embedded));
    }

    #[test]
    fn the_hash_is_stable() {
        // Golden values: a change here changes every trained model's
        // meaning, so it must come with a new FEATURE_SCHEMA.
        let f = |kind, token| {
            Feature {
                kind,
                token,
                value: 1.0,
            }
            .bucket(19)
        };
        assert_eq!(f(Kind::PathWord, "login"), (88_186, 1.0));
        assert_eq!(f(Kind::Tld, "com"), (503_760, -1.0));
        assert_eq!(f(Kind::HostGram, "^pa"), (189_627, -1.0));
    }

    #[test]
    fn scores_and_explains_from_its_weights() {
        let model = model_with(
            &[
                (Kind::PathWord, "verify", 3.0),
                (Kind::Tld, "xyz", 2.0),
                (Kind::Tld, "org", -6.0),
            ],
            -1.0,
        );
        let bad = model.assess(
            &url("https://shop.example.xyz/account/verify"),
            View::Address,
        );
        assert_eq!(bad.level, Level::High);
        assert!((bad.score - sigmoid(4.0)).abs() < 1e-3, "{}", bad.score);
        assert_eq!(
            bad.signals[0],
            "the word \u{201c}verify\u{201d} in the path"
        );
        assert_eq!(bad.signals[1], "the ending .xyz");
        let fine = model.assess(&url("https://example.org/verify"), View::Address);
        assert_eq!(fine.level, Level::Low);
        assert!(fine.signals.is_empty());
        // Seen as a host only, the path's word does not count.
        let host = model.assess(
            &url("https://shop.example.xyz/account/verify"),
            View::HostOnly,
        );
        assert!((host.score - sigmoid(1.0)).abs() < 1e-3, "{}", host.score);
        assert_eq!(host.level, Level::Elevated);
    }

    #[test]
    fn readable_reasons_are_escaped() {
        let model = model_with(&[(Kind::PathWord, "pay\u{202e}pal", 9.0)], 0.0);
        let a = model.assess(&url("https://example.org/pay%E2%80%AEpal"), View::Address);
        assert!(
            a.signals.iter().all(|s| !s.contains('\u{202e}')),
            "{:?}",
            a.signals
        );
    }

    #[test]
    fn damaged_models_are_refused() {
        let good = UrlModel::encode(&ModelParts {
            bits: MIN_BITS,
            bias: 0.0,
            elevated: 0.5,
            high: 0.9,
            weights: vec![0.5; 1 << MIN_BITS],
            suffixes: Suffixes::parse("com\n*.platform.example\n").unwrap(),
            popular: vec!["popular.com".into()],
            factors: None,
        })
        .unwrap();
        assert!(UrlModel::parse(&good).is_ok());
        assert_eq!(
            UrlModel::parse(b"nope").unwrap_err(),
            ModelError::Size("no header".into())
        );
        let mut magic = good.clone();
        magic[0] = b'X';
        assert_eq!(UrlModel::parse(&magic).unwrap_err(), ModelError::Magic);
        let mut schema = good.clone();
        schema[8] = 99;
        assert_eq!(
            UrlModel::parse(&schema).unwrap_err(),
            ModelError::Schema(99)
        );
        assert!(matches!(
            UrlModel::parse(&good[..good.len() - 2]),
            Err(ModelError::Size(_))
        ));
        let mut bits = good.clone();
        bits[12] = 30;
        assert_eq!(
            UrlModel::parse(&bits).unwrap_err(),
            ModelError::Value("table size")
        );
        let mut nan = good.clone();
        nan[20..24].copy_from_slice(&f32::NAN.to_le_bytes());
        assert_eq!(
            UrlModel::parse(&nan).unwrap_err(),
            ModelError::Value("bias")
        );
        let mut order = good.clone();
        order[24..28].copy_from_slice(&0.95f32.to_le_bytes());
        assert_eq!(
            UrlModel::parse(&order).unwrap_err(),
            ModelError::Value("thresholds")
        );
        assert!(
            UrlModel::encode(&ModelParts {
                bits: MIN_BITS,
                bias: 0.0,
                elevated: 0.5,
                high: 0.9,
                weights: vec![0.0; 3],
                suffixes: Suffixes::default(),
                popular: Vec::new(),
                factors: None,
            })
            .is_err()
        );
    }

    /// A model whose only factors are for two words, one in the host and
    /// one in the path: each alone adds nothing, together they add `v·v`.
    fn paired_model(v: f32) -> UrlModel {
        let bits = MIN_BITS;
        const K: usize = 2;
        const FACTOR_BITS: u32 = 12;
        let (k, factor_bits) = (K, FACTOR_BITS);
        let mut values = vec![0f32; K << FACTOR_BITS];
        for (kind, token) in [(Kind::HostWord, "paypal"), (Kind::PathWord, "login")] {
            let (bucket, sign) = Feature {
                kind,
                token,
                value: 1.0,
            }
            .bucket(bits);
            values[Factors::row(k, factor_bits, bucket)] = v * sign;
        }
        let parts = ModelParts {
            bits,
            bias: 0.0,
            elevated: 0.5,
            high: 0.9,
            weights: vec![0.0; 1 << bits],
            suffixes: Suffixes::default(),
            popular: Vec::new(),
            factors: Some(Factors {
                k,
                bits: factor_bits,
                values,
            }),
        };
        UrlModel::parse(&UrlModel::encode(&parts).unwrap()).unwrap()
    }

    #[test]
    fn factors_weigh_features_that_appear_together() {
        let model = paired_model(2.0);
        let score = |s: &str| model.assess(&url(s), View::Address);
        // Unless the two collide with another feature's row, each alone is 0.5.
        assert!((score("http://paypal.example.net/").score - 0.5).abs() < 0.05);
        assert!((score("http://shop.example.net/login").score - 0.5).abs() < 0.05);
        let both = score("http://paypal.example.net/login");
        assert!((both.score - sigmoid(4.0)).abs() < 0.05, "{}", both.score);
        assert!(
            both.signals
                .contains(&"how the parts of the address go together".to_owned())
        );
    }

    #[test]
    fn damaged_factor_sections_are_refused() {
        let with_factors = |values: Vec<f32>| {
            UrlModel::encode(&ModelParts {
                bits: MIN_BITS,
                bias: 0.0,
                elevated: 0.5,
                high: 0.9,
                weights: vec![0.0; 1 << MIN_BITS],
                suffixes: Suffixes::default(),
                popular: Vec::new(),
                factors: Some(Factors {
                    k: 2,
                    bits: 12,
                    values,
                }),
            })
        };
        let good = with_factors(vec![0.5; 2 << 12]).unwrap();
        assert!(UrlModel::parse(&good).is_ok());
        let at = good.len() - (2 << 12) * 2 - 12;
        let with = |offset: usize, word: [u8; 4]| {
            let mut bad = good.clone();
            bad[at + offset..at + offset + 4].copy_from_slice(&word);
            UrlModel::parse(&bad)
        };
        assert_eq!(
            with(0, 0u32.to_le_bytes()).unwrap_err(),
            ModelError::Value("factor table size")
        );
        assert_eq!(
            with(0, 9u32.to_le_bytes()).unwrap_err(),
            ModelError::Value("factor table size")
        );
        assert_eq!(
            with(4, 30u32.to_le_bytes()).unwrap_err(),
            ModelError::Value("factor table size")
        );
        assert_eq!(
            with(8, f32::NAN.to_le_bytes()).unwrap_err(),
            ModelError::Value("factor scale")
        );
        assert_eq!(
            with(8, (-1f32).to_le_bytes()).unwrap_err(),
            ModelError::Value("factor scale")
        );
        // One row more than the table holds, or one byte short.
        assert!(matches!(
            with(4, 11u32.to_le_bytes()),
            Err(ModelError::Size(_))
        ));
        assert!(matches!(
            UrlModel::parse(&good[..good.len() - 1]),
            Err(ModelError::Size(_))
        ));
        // Values that do not fill the table are refused when written.
        assert!(with_factors(vec![0.5; 3]).is_err());
    }

    #[test]
    fn damaged_sections_are_refused() {
        let parts = |popular: Vec<String>| ModelParts {
            bits: MIN_BITS,
            bias: 0.0,
            elevated: 0.5,
            high: 0.9,
            weights: vec![0.0; 1 << MIN_BITS],
            suffixes: Suffixes::parse("com\nco.uk\n").unwrap(),
            popular,
            factors: None,
        };
        let good = UrlModel::encode(&parts(vec!["a.com".into(), "b.com".into()])).unwrap();
        let mut extra = good.clone();
        extra.push(0);
        assert!(matches!(UrlModel::parse(&extra), Err(ModelError::Size(_))));
        // The two site keys, swapped: no longer sorted.
        let n = good.len();
        let mut swapped = good.clone();
        swapped[n - 16..].copy_from_slice(&[&good[n - 8..], &good[n - 16..n - 8]].concat());
        assert_eq!(
            UrlModel::parse(&swapped).unwrap_err(),
            ModelError::Value("popular sites (not sorted)")
        );
        // A rule with a character no rule has.
        let rules_at = HEADER_BYTES + (2 << MIN_BITS) + 4;
        let mut rule = good.clone();
        rule[rules_at] = b'/';
        assert_eq!(
            UrlModel::parse(&rule).unwrap_err(),
            ModelError::Value("suffix rules")
        );
        // Only the first word of a line is the rule, as in the list itself.
        assert!(Suffixes::parse("*.a*.b\n").is_err());
        assert!(Suffixes::parse("!*.b\n").is_err());
        assert!(Suffixes::parse("Upper.com\n").is_err());
        let mut huge = good.clone();
        huge[rules_at - 4..rules_at].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(UrlModel::parse(&huge), Err(ModelError::Size(_))));
    }

    #[test]
    fn sites_follow_the_public_suffix_rules() {
        let rules = Suffixes::parse(
            "// a comment\ncom\nuk\nco.uk\ndev\nworkers.dev\n*.ck\n!www.ck\n*.compute.example\n",
        )
        .unwrap();
        for (host, site) in [
            ("mail.google.com", "google.com"),
            ("google.com", "google.com"),
            ("bank.example.co.uk", "example.co.uk"),
            ("evil.workers.dev", "evil.workers.dev"),
            ("a.evil.workers.dev", "evil.workers.dev"),
            ("workers.dev", "workers.dev"),
            ("x.y.ck", "x.y.ck"),
            ("www.ck", "www.ck"),
            ("a.www.ck", "www.ck"),
            ("host.region.compute.example", "host.region.compute.example"),
            ("no-rule.zz", "no-rule.zz"),
            ("deep.no-rule.zz", "no-rule.zz"),
            ("com", "com"),
            ("example.com.", "example.com"),
        ] {
            assert_eq!(rules.site(host), site, "{host}");
        }
        assert_eq!(Suffixes::parse(&rules.to_text()).unwrap(), rules);
    }

    #[test]
    fn the_model_abstains_on_the_most_visited_sites() {
        let mut weights = vec![0f32; 1 << MIN_BITS];
        let (i, sign) = Feature {
            kind: Kind::PathWord,
            token: "signin",
            value: 1.0,
        }
        .bucket(MIN_BITS);
        weights[i] = 9.0 * sign;
        let model = UrlModel::parse(
            &UrlModel::encode(&ModelParts {
                bits: MIN_BITS,
                bias: 0.0,
                elevated: 0.5,
                high: 0.9,
                weights,
                suffixes: Suffixes::parse("com\ndev\nworkers.dev\n").unwrap(),
                popular: vec!["google.com".into(), "workers.dev".into()],
                factors: None,
            })
            .unwrap(),
        )
        .unwrap();
        let on = |s: &str| model.assess(&url(s), View::Address);
        let real = on("https://accounts.google.com/signin");
        assert!(
            real.abstained && real.level == Level::Low && real.risk == 0 && real.signals.is_empty(),
            "{real:?}"
        );
        // A site of its own on a hosting platform is judged, and so is a lookalike.
        assert_eq!(on("https://evil.workers.dev/signin").level, Level::High);
        assert_eq!(
            on("https://google.com.evil.example/signin").level,
            Level::High
        );
        assert!(!on("https://evil.workers.dev/signin").abstained);
    }

    #[test]
    fn risk_bands_match_the_levels() {
        // Thresholds 0.5 (elevated) and 0.9 (high).
        let model = model_with(&[], 0.0);
        assert_eq!(model.risk(0.0), 0);
        assert_eq!(model.risk(0.25), 24);
        assert!(model.risk(0.4999) <= 49);
        assert_eq!(model.risk(0.5), 50);
        assert!(model.risk(0.8999) <= 89);
        assert_eq!(model.risk(0.9), 90);
        assert_eq!(model.risk(1.0), 99);
        assert_eq!(model.risk(f32::NAN), 0);
        assert_eq!(model.risk(7.0), 99);
        // Every probability's band agrees with its level.
        for i in 0..=1000u16 {
            let p = f32::from(i) / 1000.0;
            let level = if p >= 0.9 {
                Level::High
            } else if p >= 0.5 {
                Level::Elevated
            } else {
                Level::Low
            };
            let risk = model.risk(p);
            let band = if risk >= 90 {
                Level::High
            } else if risk >= 50 {
                Level::Elevated
            } else {
                Level::Low
            };
            assert_eq!(band, level, "p={p} risk={risk}");
        }
    }

    #[test]
    fn quantization_keeps_scores_close() {
        let mut weights = vec![0f32; 1 << MIN_BITS];
        for (i, w) in weights.iter_mut().enumerate() {
            *w = ((i as f32) * 0.37).sin() * 2.0;
        }
        let parts = ModelParts {
            bits: MIN_BITS,
            bias: -0.3,
            elevated: 0.5,
            high: 0.9,
            weights: weights.clone(),
            suffixes: Suffixes::default(),
            popular: Vec::new(),
            factors: None,
        };
        let model = UrlModel::parse(&UrlModel::encode(&parts).unwrap()).unwrap();
        for s in [
            "https://example.org/",
            "http://a-b-c.example.xyz/login.php?x=1",
            "https://192.0.2.1/",
        ] {
            let u = url(s);
            let mut exact = parts.bias;
            for_each_feature(&u, View::Address, |f| {
                let (i, sign) = f.bucket(MIN_BITS);
                exact += weights[i] * sign * f.value;
            });
            let got = model.assess(&u, View::Address).score;
            assert!(
                (got - sigmoid(exact)).abs() < 1e-3,
                "{s}: {got} vs {}",
                sigmoid(exact)
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn any_url_scores_without_panicking(s in "https?://[a-z0-9.-]{1,40}(/[ -~]{0,80})?") {
            if let Ok(u) = canonicalize(s.as_bytes()) {
                let model = model_with(&[(Kind::HostWord, "a", 1.0)], 0.0);
                for view in [View::Address, View::HostOnly] {
                    let a = model.assess(&u, view);
                    proptest::prop_assert!((0.0..=1.0).contains(&a.score));
                }
            }
        }
    }
}
