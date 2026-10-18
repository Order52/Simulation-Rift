//! Scan verdicts (docs/architecture.md §12.1, §12.3, INV-4).
//!
//! A pure function from evidence to a verdict: the core does the hash lookup
//! itself, a worker reports rule matches, and this module decides what the
//! combination may be called. There is no "safe" status: the best an object
//! can get is "not flagged" by the named checks, with their coverage.
//!
//! Verdicts are cached under `(object SHA-256, engine, pack digest, policy)`.
//! Changed bytes are a new object (S11), and a new pack or engine is a new
//! key (S22), so an old conclusion is never presented as current. It stays
//! available as history.

use std::collections::{BTreeMap, VecDeque};

use crate::pack::{Confidence, Pack, PackDigest};

/// Bumped whenever the mapping below from evidence to status changes.
pub const POLICY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheKey {
    pub object: [u8; 32],
    pub engine: String,
    /// `None` when no verified pack was installed.
    pub pack: Option<PackDigest>,
    pub policy: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    KnownMalicious,
    Suspicious,
    /// Every configured check completed without a match. Not "safe".
    NotFlagged,
    /// A check failed, timed out, or does not cover the content.
    NotFullyScanned,
    /// Rules are still running and nothing conclusive has been found yet.
    Pending,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::KnownMalicious => "Known malicious",
            Status::Suspicious => "Suspicious",
            Status::NotFlagged => "Not flagged",
            Status::NotFullyScanned => "Not fully scanned",
            Status::Pending => "Checking",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    /// SHA-256 against the pack's file table (core).
    FileHash,
    /// YARA-X rules (worker).
    Rules,
    /// Content type against the claimed extension (core).
    Type,
}

/// Why a check did not give full coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    /// No verified intelligence pack is installed.
    NoPack,
    Timeout,
    TooLarge,
    /// The worker failed, crashed, or could not be confined.
    Worker(String),
    /// More rules matched than were reported.
    MatchLimit,
}

impl Gap {
    pub fn explain(&self, check: Check) -> String {
        let what = match check {
            Check::FileHash => "The file-hash check",
            Check::Rules => "The rule scan",
            Check::Type => "The type check",
        };
        match self {
            Gap::NoPack => format!("{what} did not run: no verified threat database is installed."),
            Gap::Timeout => format!("{what} ran out of time."),
            Gap::TooLarge => format!("{what} did not run: the file is larger than it accepts."),
            Gap::Worker(detail) => format!("{what} failed: {detail}."),
            Gap::MatchLimit => format!("{what} stopped reporting after its match limit."),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: Check,
    pub id: String,
    pub source: String,
    pub confidence: Confidence,
    pub description: String,
}

/// The worker's part of the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleScan {
    Pending,
    Completed {
        matched: Vec<String>,
        truncated: bool,
    },
    Failed(Gap),
}

#[derive(Debug)]
pub struct Evidence<'a> {
    pub object: [u8; 32],
    /// (claimed extension, detected type) when they disagree.
    pub type_mismatch: Option<(String, String)>,
    pub pack: Option<&'a Pack>,
    pub rules: RuleScan,
    /// The worker's scan engine (rift-protocol `SCAN_ENGINE`).
    pub engine: &'a str,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub status: Status,
    pub findings: Vec<Finding>,
    pub gaps: Vec<(Check, Gap)>,
    pub key: CacheKey,
    /// The pack's snapshot name, for display.
    pub snapshot: Option<String>,
    pub demo: bool,
    pub stale: bool,
    pub decided_unix: u64,
}

pub fn assess(evidence: &Evidence<'_>) -> Verdict {
    let mut findings = Vec::new();
    let mut gaps = Vec::new();

    if let Some((claimed, detected)) = &evidence.type_mismatch {
        findings.push(Finding {
            check: Check::Type,
            id: "type-mismatch".into(),
            source: "rift".into(),
            confidence: Confidence::Low,
            description: format!("Named as .{claimed}, but the content is {detected}."),
        });
    }

    match evidence.pack {
        None => {
            gaps.push((Check::FileHash, Gap::NoPack));
            gaps.push((Check::Rules, Gap::NoPack));
        }
        Some(pack) => {
            if let Some(indicator) = pack
                .files
                .lookup(&evidence.object)
                .and_then(|meta| pack.indicator(meta))
            {
                findings.push(Finding {
                    check: Check::FileHash,
                    id: indicator.id.clone(),
                    source: indicator.source.clone(),
                    confidence: indicator.confidence,
                    description: indicator.description.clone(),
                });
            }
            match &evidence.rules {
                RuleScan::Pending => {}
                RuleScan::Completed { matched, truncated } => {
                    for rule in matched {
                        findings.push(match pack.rule(rule) {
                            Some(entry) => Finding {
                                check: Check::Rules,
                                id: entry.id.clone(),
                                source: entry.source.clone(),
                                confidence: entry.confidence,
                                description: entry.description.clone(),
                            },
                            // The install smoke test makes this unlikely; if
                            // it happens, the match counts, at low confidence.
                            None => Finding {
                                check: Check::Rules,
                                id: rule.clone(),
                                source: "unknown".into(),
                                confidence: Confidence::Low,
                                description: "A rule the database does not describe matched."
                                    .into(),
                            },
                        });
                    }
                    if *truncated {
                        gaps.push((Check::Rules, Gap::MatchLimit));
                    }
                }
                RuleScan::Failed(gap) => gaps.push((Check::Rules, gap.clone())),
            }
        }
    }

    let pending = evidence.pack.is_some() && evidence.rules == RuleScan::Pending;
    let status = if findings.iter().any(|f| f.confidence == Confidence::High) {
        Status::KnownMalicious
    } else if pending {
        Status::Pending
    } else if !findings.is_empty() {
        Status::Suspicious
    } else if !gaps.is_empty() {
        Status::NotFullyScanned
    } else {
        Status::NotFlagged
    };

    Verdict {
        status,
        findings,
        gaps,
        key: CacheKey {
            object: evidence.object,
            engine: evidence.engine.to_owned(),
            pack: evidence.pack.map(|p| p.digest),
            policy: POLICY_VERSION,
        },
        snapshot: evidence.pack.map(|p| p.metadata.snapshot.clone()),
        demo: evidence.pack.is_some_and(|p| p.metadata.demo),
        stale: evidence.pack.is_some_and(|p| p.is_stale(evidence.now_unix)),
        decided_unix: evidence.now_unix,
    }
}

/// Executable content under a name that promises a document, image or
/// text: the case §12.1 flags. Other mismatches are not reported, because
/// many formats share containers (ZIP, OLE) and would only add noise.
pub fn type_mismatch(display_name: &str, content: &[u8]) -> Option<(String, String)> {
    let detected = if content.starts_with(b"MZ") {
        "a Windows executable"
    } else if content.starts_with(b"\x7fELF") {
        "a Linux or Android executable"
    } else if [
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ]
    .iter()
    .any(|magic| content.starts_with(*magic))
    {
        "a macOS executable"
    } else {
        return None;
    };
    let extension = display_name.rsplit_once('.')?.1.to_ascii_lowercase();
    const HARMLESS_LOOKING: [&str; 16] = [
        "pdf", "txt", "png", "jpg", "jpeg", "gif", "webp", "doc", "docx", "xls", "xlsx", "ppt",
        "pptx", "csv", "rtf", "mp4",
    ];
    HARMLESS_LOOKING
        .contains(&extension.as_str())
        .then(|| (extension, detected.to_owned()))
}

/// Finished verdicts by key, bounded; the oldest entry goes first.
#[derive(Debug)]
pub struct VerdictCache {
    entries: BTreeMap<CacheKey, Verdict>,
    order: VecDeque<CacheKey>,
    capacity: usize,
}

impl VerdictCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// A verdict that is current for `key`, i.e. same bytes, engine, pack and policy.
    pub fn current(&self, key: &CacheKey) -> Option<&Verdict> {
        self.entries.get(key)
    }

    /// Stores a finished verdict. Pending ones are not conclusions and are not kept.
    pub fn insert(&mut self, verdict: Verdict) {
        if verdict.status == Status::Pending {
            return;
        }
        let key = verdict.key.clone();
        if self.entries.insert(key.clone(), verdict).is_none() {
            self.order.push_back(key);
        }
        while self.entries.len() > self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.entries.remove(&oldest);
                }
                None => break,
            }
        }
    }

    /// Earlier verdicts for the same bytes under another engine, pack or
    /// policy: shown as history, never as the current conclusion.
    pub fn history(&self, key: &CacheKey) -> Vec<&Verdict> {
        self.entries
            .values()
            .filter(|v| v.key.object == key.object && v.key != *key)
            .collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::tests::{demo_rule, metadata, pack_files, validate};

    const ENGINE: &str = "yara-x 1.21.0";
    const MARKED: [u8; 32] = [1; 32];
    const OTHER: [u8; 32] = [2; 32];

    fn pack() -> Pack {
        validate(&pack_files(&metadata(demo_rule()), &[(MARKED, 0)])).unwrap()
    }

    fn evidence<'a>(object: [u8; 32], pack: Option<&'a Pack>, rules: RuleScan) -> Evidence<'a> {
        Evidence {
            object,
            type_mismatch: None,
            pack,
            rules,
            engine: ENGINE,
            now_unix: 150,
        }
    }

    fn clean() -> RuleScan {
        RuleScan::Completed {
            matched: vec![],
            truncated: false,
        }
    }

    #[test]
    fn s21_demo_indicator_and_rule_match_with_versions() {
        let pack = pack();
        let by_hash = assess(&evidence(MARKED, Some(&pack), clean()));
        assert_eq!(by_hash.status, Status::KnownMalicious);
        assert_eq!(by_hash.findings[0].check, Check::FileHash);
        assert_eq!(by_hash.findings[0].id, "demo-file");
        assert_eq!(by_hash.key.engine, ENGINE);
        assert_eq!(by_hash.key.pack, Some(pack.digest));
        assert_eq!(by_hash.snapshot.as_deref(), Some("demo-1"));
        assert!(by_hash.demo);

        let by_rule = assess(&evidence(
            OTHER,
            Some(&pack),
            RuleScan::Completed {
                matched: vec!["rift_demo_marker".into()],
                truncated: false,
            },
        ));
        assert_eq!(by_rule.status, Status::KnownMalicious);
        assert_eq!(by_rule.findings[0].source, "rift-demo");
    }

    #[test]
    fn status_never_claims_more_than_the_evidence() {
        let pack = pack();
        let none = assess(&evidence(OTHER, Some(&pack), clean()));
        assert_eq!((none.status, none.gaps.len()), (Status::NotFlagged, 0));

        let no_pack = assess(&evidence(OTHER, None, clean()));
        assert_eq!(no_pack.status, Status::NotFullyScanned);
        assert_eq!(no_pack.gaps.len(), 2);

        let timeout = assess(&evidence(
            OTHER,
            Some(&pack),
            RuleScan::Failed(Gap::Timeout),
        ));
        assert_eq!(timeout.status, Status::NotFullyScanned);

        // A hash hit is conclusive even while rules still run or fail.
        let early = assess(&evidence(MARKED, Some(&pack), RuleScan::Pending));
        assert_eq!(early.status, Status::KnownMalicious);
        let pending = assess(&evidence(OTHER, Some(&pack), RuleScan::Pending));
        assert_eq!(pending.status, Status::Pending);

        let mut mismatch = evidence(OTHER, Some(&pack), clean());
        mismatch.type_mismatch = Some(("pdf".into(), "a Windows executable".into()));
        let mismatch = assess(&mismatch);
        assert_eq!(mismatch.status, Status::Suspicious);
        assert!(mismatch.findings[0].description.contains(".pdf"));

        let unknown = assess(&evidence(
            OTHER,
            Some(&pack),
            RuleScan::Completed {
                matched: vec!["undocumented".into()],
                truncated: true,
            },
        ));
        assert_eq!(unknown.status, Status::Suspicious);
        assert_eq!(unknown.gaps, vec![(Check::Rules, Gap::MatchLimit)]);
    }

    #[test]
    fn stale_packs_are_used_and_marked() {
        let pack = pack();
        let mut late = evidence(MARKED, Some(&pack), clean());
        late.now_unix = 500;
        let verdict = assess(&late);
        assert_eq!(verdict.status, Status::KnownMalicious);
        assert!(verdict.stale);
    }

    #[test]
    fn s11_changed_bytes_do_not_reuse_a_verdict() {
        let pack = pack();
        let mut cache = VerdictCache::new(16);
        cache.insert(assess(&evidence(OTHER, Some(&pack), clean())));
        let changed = assess(&evidence(MARKED, Some(&pack), clean()));
        assert!(cache.current(&changed.key).is_none());
        assert!(cache.history(&changed.key).is_empty());
    }

    #[test]
    fn s22_a_new_pack_or_engine_invalidates_current_verdicts() {
        let old = pack();
        let new = validate(&pack_files(
            &metadata(&format!(
                "{},{}",
                demo_rule(),
                r#"{"id":"rift_demo_hex","source":"rift-demo","confidence":"low","description":"Demo hex"}"#
            )),
            &[(MARKED, 0)],
        ))
        .unwrap();
        assert_ne!(old.digest, new.digest);

        let mut cache = VerdictCache::new(16);
        let before = assess(&evidence(OTHER, Some(&old), clean()));
        cache.insert(before.clone());
        assert_eq!(cache.current(&before.key), Some(&before));

        let after = assess(&evidence(OTHER, Some(&new), RuleScan::Pending));
        assert!(cache.current(&after.key).is_none(), "new pack must rescan");
        assert_eq!(cache.history(&after.key), vec![&before]);

        let mut other_engine = evidence(OTHER, Some(&old), clean());
        other_engine.engine = "yara-x 1.22.0";
        assert!(cache.current(&assess(&other_engine).key).is_none());
    }

    #[test]
    fn executables_named_as_documents_are_flagged() {
        assert_eq!(
            type_mismatch("invoice.PDF", b"MZ\x90\x00"),
            Some(("pdf".into(), "a Windows executable".into()))
        );
        assert!(type_mismatch("photo.jpg", b"\x7fELF\x02").is_some());
        assert!(type_mismatch("notes.txt", b"\xcf\xfa\xed\xfe").is_some());
        assert_eq!(type_mismatch("setup.exe", b"MZ"), None);
        assert_eq!(type_mismatch("invoice.pdf", b"%PDF-1.7"), None);
        assert_eq!(type_mismatch("no-extension", b"MZ"), None);
    }

    #[test]
    fn cache_is_bounded_and_skips_pending() {
        let pack = pack();
        let mut cache = VerdictCache::new(2);
        cache.insert(assess(&evidence(OTHER, Some(&pack), RuleScan::Pending)));
        assert!(cache.is_empty());
        for object in [[3; 32], [4; 32], [5; 32]] {
            cache.insert(assess(&evidence(object, Some(&pack), clean())));
        }
        assert_eq!(cache.len(), 2);
        let first = assess(&evidence([3; 32], Some(&pack), clean()));
        assert!(cache.current(&first.key).is_none());
    }
}
