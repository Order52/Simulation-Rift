//! Scanning quarantined files and installing intelligence for the Android
//! controller (docs/architecture.md §12, §13).
//!
//! The core does the hash lookup and decides the status; a fresh isolated
//! worker compiles the pack's rules and runs them. Every worker reply is
//! validated against its request, and a worker that misbehaves only costs
//! coverage: the verdict says what did not run.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rift_core::pack::{Confidence, Pack};
use rift_core::scan::{self as verdicts, CacheKey, Check, Evidence, Gap, RuleScan, Status};
use rift_core::snapshot::{InstallCheck, SnapshotStore};
use rift_core::text::escape_for_display;
use rift_protocol::{Envelope, Request, Response, SCAN_ENGINE, WorkerError};

use crate::{Content, ReadFailure, Sessions, decode_reply, envelope, frame};

/// Largest file decrypted for a rule scan; larger ones get the hash check
/// only, and say so.
const MAX_SCAN_INPUT: u64 = 32 * 1024 * 1024;
/// Passed to the worker for YARA-X's own timeout (§12.1 default: 15 s). The
/// controller's backstop is unbinding.
const SCAN_DEADLINE_MS: u32 = 15_000;
const MAX_MATCHES: u16 = 64;

/// Job ids for intelligence installs, which belong to no session.
static NEXT_INTEL_JOB: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ScanStatus {
    KnownMalicious,
    Suspicious,
    NotFlagged,
    NotFullyScanned,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ScanFinding {
    /// "file hash", "rules" or "type".
    pub check: String,
    pub id: String,
    pub source: String,
    pub high_confidence: bool,
    pub description: String,
}

/// A scan result for the trusted UI. Text from the pack is escaped.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Verdict {
    pub file_id: String,
    pub status: ScanStatus,
    /// "Known malicious", "Suspicious", "Not flagged" or "Not fully scanned".
    pub label: String,
    pub findings: Vec<ScanFinding>,
    /// One sentence per check that did not give full coverage.
    pub gaps: Vec<String>,
    /// The threat database the verdict is based on, if any.
    pub snapshot: Option<String>,
    /// The database is a demo and gives no real coverage.
    pub demo: bool,
    pub stale: bool,
    pub engine: String,
}

/// What [`Sessions::scan`] needs the platform to do.
#[derive(Debug, uniffi::Enum)]
pub enum ScanStart {
    /// Decided without a worker: a current cached verdict, no database
    /// installed, or a file too large for a rule scan.
    Done { verdict: Verdict },
    /// Run this job in a fresh isolated worker.
    Run { job: Arc<ScanJob> },
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ScanFailure {
    #[error("the session this file belonged to has ended")]
    SessionEnded,
    #[error("the file is not in this session's quarantine")]
    NotFound,
    #[error("the quarantined copy could not be read: {detail}")]
    Storage { detail: String },
    #[error("the scan worker is not confined: {detail}")]
    Unconfined { detail: String },
    /// The worker's reply failed validation; the worker must be retired.
    #[error("the scan worker sent an invalid reply: {detail}")]
    BadReply { detail: String },
    #[error("session state is unusable after an internal error")]
    Poisoned,
}

impl From<ReadFailure> for ScanFailure {
    fn from(failure: ReadFailure) -> Self {
        match failure {
            ReadFailure::SessionEnded => ScanFailure::SessionEnded,
            ReadFailure::NotFound => ScanFailure::NotFound,
            ReadFailure::Storage(detail) => ScanFailure::Storage { detail },
            ReadFailure::Poisoned => ScanFailure::Poisoned,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum IntelStatus {
    /// No verified threat database is installed.
    Missing,
    Installed {
        snapshot: String,
        digest: String,
        demo: bool,
        stale: bool,
        created_unix: u64,
        refresh_after_unix: u64,
        notices: Vec<String>,
    },
    /// The installed database failed validation and is not used.
    Damaged { detail: String },
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum IntelFailure {
    #[error("the threat database storage failed: {detail}")]
    Storage { detail: String },
    /// Verification or validation refused the update; nothing changed.
    #[error("the update was refused: {detail}")]
    Refused { detail: String },
    #[error("the checking worker is not confined: {detail}")]
    Unconfined { detail: String },
    #[error("the checking worker sent an invalid reply: {detail}")]
    BadReply { detail: String },
    #[error("the update has not passed its rule check")]
    NotChecked,
    #[error("threat database state is unusable after an internal error")]
    Poisoned,
}

/// The installed intelligence snapshot (§13.1).
#[derive(Debug, uniffi::Object)]
pub struct Intel {
    store: SnapshotStore,
    current: Mutex<Result<Option<Arc<Pack>>, String>>,
    datastore: std::path::PathBuf,
}

#[uniffi::export]
impl Intel {
    /// Opens the snapshot store under `dir`, cleaning up interrupted installs.
    #[uniffi::constructor]
    pub fn open(dir: String) -> Result<Arc<Self>, IntelFailure> {
        let root = Path::new(&dir);
        let (store, _) = SnapshotStore::open(root.join("store")).map_err(storage)?;
        let current = store
            .current()
            .map(|p| p.map(Arc::new))
            .map_err(|e| e.to_string());
        Ok(Arc::new(Self {
            store,
            current: Mutex::new(current),
            datastore: root.join("tuf"),
        }))
    }

    pub fn status(&self, now_unix: u64) -> IntelStatus {
        match self.current.lock().as_deref() {
            Err(_) => IntelStatus::Damaged {
                detail: "internal error".into(),
            },
            Ok(Err(detail)) => IntelStatus::Damaged {
                detail: escape_for_display(detail),
            },
            Ok(Ok(None)) => IntelStatus::Missing,
            Ok(Ok(Some(pack))) => IntelStatus::Installed {
                snapshot: escape_for_display(&pack.metadata.snapshot),
                digest: pack.digest.hex(),
                demo: pack.metadata.demo,
                stale: pack.is_stale(now_unix),
                created_unix: pack.metadata.created_unix,
                refresh_after_unix: pack.metadata.refresh_after_unix,
                notices: pack
                    .metadata
                    .notices
                    .iter()
                    .map(|n| escape_for_display(n))
                    .collect(),
            },
        }
    }

    /// Verifies the TUF repository directory `repository` against
    /// `trusted_root` (§13.2). The result is installed only after a fresh
    /// worker has compiled its rules ([`PendingIntel`]).
    pub fn verify_offline(
        self: Arc<Self>,
        trusted_root: Vec<u8>,
        repository: String,
    ) -> Result<Arc<PendingIntel>, IntelFailure> {
        let verified =
            rift_update::verify_offline(&trusted_root, Path::new(&repository), &self.datastore)
                .map_err(|e| IntelFailure::Refused {
                    detail: escape_for_display(&e.to_string()),
                })?;
        let pack = Pack::validate(verified.files.iter().map(|(n, b)| (*n, b.as_slice()))).map_err(
            |e| IntelFailure::Refused {
                detail: escape_for_display(&e.to_string()),
            },
        )?;
        let job = NEXT_INTEL_JOB.fetch_add(2, Ordering::SeqCst);
        let rules = RulesStep::new(job, 0, &pack)?;
        Ok(Arc::new(PendingIntel {
            intel: self,
            files: verified.files,
            pack,
            rules,
            checked: Mutex::new(false),
        }))
    }
}

impl Intel {
    fn pack(&self) -> Option<Arc<Pack>> {
        self.current.lock().ok()?.as_ref().ok()?.clone()
    }
}

/// A verified update waiting for its rule check.
#[derive(Debug, uniffi::Object)]
pub struct PendingIntel {
    intel: Arc<Intel>,
    files: Vec<(&'static str, Vec<u8>)>,
    pack: Pack,
    rules: RulesStep,
    checked: Mutex<bool>,
}

#[uniffi::export]
impl PendingIntel {
    pub fn snapshot(&self) -> String {
        escape_for_display(&self.pack.metadata.snapshot)
    }

    pub fn hello_frame(&self) -> Vec<u8> {
        frame(&self.rules.hello)
    }

    pub fn accept_hello(&self, reply: Vec<u8>) -> Result<(), IntelFailure> {
        self.rules.accept_hello(&reply).map_err(|f| match f {
            StepFailure::Unconfined(detail) => IntelFailure::Unconfined { detail },
            StepFailure::BadReply(detail) => IntelFailure::BadReply { detail },
        })
    }

    pub fn rules(&self) -> Vec<u8> {
        self.pack.rules_source.clone()
    }

    pub fn load_frame(&self) -> Vec<u8> {
        frame(&self.rules.load)
    }

    /// The install check (§13.2): the worker compiled exactly the rules the
    /// metadata describes.
    pub fn accept_load(&self, reply: Vec<u8>) -> Result<(), IntelFailure> {
        self.rules.accept_load(&reply).map_err(|f| match f {
            StepFailure::Unconfined(detail) => IntelFailure::Unconfined { detail },
            StepFailure::BadReply(detail) => IntelFailure::Refused { detail },
        })?;
        *self.checked.lock().map_err(|_| IntelFailure::Poisoned)? = true;
        Ok(())
    }

    /// Makes the checked update current. On failure the old snapshot stays.
    pub fn install(&self, now_unix: u64) -> Result<IntelStatus, IntelFailure> {
        if !*self.checked.lock().map_err(|_| IntelFailure::Poisoned)? {
            return Err(IntelFailure::NotChecked);
        }
        let files = self.files.iter().map(|(n, b)| (*n, b.as_slice()));
        let pack =
            self.intel
                .store
                .install(files, &Checked)
                .map_err(|e| IntelFailure::Refused {
                    detail: escape_for_display(&e.to_string()),
                })?;
        *self
            .intel
            .current
            .lock()
            .map_err(|_| IntelFailure::Poisoned)? = Ok(Some(Arc::new(pack)));
        Ok(self.intel.status(now_unix))
    }
}

/// The worker's rule check already ran (`PendingIntel::accept_load`).
struct Checked;
impl InstallCheck for Checked {
    fn check(&self, _: &Pack) -> Result<(), String> {
        Ok(())
    }
}

/// One file's rule scan by one fresh worker: Hello, LoadRules, then Scan.
#[derive(Debug, uniffi::Object)]
pub struct ScanJob {
    sessions: Arc<Sessions>,
    generation: u64,
    file_id: String,
    object: [u8; 32],
    type_mismatch: Option<(String, String)>,
    pack: Arc<Pack>,
    rules: RulesStep,
    scan: Envelope<Request>,
    input: Vec<u8>,
}

#[uniffi::export]
impl ScanJob {
    pub fn hello_frame(&self) -> Vec<u8> {
        frame(&self.rules.hello)
    }

    pub fn accept_hello(&self, reply: Vec<u8>) -> Result<(), ScanFailure> {
        self.rules.accept_hello(&reply).map_err(scan_failure)
    }

    pub fn rules(&self) -> Vec<u8> {
        self.pack.rules_source.clone()
    }

    pub fn load_frame(&self) -> Vec<u8> {
        frame(&self.rules.load)
    }

    pub fn accept_load(&self, reply: Vec<u8>) -> Result<(), ScanFailure> {
        self.rules.accept_load(&reply).map_err(scan_failure)
    }

    /// The decrypted, hash-verified content for the worker's input descriptor.
    pub fn input(&self) -> Vec<u8> {
        self.input.clone()
    }

    pub fn scan_frame(&self) -> Vec<u8> {
        frame(&self.scan)
    }

    /// Validates the scan reply and records the verdict for this session.
    pub fn finish(&self, reply: Vec<u8>) -> Result<Verdict, ScanFailure> {
        let rules = match decode_reply(&reply, &self.scan)
            .map_err(|detail| ScanFailure::BadReply { detail })?
        {
            Response::ScanResult { matches, truncated } => RuleScan::Completed {
                matched: matches.into_iter().map(|m| m.rule).collect(),
                truncated,
            },
            Response::Error(WorkerError::Timeout) => RuleScan::Failed(Gap::Timeout),
            Response::Error(WorkerError::TooLarge) => RuleScan::Failed(Gap::TooLarge),
            Response::Error(error) => RuleScan::Failed(Gap::Worker(format!("{error:?}"))),
            _ => {
                return Err(ScanFailure::BadReply {
                    detail: "unexpected response to the scan request".into(),
                });
            }
        };
        self.record(rules)
    }

    /// The rule scan did not complete (worker crash, deadline, refused
    /// confinement or an invalid reply): the hash check still counts, and the
    /// verdict names the missing coverage.
    pub fn failed(&self, detail: String) -> Result<Verdict, ScanFailure> {
        self.record(RuleScan::Failed(Gap::Worker(detail)))
    }
}

impl ScanJob {
    fn record(&self, rules: RuleScan) -> Result<Verdict, ScanFailure> {
        let verdict = verdicts::assess(&Evidence {
            object: self.object,
            type_mismatch: self.type_mismatch.clone(),
            pack: Some(&self.pack),
            rules,
            engine: SCAN_ENGINE,
            now_unix: now_unix(),
        });
        self.sessions
            .remember(self.generation, &self.file_id, verdict)
    }
}

fn scan_failure(failure: StepFailure) -> ScanFailure {
    match failure {
        StepFailure::Unconfined(detail) => ScanFailure::Unconfined { detail },
        StepFailure::BadReply(detail) => ScanFailure::BadReply { detail },
    }
}

/// Hello and LoadRules, shared by scans and install checks.
#[derive(Debug)]
struct RulesStep {
    hello: Envelope<Request>,
    load: Envelope<Request>,
    expected_rules: u32,
}

enum StepFailure {
    Unconfined(String),
    BadReply(String),
}

impl RulesStep {
    fn new(job: u64, generation: u64, pack: &Pack) -> Result<Self, IntelFailure> {
        let expected_rules =
            u32::try_from(pack.metadata.rules.len()).map_err(|_| IntelFailure::Refused {
                detail: "too many rules".into(),
            })?;
        Ok(Self {
            hello: envelope(job, generation, Request::Hello),
            load: envelope(
                job.saturating_add(1),
                generation,
                Request::LoadRules {
                    digest: pack.rules_digest,
                },
            ),
            expected_rules,
        })
    }

    /// As for previews: seccomp is required before any input (§8.6).
    fn accept_hello(&self, reply: &[u8]) -> Result<(), StepFailure> {
        match decode_reply(reply, &self.hello).map_err(StepFailure::BadReply)? {
            Response::Ready(confinement) if confinement.seccomp => Ok(()),
            Response::Ready(_) => Err(StepFailure::Unconfined(
                "the worker reports no seccomp filter".into(),
            )),
            _ => Err(StepFailure::BadReply("unexpected response to hello".into())),
        }
    }

    fn accept_load(&self, reply: &[u8]) -> Result<(), StepFailure> {
        match decode_reply(reply, &self.load).map_err(StepFailure::BadReply)? {
            Response::RulesLoaded { rule_count } if rule_count == self.expected_rules => Ok(()),
            Response::RulesLoaded { rule_count } => Err(StepFailure::BadReply(format!(
                "the worker compiled {rule_count} rules, the database describes {}",
                self.expected_rules
            ))),
            Response::Error(error) => Err(StepFailure::BadReply(format!(
                "the rules did not compile: {error:?}"
            ))),
            _ => Err(StepFailure::BadReply(
                "unexpected response to the rules".into(),
            )),
        }
    }
}

#[uniffi::export]
impl Sessions {
    /// Starts a scan of quarantined file `id` (§12.1) with the installed
    /// database. The verdict is kept for this session only.
    pub fn scan(
        self: Arc<Self>,
        generation: u64,
        id: String,
        intel: Arc<Intel>,
    ) -> Result<ScanStart, ScanFailure> {
        let (file, content) = self.read_quarantined(generation, &id, MAX_SCAN_INPUT)?;
        let object: [u8; 32] = hex::decode(&file.sha256)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| ScanFailure::Storage {
                detail: "the stored hash is malformed".into(),
            })?;
        let head = match &content {
            Content::Whole(bytes) | Content::Head(bytes) => bytes.as_slice(),
        };
        // The display name is the normalized one (§11.1); the check reads content.
        let type_mismatch = verdicts::type_mismatch(&file.display_name, head);
        let Some(pack) = intel.pack() else {
            let verdict = verdicts::assess(&Evidence {
                object,
                type_mismatch,
                pack: None,
                rules: RuleScan::Pending,
                engine: SCAN_ENGINE,
                now_unix: now_unix(),
            });
            return Ok(ScanStart::Done {
                verdict: self.remember(generation, &id, verdict)?,
            });
        };
        let key = CacheKey {
            object,
            engine: SCAN_ENGINE.to_owned(),
            pack: Some(pack.digest),
            policy: verdicts::POLICY_VERSION,
        };
        if let Some(verdict) = self.cached(generation, &key)? {
            return Ok(ScanStart::Done {
                verdict: to_ffi(&id, &verdict),
            });
        }
        let input = match content {
            Content::Whole(bytes) => bytes,
            Content::Head(_) => {
                let verdict = verdicts::assess(&Evidence {
                    object,
                    type_mismatch,
                    pack: Some(&pack),
                    rules: RuleScan::Failed(Gap::TooLarge),
                    engine: SCAN_ENGINE,
                    now_unix: now_unix(),
                });
                return Ok(ScanStart::Done {
                    verdict: self.remember(generation, &id, verdict)?,
                });
            }
        };
        let rules_digest = pack.rules_digest;
        let job_id = self.next_job.fetch_add(3, Ordering::SeqCst);
        let rules =
            RulesStep::new(job_id, generation, &pack).map_err(|e| ScanFailure::Storage {
                detail: e.to_string(),
            })?;
        Ok(ScanStart::Run {
            job: Arc::new(ScanJob {
                sessions: self,
                generation,
                file_id: id,
                object,
                type_mismatch,
                pack,
                rules,
                scan: envelope(
                    job_id.saturating_add(2),
                    generation,
                    Request::Scan {
                        rules_digest,
                        max_matches: MAX_MATCHES,
                        deadline_ms: SCAN_DEADLINE_MS,
                    },
                ),
                input,
            }),
        })
    }

    /// The latest verdict recorded for file `id` in this session, if any.
    pub fn verdict(&self, generation: u64, id: String) -> Option<Verdict> {
        let mut state = self.state.lock().ok()?;
        let extras = state.current(generation)?;
        extras
            .verdicts
            .iter()
            .find(|(f, _)| *f == id)
            .map(|(_, v)| v.clone())
    }
}

impl Sessions {
    fn cached(
        &self,
        generation: u64,
        key: &CacheKey,
    ) -> Result<Option<verdicts::Verdict>, ScanFailure> {
        let mut state = self.state.lock().map_err(|_| ScanFailure::Poisoned)?;
        let extras = state.current(generation).ok_or(ScanFailure::SessionEnded)?;
        Ok(extras.cache.current(key).cloned())
    }

    /// Stores a verdict in the session (which drops it at reset) and returns
    /// its display form.
    fn remember(
        &self,
        generation: u64,
        id: &str,
        verdict: verdicts::Verdict,
    ) -> Result<Verdict, ScanFailure> {
        let mut state = self.state.lock().map_err(|_| ScanFailure::Poisoned)?;
        let extras = state.current(generation).ok_or(ScanFailure::SessionEnded)?;
        let shown = to_ffi(id, &verdict);
        extras.cache.insert(verdict);
        extras.verdicts.retain(|(f, _)| f != id);
        extras.verdicts.push((id.to_owned(), shown.clone()));
        Ok(shown)
    }
}

fn to_ffi(id: &str, verdict: &verdicts::Verdict) -> Verdict {
    let check = |c: Check| match c {
        Check::FileHash => "file hash",
        Check::Rules => "rules",
        Check::Type => "type",
    };
    Verdict {
        file_id: id.to_owned(),
        status: match verdict.status {
            Status::KnownMalicious => ScanStatus::KnownMalicious,
            Status::Suspicious => ScanStatus::Suspicious,
            Status::NotFlagged => ScanStatus::NotFlagged,
            // A finished verdict is never pending; if one were, it is not a conclusion.
            Status::NotFullyScanned | Status::Pending => ScanStatus::NotFullyScanned,
        },
        label: verdict.status.label().to_owned(),
        findings: verdict
            .findings
            .iter()
            .map(|f| ScanFinding {
                check: check(f.check).to_owned(),
                id: escape_for_display(&f.id),
                source: escape_for_display(&f.source),
                high_confidence: f.confidence == Confidence::High,
                description: escape_for_display(&f.description),
            })
            .collect(),
        gaps: verdict
            .gaps
            .iter()
            .map(|(c, g)| escape_for_display(&g.explain(*c)))
            .collect(),
        snapshot: verdict.snapshot.as_deref().map(escape_for_display),
        demo: verdict.demo,
        stale: verdict.stale,
        engine: verdict.key.engine.clone(),
    }
}

fn storage(error: impl std::fmt::Display) -> IntelFailure {
    IntelFailure::Storage {
        detail: error.to_string(),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
