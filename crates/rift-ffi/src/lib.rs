//! UniFFI bindings for the Android controller (docs/architecture.md §6, §8.3).
//!
//! Only the trusted main process loads this library; `:browser` reaches the
//! core through the main process's Binder interface instead. Everything that
//! crosses into Kotlin is a plain value: keys, stores and other rift-core
//! internals stay on the Rust side.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rift_core::download::{self, DownloadPolicy, DownloadRequest};
use rift_core::heuristics::{HeuristicConfig, SHIPPED_BRANDS};
use rift_core::policy::{self, Decision, IntelState, NavigationContext};
use rift_core::session::{RecoveryReport, SessionError, SessionManager, SessionPlatform};
use rift_core::store::StoredObject;
use rift_protocol::{Envelope, PROTOCOL_VERSION, Request, Response};

uniffi::setup_scaffolding!();

mod ai;
mod applink;
pub use applink::{AppLinkRisk, AppLinkView, explain_app_link};
mod appupdate;
pub use appupdate::{AppRelease, AppUpdateFailure, download_app_release, newer_app_release};
mod egress;
mod filters;
pub use filters::{ContentFilters, FilterFetchFailure, Hiding, fetch_filter_list};
mod intake;
mod link;
mod lists;
mod relay;
pub use ai::{Ai, AiFailure, AiLevel, AiView, LinkCheck};
pub use link::{
    CleanFailure, CleanedLink, LinkCleaner, LinkTrace, TraceHop, TraceOutcome, link_with_https,
    link_without_query,
};
pub use relay::{RelayCheck, RelayFailure, RelaySetting};
mod scan;
pub use egress::{EgressDenial, EgressEndpoint, EgressFailure, EgressRemark, EgressStats};
pub use intake::Intake;
pub use lists::{
    ThreatListChange, ThreatListLoaded, ThreatListText, ThreatLists, compare_threat_lists,
    fetch_threat_list,
};
/// The Linux controller's proxy, from [`Sessions::forwarded_egress`].
pub use rift_core::egress::ForwardedEgress;
pub use scan::{
    Intel, IntelFailure, IntelStatus, PendingIntel, ScanFailure, ScanFinding, ScanJob, ScanStart,
    ScanStatus, Verdict,
};

/// One explainable fact for the trusted UI: `code` is stable, `text` is a
/// sentence in which any web-supplied part has been escaped.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Fact {
    pub code: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Navigation {
    /// Load the page; `notes` belong in the protection details.
    Proceed { notes: Vec<Fact> },
    /// Show the trusted interstitial with `reasons`; load only if the user confirms.
    Confirm {
        reasons: Vec<Fact>,
        notes: Vec<Fact>,
    },
    /// Do not load. `inspect_anyway` allows an explicit per-navigation override.
    Block { reason: Fact, inspect_anyway: bool },
}

/// Main-frame navigation decisions (§10.2–§10.4).
#[derive(Debug, uniffi::Object)]
pub struct Navigator {
    heuristics: HeuristicConfig,
    ai: Option<Arc<Ai>>,
    /// The threat lists Check consults (§10.12); set when they load.
    lists: std::sync::RwLock<Option<Arc<ThreatLists>>>,
    /// The protected brands a page's own name is compared with: the hand-picked ones.
    page_brands: Vec<String>,
}

/// The brands Check protects (§10.3), as the app ships them: hand-picked,
/// and learned from the feeds by the monthly workflow.
#[uniffi::export]
pub fn shipped_brands() -> Vec<String> {
    rift_core::heuristics::parse_brands(SHIPPED_BRANDS)
        .into_iter()
        .map(|b| b.domain)
        .collect()
}

#[uniffi::export]
impl Navigator {
    #[uniffi::constructor]
    pub fn new(protected_domains: Vec<String>, shorteners: Vec<String>) -> Arc<Self> {
        Self::with_ai(protected_domains, shorteners, Vec::new(), None)
    }

    /// As [`Navigator::new`], with the free-hosting platforms to note
    /// (`hosting`) and Rift AI (§16) consulted after the indicators: it can
    /// add a warning or a note, never a block.
    #[uniffi::constructor]
    pub fn with_ai(
        protected_domains: Vec<String>,
        shorteners: Vec<String>,
        hosting: Vec<String>,
        ai: Option<Arc<Ai>>,
    ) -> Arc<Self> {
        // Learned brands protect addresses only (§10.3, §10.5).
        let learned: Vec<String> = rift_core::heuristics::parse_brands(SHIPPED_BRANDS)
            .into_iter()
            .filter(|b| b.learned)
            .map(|b| b.domain)
            .collect();
        let page_brands = protected_domains
            .iter()
            .filter(|d| !learned.contains(d))
            .cloned()
            .collect();
        Arc::new(Self {
            page_brands,
            heuristics: HeuristicConfig {
                protected_domains,
                shorteners,
                hosting,
                ..HeuristicConfig::default()
            },
            ai,
            lists: std::sync::RwLock::new(None),
        })
    }

    /// Decides a navigation to `url`. `sandbox_verified` is the result of the
    /// platform's renderer checks (§8.4); without it everything is blocked.
    /// `intel`'s installed snapshot, if any, is consulted, and its freshness
    /// at `now_unix` is noted; without one every decision says so.
    pub fn decide(
        &self,
        url: String,
        sandbox_verified: bool,
        intel: Option<Arc<Intel>>,
        now_unix: u64,
    ) -> Navigation {
        let pack = intel.and_then(|intel| intel.pack());
        let ctx = NavigationContext {
            sandbox_verified,
            indicators: pack.as_deref().map(|pack| &pack.urls),
            intel_state: match &pack {
                None => IntelState::Missing,
                Some(pack) if pack.is_stale(now_unix) => IntelState::Stale,
                Some(_) => IntelState::Current,
            },
            heuristics: &self.heuristics,
            // A current pack's model replaces the one the app ships.
            model: pack
                .as_ref()
                .and_then(|pack| pack.model.as_deref())
                .or(self.ai.as_deref().map(|ai| &ai.model)),
        };
        match policy::decide_navigation(url.as_bytes(), &ctx) {
            Decision::Proceed { notes } => Navigation::Proceed {
                notes: notes.iter().map(|n| fact(n.code(), n.explain())).collect(),
            },
            Decision::Confirm { reasons, notes } => Navigation::Confirm {
                reasons: reasons
                    .iter()
                    .map(|r| fact(r.code(), r.explain()))
                    .collect(),
                notes: notes.iter().map(|n| fact(n.code(), n.explain())).collect(),
            },
            Decision::Block {
                reason,
                inspect_anyway,
            } => Navigation::Block {
                reason: fact(reason.code(), reason.explain()),
                inspect_anyway,
            },
        }
    }
}

/// One fact about a loaded page (§10.5); `warn` marks those worth an alert.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PageFact {
    pub code: String,
    pub text: String,
    pub warn: bool,
}

#[uniffi::export]
impl Navigator {
    /// What a page at `url` asks for, whether it names itself after a
    /// protected brand on another site, and what Rift AI's page model reads
    /// in `counts` (rift_core::pagemodel::PageCounts as JSON; §16.1). The
    /// facts come from the page and are bounded here; nothing is returned
    /// for an address that does not canonicalize.
    pub fn assess_page(
        &self,
        url: String,
        names: String,
        password: bool,
        card: bool,
        counts: String,
    ) -> Vec<PageFact> {
        let Ok(canonical) = rift_core::urlcanon::canonicalize(url.as_bytes()) else {
            return Vec::new();
        };
        let facts = rift_core::page::PageFacts {
            names,
            password,
            card,
        };
        let mut found: Vec<PageFact> =
            rift_core::page::assess(&canonical, &facts, &self.page_brands)
                .iter()
                .map(|flag| PageFact {
                    code: flag.code().to_owned(),
                    text: flag.explain(canonical.host()),
                    warn: flag.severity() == rift_core::heuristics::Severity::Warn,
                })
                .collect();
        let counts = rift_core::pagemodel::PageCounts::from_report(&counts);
        if let Some(counts) = &counts {
            found.extend(rift_core::page::rules(counts).iter().map(|flag| PageFact {
                code: flag.code().to_owned(),
                text: flag.explain(canonical.host()),
                warn: flag.severity() == rift_core::heuristics::Severity::Warn,
            }));
        }
        if let (Some(model), Some(counts)) = (page_model(), counts) {
            let score = model.score(canonical.host(), &counts);
            if score.level != rift_core::pagemodel::PageLevel::Low {
                found.push(PageFact {
                    code: "page-ai".to_owned(),
                    text: score.explain(canonical.host()),
                    warn: score.level == rift_core::pagemodel::PageLevel::High,
                });
            }
        }
        found
    }
}

/// The shipped page model, read once; None (no page scores) if it is damaged.
fn page_model() -> Option<&'static rift_core::pagemodel::PageModel> {
    static MODEL: std::sync::OnceLock<Option<rift_core::pagemodel::PageModel>> =
        std::sync::OnceLock::new();
    MODEL
        .get_or_init(|| rift_core::pagemodel::PageModel::shipped().ok())
        .as_ref()
}

fn fact(code: &str, text: String) -> Fact {
    Fact {
        code: code.to_owned(),
        text,
    }
}

/// The URL to decide and load for text typed in the address bar.
#[uniffi::export]
pub fn typed_address(input: String) -> String {
    policy::typed_address(&input)
}

/// Display metadata for a server- or user-supplied filename (§11.1).
#[uniffi::export]
pub fn display_name(supplied: String) -> String {
    rift_core::transfer::display_name(&supplied)
}

/// Escapes web-derived text (such as an address) before it is shown in
/// trusted UI, so it cannot reorder or hide the surrounding wording.
#[uniffi::export]
pub fn display_safe(text: String) -> String {
    rift_core::text::escape_for_display(&text)
}

/// Engine-side disposal, implemented by the Android controller (§15 steps
/// 3–5). Called with the session lock held: the implementation may block
/// until the browser process is gone, but must not call back into
/// [`Sessions`].
#[uniffi::export(with_foreign)]
pub trait BrowserDisposal: Send + Sync {
    /// Ends the generation's browser process and deletes its engine data.
    /// Must be idempotent: recovery repeats it after a crash.
    fn destroy_browser_state(&self, generation: u64) -> Result<(), DisposalError>;
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DisposalError {
    #[error("{reason}")]
    Failed { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for DisposalError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed {
            reason: format!("disposal callback failed: {}", error.reason),
        }
    }
}

struct Platform(Arc<dyn BrowserDisposal>);

impl fmt::Debug for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Platform")
    }
}

impl SessionPlatform for Platform {
    fn destroy_browser_state(&mut self, generation: u64) -> Result<(), String> {
        self.0
            .destroy_browser_state(generation)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SessionFailure {
    /// Cleanup did not complete. The session is not reported destroyed, and
    /// the next launch retries before presenting any session as fresh.
    #[error("cleanup of generation {generation} failed: {reason}")]
    CleanupFailed { generation: u64, reason: String },
    #[error("no active session")]
    NoActiveSession,
    #[error("a session is already active")]
    AlreadyActive,
    #[error("session storage failed: {detail}")]
    Storage { detail: String },
    /// A previous call panicked while holding the session state.
    #[error("session state is unusable after an internal error")]
    Poisoned,
}

impl From<SessionError> for SessionFailure {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::CleanupFailed { generation, reason } => {
                Self::CleanupFailed { generation, reason }
            }
            SessionError::NoActiveSession => Self::NoActiveSession,
            SessionError::AlreadyActive => Self::AlreadyActive,
            other @ (SessionError::Storage(_)
            | SessionError::Sealed(_)
            | SessionError::MalformedMarker) => Self::Storage {
                detail: other.to_string(),
            },
        }
    }
}

/// What launch-time recovery found and did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Recovery {
    /// A session was left active or mid-reset by a previous run, and its
    /// cleanup has now completed.
    pub interrupted_generation: Option<u64>,
    pub removed_generations: Vec<u64>,
}

impl From<RecoveryReport> for Recovery {
    fn from(report: RecoveryReport) -> Self {
        Self {
            interrupted_generation: report.interrupted_generation,
            removed_generations: report.removed_generations,
        }
    }
}

/// What `:browser` reported about a download (§8.5).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DownloadInfo {
    pub url: String,
    /// The engine's cookies for `url`; sent only to that URL's origin.
    pub cookie: Option<String>,
    pub user_agent: String,
    pub referer: Option<String>,
    pub content_disposition: Option<String>,
}

/// A committed object in the session's quarantine.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct QuarantinedFile {
    pub id: String,
    /// Normalized display metadata; storage uses `id` only.
    pub display_name: String,
    pub size: u64,
    pub sha256: String,
    /// As the server labelled it, escaped for display.
    pub content_type: Option<String>,
    /// Where the bytes finally came from, escaped for display.
    pub source: String,
    pub redirects: u32,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DownloadFailure {
    /// The download could not be captured safely (§8.5); nothing was stored.
    #[error("{reason}")]
    NotCaptured { reason: String },
    #[error("this session's download quota ({limit} bytes) is used up")]
    QuotaExceeded { limit: u64 },
    /// The session ended before or during the download; the result is discarded.
    #[error("the session this download belonged to has ended")]
    SessionEnded,
    #[error("session state is unusable after an internal error")]
    Poisoned,
}

/// Bytes one session may hold in quarantine (§11.1).
const SESSION_QUOTA: u64 = 500 * 1024 * 1024;

/// Per-session state that dies with the session.
#[derive(Debug)]
struct SessionExtras {
    generation: u64,
    /// Set by reset; downloads stop at their next chunk (§15 step 1).
    cancel: Arc<AtomicBool>,
    local_hosts: Vec<String>,
    /// Hosts of known-malicious links the user chose to open in this
    /// session (§10.4); the proxy lets them through, and only them.
    inspected: Arc<Mutex<Vec<String>>>,
    files: Vec<QuarantinedFile>,
    /// Where each of `files` is stored, for reading it back.
    objects: Vec<StoredObject>,
    /// Committed bytes plus reservations of downloads in progress.
    reserved: u64,
    /// Scan verdicts; they go with the session, like the files they describe.
    cache: rift_core::scan::VerdictCache,
    verdicts: Vec<(String, Verdict)>,
    /// The browser's only way to the network; dropping it closes every tunnel.
    egress: Option<egress::Proxy>,
    /// The proxy's threat-database screen, which the core's own download
    /// fetches go through too.
    screen: Option<Arc<dyn rift_core::egress::Screen>>,
    /// The relay this session's proxy and downloads go through (§8.12),
    /// fixed when the session starts.
    relay: Option<rift_core::relay::Relay>,
}

impl SessionExtras {
    fn new(generation: u64, relay: Option<rift_core::relay::Relay>) -> Self {
        Self {
            generation,
            cancel: Arc::new(AtomicBool::new(false)),
            local_hosts: Vec::new(),
            inspected: Arc::new(Mutex::new(Vec::new())),
            files: Vec::new(),
            objects: Vec::new(),
            reserved: 0,
            cache: rift_core::scan::VerdictCache::new(1024),
            verdicts: Vec::new(),
            egress: None,
            screen: None,
            relay,
        }
    }
}

/// Largest quarantined file decrypted for a preview; it is held in memory
/// in both the controller and the worker.
const MAX_PREVIEW_INPUT: u64 = 32 * 1024 * 1024;

/// How much of a text file is shown.
const MAX_TEXT_PREVIEW: usize = 64 * 1024;

/// A prepared preview.
#[derive(Debug, uniffi::Enum)]
pub enum Preview {
    /// Rendered by an isolated worker.
    Rendered { job: Arc<PreviewJob> },
    /// The start of a text file, with control, bidirectional and invisible
    /// characters (other than line breaks and tabs) shown as escapes.
    Text {
        text: String,
        truncated: bool,
        replaced: bool,
    },
}

/// Passed to the worker; the controller enforces its own deadline by
/// unbinding (§8.6), since an isolated process cannot be killed by the app.
const PREVIEW_DEADLINE_MS: u32 = 10_000;

/// What a quarantined file's content says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PreviewKind {
    /// PNG, JPEG or WebP, decoded by rift-worker.
    Image,
    /// Rendered by the platform's PdfRenderer inside the worker.
    Pdf,
}

/// Identifies previewable content by its leading bytes.
fn sniff(content: &[u8]) -> Option<PreviewKind> {
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
    const JPEG: &[u8] = b"\xff\xd8\xff";
    if content.starts_with(PNG) || content.starts_with(JPEG) {
        return Some(PreviewKind::Image);
    }
    if content.starts_with(b"RIFF") && content.get(8..12) == Some(b"WEBP") {
        return Some(PreviewKind::Image);
    }
    // PDF readers accept the header anywhere in the first KiB.
    let head = content.get(..1024).unwrap_or(content);
    if head.windows(5).any(|w| w == b"%PDF-") {
        return Some(PreviewKind::Pdf);
    }
    None
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PreviewFailure {
    #[error("the session this file belonged to has ended")]
    SessionEnded,
    #[error("the file is not in this session's quarantine")]
    NotFound,
    #[error("Rift previews PNG, JPEG, WebP, PDF and plain-text content only")]
    Unsupported,
    #[error("files larger than {limit} bytes are not previewed")]
    TooLarge { limit: u64 },
    #[error("the quarantined copy could not be read: {detail}")]
    Storage { detail: String },
    /// The worker did not prove the confinement the controller requires.
    #[error("the preview worker is not confined: {detail}")]
    Unconfined { detail: String },
    /// The worker's reply failed validation; the worker must be retired.
    #[error("the preview worker sent an invalid reply: {detail}")]
    BadReply { detail: String },
    /// The worker answered with a typed error.
    #[error("the preview worker could not render the file: {detail}")]
    Worker { detail: String },
    #[error("session state is unusable after an internal error")]
    Poisoned,
}

/// A validated bitmap reply: `width * 4 == stride`, within the requested
/// box and the protocol's size limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct PreviewBitmap {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

/// What a preview belongs to; its result is accepted only while that lasts.
#[derive(Debug)]
enum PreviewOwner {
    /// A quarantined file: the session generation must still be current.
    Session {
        sessions: Arc<Sessions>,
        generation: u64,
    },
}

impl PreviewOwner {
    fn check(&self) -> Result<(), PreviewFailure> {
        match self {
            Self::Session {
                sessions,
                generation,
            } if !sessions.is_current(*generation) => Err(PreviewFailure::SessionEnded),
            _ => Ok(()),
        }
    }
}

/// One preview of one file by one fresh worker. The controller sends
/// `hello_frame`, checks the reply with `accept_hello`, and only then passes
/// `input` and `request_frame`; every reply is validated against the request.
#[derive(Debug, uniffi::Object)]
pub struct PreviewJob {
    owner: PreviewOwner,
    kind: PreviewKind,
    hello: Envelope<Request>,
    request: Envelope<Request>,
    input: Vec<u8>,
}

#[uniffi::export]
impl PreviewJob {
    pub fn kind(&self) -> PreviewKind {
        self.kind
    }

    pub fn hello_frame(&self) -> Vec<u8> {
        frame(&self.hello)
    }

    /// Requires the worker to report seccomp, which Android applies to every
    /// app process; anything else means the process is not what was bound.
    /// The isolation itself is checked by the platform (FLAG_ISOLATED_PROCESS).
    pub fn accept_hello(&self, reply: Vec<u8>) -> Result<(), PreviewFailure> {
        match self.validate(&reply, &self.hello)? {
            Response::Ready(confinement) if confinement.seccomp => Ok(()),
            Response::Ready(_) => Err(PreviewFailure::Unconfined {
                detail: "the worker reports no seccomp filter".into(),
            }),
            Response::Error(error) => Err(PreviewFailure::Unconfined {
                detail: format!("{error:?}"),
            }),
            _ => Err(bad_reply("unexpected response to hello")),
        }
    }

    /// The decrypted, hash-verified file content for the worker's input descriptor.
    pub fn input(&self) -> Vec<u8> {
        self.input.clone()
    }

    pub fn request_frame(&self) -> Vec<u8> {
        frame(&self.request)
    }

    /// Validates the render reply. `region_bytes` is the size of the output
    /// region the controller created; the bitmap must fit in it. Fails if the
    /// session ended meanwhile.
    pub fn accept(
        &self,
        reply: Vec<u8>,
        region_bytes: u64,
    ) -> Result<PreviewBitmap, PreviewFailure> {
        let response = self.validate(&reply, &self.request)?;
        self.owner.check()?;
        match response {
            Response::Bitmap(header) => {
                let expected = u64::from(header.stride).saturating_mul(u64::from(header.height));
                if expected > region_bytes {
                    return Err(bad_reply("the bitmap does not fit the output region"));
                }
                Ok(PreviewBitmap {
                    width: header.width,
                    height: header.height,
                    stride: header.stride,
                })
            }
            Response::Error(error) => Err(PreviewFailure::Worker {
                detail: worker_error_text(error).into(),
            }),
            _ => Err(bad_reply("unexpected response to the render request")),
        }
    }
}

impl PreviewJob {
    fn validate(
        &self,
        reply: &[u8],
        request: &Envelope<Request>,
    ) -> Result<Response, PreviewFailure> {
        decode_reply(reply, request).map_err(|detail| bad_reply(&detail))
    }
}

/// One complete reply frame, validated against the request it answers.
fn decode_reply(reply: &[u8], request: &Envelope<Request>) -> Result<Response, String> {
    let mut reader = reply;
    let body = rift_protocol::read_frame(&mut reader).map_err(|e| e.to_string())?;
    if !reader.is_empty() {
        return Err("trailing bytes after the reply".into());
    }
    rift_protocol::decode_response(&body, request)
        .map(rift_protocol::Validated::into_inner)
        .map_err(|e| e.to_string())
}

fn bad_reply(detail: &str) -> PreviewFailure {
    PreviewFailure::BadReply {
        detail: detail.to_owned(),
    }
}

fn worker_error_text(error: rift_protocol::WorkerError) -> &'static str {
    use rift_protocol::WorkerError as E;
    match error {
        E::Unsupported => "the format or a feature it uses is not supported",
        E::Malformed => "the file is damaged or not what it claims to be",
        E::TooLarge => "the content is too large to preview",
        E::Timeout => "rendering took too long",
        E::Encrypted => "the document is password-protected",
        E::EngineFailure => "the renderer failed",
        E::RulesNotLoaded => "the worker was in an unexpected state",
    }
}

fn envelope(job_id: u64, generation: u64, body: Request) -> Envelope<Request> {
    Envelope {
        version: PROTOCOL_VERSION,
        job_id,
        generation,
        body,
    }
}

/// Requests built here are small and fixed-shape, so encoding cannot fail;
/// an empty frame would be rejected by the worker rather than misread.
fn frame(request: &Envelope<Request>) -> Vec<u8> {
    rift_protocol::encode(request).unwrap_or_default()
}

#[derive(Debug)]
struct State {
    manager: SessionManager<Platform>,
    extras: Option<SessionExtras>,
    /// The relay the next session starts with.
    relay: Option<rift_core::relay::Relay>,
}

impl State {
    fn current(&mut self, generation: u64) -> Option<&mut SessionExtras> {
        self.extras
            .as_mut()
            .filter(|e| e.generation == generation && self.manager.is_current(generation))
    }
}

/// Disposable sessions (§15, INV-8).
#[derive(Debug, uniffi::Object)]
pub struct Sessions {
    state: Mutex<State>,
    recovery: Recovery,
    /// Worker job ids, unique for the life of the process.
    next_job: AtomicU64,
}

#[uniffi::export]
impl Sessions {
    /// Opens the session area under `root` and completes any interrupted
    /// cleanup first. Fails, rather than returning a manager, if that cleanup
    /// still cannot complete, so the UI can show it.
    #[uniffi::constructor]
    pub fn open(
        root: String,
        platform: Arc<dyn BrowserDisposal>,
    ) -> Result<Arc<Self>, SessionFailure> {
        let (manager, report) = SessionManager::open(root, Platform(platform))?;
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                manager,
                extras: None,
                relay: None,
            }),
            recovery: report.into(),
            next_job: AtomicU64::new(1),
        }))
    }

    pub fn recovery(&self) -> Recovery {
        self.recovery.clone()
    }

    /// Starts a session and returns its generation.
    pub fn start(&self) -> Result<u64, SessionFailure> {
        let mut state = self.lock()?;
        let generation = state.manager.start()?.generation();
        let relay = state.relay.clone();
        state.extras = Some(SessionExtras::new(generation, relay));
        Ok(generation)
    }

    /// The relay sessions started from now on send everything through
    /// (§8.12); None sends them direct. A session keeps the relay it
    /// started with, so a change takes effect at the next reset.
    pub fn set_relay(&self, relay: Option<Arc<RelaySetting>>) -> Result<(), SessionFailure> {
        self.lock()?.relay = relay.map(|r| r.relay.clone());
        Ok(())
    }

    /// The relay this session goes through (`ip:port`), if any.
    pub fn session_relay(&self, generation: u64) -> Option<String> {
        let mut state = self.lock().ok()?;
        let relay = state.current(generation)?.relay.as_ref()?;
        Some(relay.address().to_string())
    }

    /// Destroys the active session and returns its generation. Transfers
    /// are cancelled first. Succeeds only after disposal and deletion were
    /// verified.
    pub fn reset(&self) -> Result<u64, SessionFailure> {
        let mut state = self.lock()?;
        if let Some(extras) = state.extras.take() {
            extras.cancel.store(true, Ordering::SeqCst);
            // Before disposal: no tunnel stays open into the next session.
            if let Some(egress) = &extras.egress {
                egress.stop();
            }
        }
        Ok(state.manager.reset()?)
    }

    pub fn current_generation(&self) -> Option<u64> {
        self.lock().ok()?.manager.active().map(|s| s.generation())
    }

    /// True only for the active generation; results tagged with anything
    /// else must be discarded. False if the state is unusable.
    pub fn is_current(&self, generation: u64) -> bool {
        self.lock().is_ok_and(|s| s.manager.is_current(generation))
    }

    /// Lets downloads in this session reach `host` even if it resolves to a
    /// local or private address: the user's explicit exception (INV-13). It
    /// applies to that exact name only and ends with the session.
    pub fn allow_local_host(&self, generation: u64, host: String) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        let Ok(mut state) = self.lock() else {
            return false;
        };
        let Some(extras) = state.current(generation) else {
            return false;
        };
        if !extras.local_hosts.contains(&host) {
            extras.local_hosts.push(host);
        }
        if let Some(egress) = &extras.egress {
            egress.set_local_hosts(extras.local_hosts.clone());
        }
        true
    }

    /// Lets this session open the known-malicious link `url` after the
    /// user's warning (§10.4): its host, and no other listed one, passes
    /// the proxy's threat-database check. Call it on a session that has
    /// loaded nothing yet; it ends with the session.
    pub fn allow_inspection(&self, generation: u64, url: String) -> bool {
        let Ok(canonical) = rift_core::urlcanon::canonicalize(url.as_bytes()) else {
            return false;
        };
        // Canonical forms assume http when there is no scheme: check the link itself.
        let lower = url.trim_start().to_ascii_lowercase();
        let web = lower.starts_with("http://") || lower.starts_with("https://");
        if !web || canonical.host().is_empty() {
            return false;
        }
        let Ok(mut state) = self.lock() else {
            return false;
        };
        let Some(extras) = state.current(generation) else {
            return false;
        };
        let Ok(mut inspected) = extras.inspected.lock() else {
            return false;
        };
        let host = canonical.host().to_owned();
        if !inspected.contains(&host) {
            inspected.push(host);
        }
        true
    }

    /// Whether `url`'s host was allowed by [`Sessions::allow_inspection`] in `generation`.
    pub fn is_inspected(&self, generation: u64, url: String) -> bool {
        let Ok(canonical) = rift_core::urlcanon::canonicalize(url.as_bytes()) else {
            return false;
        };
        let Ok(mut state) = self.lock() else {
            return false;
        };
        state
            .current(generation)
            .and_then(|e| {
                e.inspected
                    .lock()
                    .ok()
                    .map(|i| i.iter().any(|h| h == canonical.host()))
            })
            .unwrap_or(false)
    }

    pub fn local_hosts(&self, generation: u64) -> Vec<String> {
        self.lock()
            .ok()
            .and_then(|mut s| s.current(generation).map(|e| e.local_hosts.clone()))
            .unwrap_or_default()
    }

    /// The session's committed quarantine objects, newest last.
    pub fn quarantine(&self, generation: u64) -> Vec<QuarantinedFile> {
        self.lock()
            .ok()
            .and_then(|mut s| s.current(generation).map(|e| e.files.clone()))
            .unwrap_or_default()
    }

    /// Fetches a download the engine reported into this session's encrypted
    /// quarantine (§8.5). Blocks for the whole transfer: call it off the UI
    /// thread. The result is kept only if `generation` is still current.
    pub fn download(
        &self,
        generation: u64,
        info: DownloadInfo,
    ) -> Result<QuarantinedFile, DownloadFailure> {
        let poisoned = |_| DownloadFailure::Poisoned;
        let (store, recipient, cancel, policy) = {
            let mut state = self.state.lock().map_err(poisoned)?;
            let session = state
                .manager
                .active()
                .filter(|s| s.generation() == generation)
                .map(|s| (s.quarantine().clone(), s.quarantine_key().recipient()))
                .ok_or(DownloadFailure::SessionEnded)?;
            let extras = state
                .current(generation)
                .ok_or(DownloadFailure::SessionEnded)?;
            let room = SESSION_QUOTA.saturating_sub(extras.reserved);
            let policy = DownloadPolicy {
                local_hosts: extras.local_hosts.clone(),
                max_bytes: room.min(DownloadPolicy::default().max_bytes),
                screen: extras.screen.clone(),
                relay: extras.relay.clone(),
                ..DownloadPolicy::default()
            };
            if policy.max_bytes == 0 {
                return Err(DownloadFailure::QuotaExceeded {
                    limit: SESSION_QUOTA,
                });
            }
            extras.reserved = extras.reserved.saturating_add(policy.max_bytes);
            (session.0, session.1, extras.cancel.clone(), policy)
        };

        let request = DownloadRequest {
            url: &info.url,
            cookie: info.cookie.as_deref(),
            user_agent: &info.user_agent,
            referer: info.referer.as_deref(),
            engine_disposition: info.content_disposition.as_deref(),
        };
        let result = download::download(&request, &policy, &store, &recipient, &cancel);

        let mut state = self.state.lock().map_err(poisoned)?;
        let Some(extras) = state.current(generation) else {
            // Reset ran meanwhile: its directory, and anything committed in
            // it, is already deleted. Never report it as part of a new session.
            return Err(DownloadFailure::SessionEnded);
        };
        let downloaded = match result {
            Ok(downloaded) => downloaded,
            Err(error) => {
                extras.reserved = extras.reserved.saturating_sub(policy.max_bytes);
                return Err(DownloadFailure::NotCaptured {
                    reason: rift_core::text::escape_for_display(&error.to_string()),
                });
            }
        };
        let unused = policy
            .max_bytes
            .saturating_sub(downloaded.object.sealed.size);
        extras.reserved = extras.reserved.saturating_sub(unused);
        let file = QuarantinedFile {
            id: downloaded.object.id.to_hex(),
            display_name: downloaded.display_name,
            size: downloaded.object.sealed.size,
            sha256: hex::encode(downloaded.object.sealed.sha256),
            content_type: downloaded
                .content_type
                .as_deref()
                .map(rift_core::text::escape_for_display),
            source: rift_core::text::escape_for_display(&downloaded.final_url),
            redirects: u32::try_from(downloaded.redirects).unwrap_or(u32::MAX),
        };
        extras.files.push(file.clone());
        extras.objects.push(downloaded.object);
        Ok(file)
    }

    /// Prepares a preview of quarantined file `id` (§8.6, §11.2): decrypts
    /// and verifies it, and identifies the format from its content, never
    /// from its name or the server's label. Images and PDFs get a job that
    /// frames the worker requests and checks every reply; text is returned
    /// as bounded, escaped plain text.
    pub fn preview(
        self: Arc<Self>,
        generation: u64,
        id: String,
        max_width: u32,
        max_height: u32,
    ) -> Result<Preview, PreviewFailure> {
        let (_, input) = match self.read_quarantined(generation, &id, MAX_PREVIEW_INPUT)? {
            (file, Content::Whole(input)) => (file, input),
            (_, Content::Head(_)) => {
                return Err(PreviewFailure::TooLarge {
                    limit: MAX_PREVIEW_INPUT,
                });
            }
        };
        let job_id = self.next_job.fetch_add(1, Ordering::SeqCst);
        let owner = PreviewOwner::Session {
            sessions: self,
            generation,
        };
        prepare_preview(owner, generation, job_id, input, max_width, max_height)
    }
}

/// Identifies `input` from its content, never from its name or label:
/// images and PDFs get a job for a fresh worker, text is returned as
/// bounded, escaped plain text. `generation` goes into the request
/// envelopes, which the replies must match.
fn prepare_preview(
    owner: PreviewOwner,
    generation: u64,
    job_id: u64,
    input: Vec<u8>,
    max_width: u32,
    max_height: u32,
) -> Result<Preview, PreviewFailure> {
    let Some(kind) = sniff(&input) else {
        // Plain text is decoded here, in memory-safe code with a bound,
        // and never interpreted (§11.2).
        return rift_core::text::plain_text(&input, MAX_TEXT_PREVIEW)
            .map(|t| Preview::Text {
                text: t.text,
                truncated: t.truncated,
                replaced: t.replaced,
            })
            .ok_or(PreviewFailure::Unsupported);
    };
    let request = match kind {
        PreviewKind::Image => Request::DecodeImage {
            max_width,
            max_height,
            deadline_ms: PREVIEW_DEADLINE_MS,
        },
        PreviewKind::Pdf => Request::RenderPdfPage {
            page: 0,
            max_width,
            max_height,
            deadline_ms: PREVIEW_DEADLINE_MS,
        },
    };
    Ok(Preview::Rendered {
        job: Arc::new(PreviewJob {
            owner,
            kind,
            hello: envelope(job_id, generation, Request::Hello),
            request: envelope(job_id.saturating_add(1), generation, request),
            input,
        }),
    })
}

impl Sessions {
    fn lock(&self) -> Result<MutexGuard<'_, State>, SessionFailure> {
        self.state.lock().map_err(|_| SessionFailure::Poisoned)
    }

    /// Decrypts and verifies quarantined file `id`. Content over `limit` is
    /// still read through (so its integrity is checked) but only its first
    /// bytes are kept. Runs under the lock (the key never leaves the
    /// session), so a reset waits for this bounded local read.
    fn read_quarantined(
        &self,
        generation: u64,
        id: &str,
        limit: u64,
    ) -> Result<(QuarantinedFile, Content), ReadFailure> {
        let mut state = self.state.lock().map_err(|_| ReadFailure::Poisoned)?;
        let extras = state.current(generation).ok_or(ReadFailure::SessionEnded)?;
        let index = extras
            .objects
            .iter()
            .position(|o| o.id.to_hex() == id)
            .ok_or(ReadFailure::NotFound)?;
        let (Some(object), Some(file)) = (
            extras.objects.get(index).copied(),
            extras.files.get(index).cloned(),
        ) else {
            return Err(ReadFailure::NotFound);
        };
        let session = state.manager.active().ok_or(ReadFailure::SessionEnded)?;
        let storage = |e: rift_core::seal::SealError| ReadFailure::Storage(e.to_string());
        let content = if object.sealed.size > limit {
            let mut head = Head(Vec::new());
            session
                .quarantine()
                .read(
                    object.id,
                    session.quarantine_key(),
                    &object.sealed,
                    &mut head,
                )
                .map_err(storage)?;
            Content::Head(head.0)
        } else {
            let mut whole = Vec::new();
            session
                .quarantine()
                .read(
                    object.id,
                    session.quarantine_key(),
                    &object.sealed,
                    &mut whole,
                )
                .map_err(storage)?;
            Content::Whole(whole)
        };
        Ok((file, content))
    }
}

/// A quarantined file's plaintext: all of it, or only its first bytes.
enum Content {
    Whole(Vec<u8>),
    Head(Vec<u8>),
}

/// Keeps the first [`HEAD_BYTES`] written and discards the rest.
struct Head(Vec<u8>);
const HEAD_BYTES: usize = 64;

impl std::io::Write for Head {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let room = HEAD_BYTES.saturating_sub(self.0.len());
        self.0
            .extend_from_slice(buf.get(..room.min(buf.len())).unwrap_or_default());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
enum ReadFailure {
    SessionEnded,
    NotFound,
    Storage(String),
    Poisoned,
}

impl From<ReadFailure> for PreviewFailure {
    fn from(failure: ReadFailure) -> Self {
        match failure {
            ReadFailure::SessionEnded => PreviewFailure::SessionEnded,
            ReadFailure::NotFound => PreviewFailure::NotFound,
            ReadFailure::Storage(detail) => PreviewFailure::Storage { detail },
            ReadFailure::Poisoned => PreviewFailure::Poisoned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    #[derive(Default)]
    struct FakeDisposal {
        destroyed: AtomicU64,
        fail: AtomicBool,
    }

    impl BrowserDisposal for FakeDisposal {
        fn destroy_browser_state(&self, generation: u64) -> Result<(), DisposalError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(DisposalError::Failed {
                    reason: "browser process still alive".into(),
                });
            }
            self.destroyed.store(generation, Ordering::SeqCst);
            Ok(())
        }
    }

    fn root(dir: &tempfile::TempDir) -> String {
        dir.path().to_string_lossy().into_owned()
    }

    #[derive(Debug)]
    struct Yes;
    impl RelayCheck for Yes {
        fn trusted(&self, _: u16, _: u16) -> bool {
            true
        }
    }

    #[test]
    fn a_relay_setting_takes_effect_at_the_next_session() {
        assert!(matches!(
            RelaySetting::new("127.0.0.1:9050".into(), None),
            Err(RelayFailure::Refused { .. })
        ));
        assert!(matches!(
            RelaySetting::new("10.0.0.2:1080".into(), None),
            Err(RelayFailure::Refused { .. })
        ));
        assert!(matches!(
            RelaySetting::new("relay.example:1080".into(), None),
            Err(RelayFailure::Address { .. })
        ));
        let orbot = RelaySetting::new("127.0.0.1:9050".into(), Some(Arc::new(Yes))).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let first = sessions.start().unwrap();
        sessions.set_relay(Some(orbot)).unwrap();
        assert_eq!(
            sessions.session_relay(first),
            None,
            "a session keeps its relay"
        );
        sessions.reset().unwrap();
        let second = sessions.start().unwrap();
        assert_eq!(
            sessions.session_relay(second).as_deref(),
            Some("127.0.0.1:9050")
        );
        sessions.set_relay(None).unwrap();
        sessions.reset().unwrap();
        let third = sessions.start().unwrap();
        assert_eq!(sessions.session_relay(third), None);
    }

    #[test]
    fn decisions_carry_codes_and_sentences() {
        let navigator = Navigator::new(vec!["paypal.com".into()], vec!["bit.ly".into()]);
        assert_eq!(
            navigator.decide("https://example.org/".into(), false, None, 0),
            Navigation::Block {
                reason: Fact {
                    code: "sandbox-unavailable".into(),
                    text: rift_core::policy::BlockReason::SandboxUnavailable.explain(),
                },
                inspect_anyway: false,
            }
        );
        match navigator.decide("https://paypa1.com/login".into(), true, None, 0) {
            Navigation::Confirm { reasons, notes } => {
                assert_eq!(reasons.first().map(|r| r.code.as_str()), Some("lookalike"));
                assert!(notes.iter().any(|n| n.code == "intel-missing"));
            }
            other => panic!("expected confirm, got {other:?}"),
        }
        match navigator.decide("intent://scan/#Intent;end".into(), true, None, 0) {
            Navigation::Block { reason, .. } => assert_eq!(reason.code, "scheme-not-allowed"),
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn session_lifecycle_and_generation_checks() {
        let dir = tempfile::tempdir().unwrap();
        let disposal = Arc::new(FakeDisposal::default());
        let sessions = Sessions::open(root(&dir), disposal.clone()).unwrap();
        assert_eq!(sessions.recovery().interrupted_generation, None);
        assert_eq!(sessions.current_generation(), None);

        let first = sessions.start().unwrap();
        assert!(sessions.is_current(first));
        assert!(matches!(
            sessions.start(),
            Err(SessionFailure::AlreadyActive)
        ));
        assert_eq!(sessions.reset().unwrap(), first);
        assert_eq!(disposal.destroyed.load(Ordering::SeqCst), first);
        assert!(!sessions.is_current(first));

        let second = sessions.start().unwrap();
        assert!(second > first);
    }

    #[test]
    fn failed_disposal_is_reported_and_recovered_on_next_open() {
        let dir = tempfile::tempdir().unwrap();
        let disposal = Arc::new(FakeDisposal::default());
        let sessions = Sessions::open(root(&dir), disposal.clone()).unwrap();
        let generation = sessions.start().unwrap();

        disposal.fail.store(true, Ordering::SeqCst);
        assert!(matches!(
            sessions.reset(),
            Err(SessionFailure::CleanupFailed { generation: g, .. }) if g == generation
        ));
        drop(sessions);
        // Still failing: opening refuses rather than presenting a fresh session.
        assert!(matches!(
            Sessions::open(root(&dir), disposal.clone()),
            Err(SessionFailure::CleanupFailed { .. })
        ));

        disposal.fail.store(false, Ordering::SeqCst);
        let reopened = Sessions::open(root(&dir), disposal.clone()).unwrap();
        assert_eq!(reopened.recovery().interrupted_generation, Some(generation));
        assert!(reopened.start().unwrap() > generation);
    }

    /// A signed demo repository, as a maintainer would publish it.
    fn demo_repository(dir: &std::path::Path) -> (Vec<u8>, String) {
        let keys = dir.join("keys");
        let pack = dir.join("pack");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::create_dir(&pack).unwrap();
        rift_pack::generate_keys(&keys).unwrap();
        let root = dir.join("root.json");
        let now = jiff::Timestamp::now();
        let year = now
            .checked_add(jiff::SignedDuration::from_hours(24 * 365))
            .unwrap();
        let one = std::num::NonZeroU64::MIN;
        rift_pack::init_root(&keys, one, year, &root).unwrap();
        (std::fs::read(&root).unwrap(), publish_demo(dir, one, now))
    }

    /// Publishes a demo pack created at `created` as `version` of the
    /// repository that [`demo_repository`] set up in `dir`.
    fn publish_demo(
        dir: &std::path::Path,
        version: std::num::NonZeroU64,
        created: jiff::Timestamp,
    ) -> String {
        let pack = dir.join(format!("pack-{version}"));
        std::fs::create_dir(&pack).unwrap();
        rift_pack::write_demo_pack(&pack, created).unwrap();
        let repo = dir.join(format!("repo-{version}"));
        let release = rift_pack::Release::standard(version, jiff::Timestamp::now()).unwrap();
        rift_pack::publish(
            &dir.join("root.json"),
            &dir.join("keys"),
            &pack,
            &repo,
            &release,
        )
        .unwrap();
        repo.to_string_lossy().into_owned()
    }

    #[test]
    fn a_signed_packs_model_replaces_the_shipped_one() {
        use rift_core::urlmodel::{MIN_BITS, ModelParts, Suffixes, UrlModel};
        let dir = tempfile::tempdir().unwrap();
        let publisher = dir.path().join("publisher");
        let (trusted_root, first) = demo_repository(&publisher);
        let intel = Intel::open(dir.path().join("intel").to_string_lossy().into_owned()).unwrap();
        let shipped = Ai::load(include_bytes!("../../../models/url-model.bin").to_vec()).unwrap();
        let navigator = Navigator::with_ai(Vec::new(), Vec::new(), Vec::new(), Some(shipped));
        let level = |intel: &Arc<Intel>| {
            let check = navigator.check(
                "https://www.uotechnology.edu.iq/".into(),
                Some(intel.clone()),
                0,
            );
            check.ai.unwrap().level
        };
        install(&intel, trusted_root.clone(), first);
        assert_eq!(intel.ai_digest(), None);
        assert_eq!(level(&intel), ai::AiLevel::Low);

        // Version 2 carries a model that rates every address High.
        let model = UrlModel::encode(&ModelParts {
            bits: MIN_BITS,
            bias: 8.0,
            elevated: 0.5,
            high: 0.9,
            weights: vec![0.0; 1 << MIN_BITS],
            suffixes: Suffixes::default(),
            popular: Vec::new(),
            factors: None,
        })
        .unwrap();
        let pack = publisher.join("pack-model");
        std::fs::create_dir(&pack).unwrap();
        let later = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_secs(1))
            .unwrap();
        rift_pack::write_demo_pack(&pack, later).unwrap();
        std::fs::write(pack.join(rift_core::pack::MODEL), &model).unwrap();
        let repo = publisher.join("repo-model");
        let two = std::num::NonZeroU64::new(2).unwrap();
        let release = rift_pack::Release::standard(two, jiff::Timestamp::now()).unwrap();
        rift_pack::publish(
            &publisher.join("root.json"),
            &publisher.join("keys"),
            &pack,
            &repo,
            &release,
        )
        .unwrap();
        install(&intel, trusted_root, repo.to_string_lossy().into_owned());
        let digest = UrlModel::parse(&model).unwrap().digest_hex();
        assert_eq!(intel.ai_digest(), Some(digest.clone()));
        assert_eq!(level(&intel), ai::AiLevel::High);
        // A restart reads the same model back from the installed snapshot.
        let reopened =
            Intel::open(dir.path().join("intel").to_string_lossy().into_owned()).unwrap();
        assert_eq!(reopened.ai_digest(), Some(digest));
    }

    /// Verifies and installs `repo`, with the rule check run by a confined worker.
    fn install(intel: &Arc<Intel>, trusted_root: Vec<u8>, repo: String) -> IntelStatus {
        use rift_worker_ffi::WorkerEngine;
        let pending = intel.clone().verify_offline(trusted_root, repo).unwrap();
        let checker = WorkerEngine::new(true, false);
        pending
            .accept_hello(checker.handle(pending.hello_frame(), None).frame)
            .unwrap();
        pending
            .accept_load(
                checker
                    .handle(pending.load_frame(), Some(pending.rules()))
                    .frame,
            )
            .unwrap();
        pending.install(0).unwrap()
    }

    /// Runs `job` to completion in a confined worker.
    fn run_scan(job: &ScanJob) -> Verdict {
        use rift_worker_ffi::WorkerEngine;
        let worker = WorkerEngine::new(true, false);
        job.accept_hello(worker.handle(job.hello_frame(), None).frame)
            .unwrap();
        job.accept_load(worker.handle(job.load_frame(), Some(job.rules())).frame)
            .unwrap();
        job.finish(worker.handle(job.scan_frame(), Some(job.input())).frame)
            .unwrap()
    }

    #[test]
    fn a_running_scan_keeps_the_snapshot_it_started_with() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let generation = sessions.start().unwrap();
        assert!(sessions.allow_local_host(generation, "localhost".into()));
        let demo = sessions
            .download(
                generation,
                info(format!("http://localhost:{}/", serve(rift_pack::DEMO_FILE))),
            )
            .unwrap();
        let intel = Intel::open(dir.path().join("intel").to_string_lossy().into_owned()).unwrap();
        let publisher = dir.path().join("publisher");
        let (trusted_root, first) = demo_repository(&publisher);
        let snapshot_of = |status: IntelStatus| match status {
            IntelStatus::Installed { snapshot, .. } => snapshot,
            other => panic!("not installed: {other:?}"),
        };
        let one = snapshot_of(install(&intel, trusted_root.clone(), first));

        let Ok(ScanStart::Run { job }) =
            sessions
                .clone()
                .scan(generation, demo.id.clone(), intel.clone())
        else {
            panic!("expected a worker job");
        };
        // A newer database is installed while the job waits for its worker.
        let later = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_secs(1))
            .unwrap();
        let second = publish_demo(&publisher, std::num::NonZeroU64::new(2).unwrap(), later);
        let two = snapshot_of(install(&intel, trusted_root, second));
        assert_ne!(one, two);
        // The job's rules, tables and verdict are the snapshot it started with.
        let pinned = run_scan(&job);
        assert_eq!(pinned.snapshot.as_deref(), Some(one.as_str()));
        assert_eq!(pinned.status, ScanStatus::KnownMalicious);
        // Its verdict is not current for the new snapshot: the next scan runs again.
        let Ok(ScanStart::Run { job }) = sessions.clone().scan(generation, demo.id, intel) else {
            panic!("expected a new worker job for the new snapshot");
        };
        assert_eq!(run_scan(&job).snapshot.as_deref(), Some(two.as_str()));
    }

    #[test]
    fn scans_combine_the_core_hash_check_with_a_validated_worker() {
        use rift_worker_ffi::WorkerEngine;
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let generation = sessions.start().unwrap();
        assert!(sessions.allow_local_host(generation, "localhost".into()));
        let get = |body: &'static [u8]| {
            sessions
                .download(
                    generation,
                    info(format!("http://localhost:{}/", serve(body))),
                )
                .unwrap()
        };
        let demo = get(rift_pack::DEMO_FILE);
        let clean = get(b"an ordinary report");
        let other = get(b"another ordinary report");

        // No database: nothing runs, and the verdict says what is missing.
        let intel = Intel::open(dir.path().join("intel").to_string_lossy().into_owned()).unwrap();
        assert_eq!(intel.status(0), IntelStatus::Missing);
        let Ok(ScanStart::Done { verdict }) =
            sessions
                .clone()
                .scan(generation, demo.id.clone(), intel.clone())
        else {
            panic!("expected a decision without a worker");
        };
        assert_eq!(verdict.status, ScanStatus::NotFullyScanned);
        assert_eq!(verdict.gaps.len(), 2);

        // Install: verified, then the rules must compile in a confined worker.
        let (trusted_root, repo) = demo_repository(&dir.path().join("publisher"));
        let pending = intel
            .clone()
            .verify_offline(trusted_root.clone(), repo.clone())
            .unwrap();
        assert!(matches!(pending.install(0), Err(IntelFailure::NotChecked)));
        let unconfined = WorkerEngine::new(false, false);
        assert!(matches!(
            pending.accept_hello(unconfined.handle(pending.hello_frame(), None).frame),
            Err(IntelFailure::Unconfined { .. })
        ));
        let checker = WorkerEngine::new(true, false);
        pending
            .accept_hello(checker.handle(pending.hello_frame(), None).frame)
            .unwrap();
        pending
            .accept_load(
                checker
                    .handle(pending.load_frame(), Some(pending.rules()))
                    .frame,
            )
            .unwrap();
        assert!(matches!(
            pending.install(0),
            Ok(IntelStatus::Installed { demo: true, .. })
        ));

        // The demo file: hash (core) and rule (worker) both find it.
        let Ok(ScanStart::Run { job }) =
            sessions
                .clone()
                .scan(generation, demo.id.clone(), intel.clone())
        else {
            panic!("expected a worker job");
        };
        assert_eq!(job.input(), rift_pack::DEMO_FILE);
        let worker = WorkerEngine::new(true, false);
        let hello = worker.handle(job.hello_frame(), None).frame;
        job.accept_hello(hello.clone()).unwrap();
        job.accept_load(worker.handle(job.load_frame(), Some(job.rules())).frame)
            .unwrap();
        // A reply to another request is refused.
        assert!(matches!(
            job.finish(hello),
            Err(ScanFailure::BadReply { .. })
        ));
        let verdict = job
            .finish(worker.handle(job.scan_frame(), Some(job.input())).frame)
            .unwrap();
        assert_eq!(verdict.status, ScanStatus::KnownMalicious);
        let checks: Vec<&str> = verdict.findings.iter().map(|f| f.check.as_str()).collect();
        assert_eq!(checks, ["file hash", "rules"]);
        assert!(verdict.demo);
        assert_eq!(verdict.engine, rift_protocol::SCAN_ENGINE);
        assert_eq!(
            sessions.verdict(generation, demo.id.clone()),
            Some(verdict.clone())
        );
        // Same bytes, same database and engine: the verdict is current.
        assert!(matches!(
            sessions.clone().scan(generation, demo.id.clone(), intel.clone()),
            Ok(ScanStart::Done { verdict: v }) if v == verdict
        ));

        // A clean file is "not flagged", never "safe".
        let Ok(ScanStart::Run { job }) =
            sessions
                .clone()
                .scan(generation, clean.id.clone(), intel.clone())
        else {
            panic!("expected a worker job");
        };
        let worker = WorkerEngine::new(true, false);
        job.accept_hello(worker.handle(job.hello_frame(), None).frame)
            .unwrap();
        job.accept_load(worker.handle(job.load_frame(), Some(job.rules())).frame)
            .unwrap();
        let verdict = job
            .finish(worker.handle(job.scan_frame(), Some(job.input())).frame)
            .unwrap();
        assert_eq!(
            (verdict.status, verdict.label.as_str()),
            (ScanStatus::NotFlagged, "Not flagged")
        );

        // A worker that dies costs coverage, not the hash check.
        let Ok(ScanStart::Run { job }) =
            sessions
                .clone()
                .scan(generation, other.id.clone(), intel.clone())
        else {
            panic!("expected a worker job");
        };
        let verdict = job
            .failed("the scan worker stopped unexpectedly".into())
            .unwrap();
        assert_eq!(verdict.status, ScanStatus::NotFullyScanned);
        assert!(verdict.gaps[0].contains("stopped unexpectedly"));

        // Verdicts end with the session.
        let next = sessions.reset().unwrap();
        assert_eq!(sessions.verdict(next, demo.id), None);
    }

    /// Serves one fixed response per connection on 127.0.0.1.
    fn serve(body: &'static [u8]) -> u16 {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                    line.clear();
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Disposition: attachment; filename=\"r\u{202e}fdp.exe\"\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
            }
        });
        port
    }

    fn info(url: String) -> DownloadInfo {
        DownloadInfo {
            url,
            cookie: None,
            user_agent: "rift-test".into(),
            referer: None,
            content_disposition: None,
        }
    }

    /// Sends a CONNECT with this endpoint's credentials and returns the status line.
    fn connect_through(endpoint: &EgressEndpoint, target: &str) -> std::io::Result<String> {
        use std::io::{BufRead, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", endpoint.port))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let credentials = rift_core::egress::proxy_authorization(&endpoint.token);
        stream.write_all(
            format!("CONNECT {target} HTTP/1.1\r\nProxy-Authorization: {credentials}\r\n\r\n")
                .as_bytes(),
        )?;
        let mut line = String::new();
        std::io::BufReader::new(stream).read_line(&mut line)?;
        Ok(line.trim_end().to_owned())
    }

    /// The first line of the proxy's answer to a plain-HTTP request for `url`.
    fn get_through(endpoint: &EgressEndpoint, url: &str) -> std::io::Result<String> {
        use std::io::{BufRead, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", endpoint.port))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let credentials = rift_core::egress::proxy_authorization(&endpoint.token);
        stream.write_all(
            format!("GET {url} HTTP/1.1\r\nProxy-Authorization: {credentials}\r\n\r\n").as_bytes(),
        )?;
        let mut line = String::new();
        std::io::BufReader::new(stream).read_line(&mut line)?;
        Ok(line.trim_end().to_owned())
    }

    #[test]
    fn a_trace_stops_before_a_listed_hop() {
        use std::io::{BufRead, BufReader, Write};
        let dir = tempfile::tempdir().unwrap();
        let intel = Intel::open(dir.path().join("intel").to_string_lossy().into_owned()).unwrap();
        let (trusted_root, repo) = demo_repository(&dir.path().join("publisher"));
        install(&intel, trusted_root, repo);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 2 {
                    line.clear();
                }
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        rift_pack::DEMO_URL
                    )
                    .as_bytes(),
                );
            }
        });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let policy = rift_core::download::DownloadPolicy {
            local_hosts: vec!["localhost".into()],
            ..rift_core::download::DownloadPolicy::default()
        };
        let navigator = Navigator::new(Vec::new(), Vec::new());
        let t = navigator.trace_with(
            &format!("http://localhost:{port}/short"),
            Some(intel),
            now,
            "t",
            &policy,
        );
        assert_eq!(t.outcome, TraceOutcome::Stopped, "{t:?}");
        assert_eq!(t.hops.len(), 2);
        assert_eq!(t.hops[0].status, Some(302));
        // Not contacted (it would not resolve, and the trace would have failed).
        assert_eq!(t.hops[1].status, None);
        assert!(matches!(
            &t.hops[1].check.navigation,
            Navigation::Block { reason, .. } if reason.code == "known-malicious"
        ));
    }

    #[test]
    fn the_installed_database_checks_navigations_and_every_proxied_request() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let generation = sessions.start().unwrap();
        let intel = Intel::open(dir.path().join("intel").to_string_lossy().into_owned()).unwrap();
        let navigator = Navigator::new(Vec::new(), Vec::new());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let notes_of = |navigation: Navigation| match navigation {
            Navigation::Proceed { notes } | Navigation::Confirm { notes, .. } => notes,
            other => panic!("expected no block, got {other:?}"),
        };
        let before =
            notes_of(navigator.decide(rift_pack::DEMO_URL.into(), true, Some(intel.clone()), now));
        assert!(
            before.iter().any(|n| n.code == "intel-missing"),
            "{before:?}"
        );

        // Started before the install: the screen reads the snapshot current at each request.
        let endpoint = sessions
            .egress(generation, Some(intel.clone()), None)
            .unwrap();
        let (trusted_root, repo) = demo_repository(&dir.path().join("publisher"));
        install(&intel, trusted_root, repo);

        match navigator.decide(rift_pack::DEMO_URL.into(), true, Some(intel.clone()), now) {
            Navigation::Block {
                reason,
                inspect_anyway,
            } => {
                assert_eq!(reason.code, "known-malicious");
                assert!(inspect_anyway);
            }
            other => panic!("expected a block, got {other:?}"),
        }
        let elsewhere = notes_of(navigator.decide(
            "http://rift-demo.invalid/fine".into(),
            true,
            Some(intel.clone()),
            now,
        ));
        assert!(
            !elsewhere.iter().any(|n| n.code.starts_with("intel-")),
            "{elsewhere:?}"
        );

        // A page's subresources, not only its address, refused before the
        // name is looked up (.invalid never resolves, which gives a different
        // refusal): a listed path over plain HTTP, and a listed host also
        // through a tunnel, where only the host is visible.
        assert_eq!(
            get_through(&endpoint, rift_pack::DEMO_URL).unwrap(),
            "HTTP/1.1 403 Forbidden"
        );
        let tunnel = format!("cdn.{}:443", rift_pack::DEMO_HOST);
        assert_eq!(
            connect_through(&endpoint, &tunnel).unwrap(),
            "HTTP/1.1 403 Forbidden"
        );
        assert_eq!(
            get_through(&endpoint, "http://rift-demo.invalid/fine").unwrap(),
            "HTTP/1.1 403 Forbidden"
        );
        // The listed path behind a query too long to check: refused as not
        // checked, not screened by its host alone.
        let padded = format!(
            "{}?{}",
            rift_pack::DEMO_URL,
            "a".repeat(rift_core::urlcanon::MAX_URL_BYTES)
        );
        assert_eq!(
            get_through(&endpoint, &padded).unwrap(),
            "HTTP/1.1 403 Forbidden"
        );
        let stats = sessions.egress_stats(generation).unwrap();
        let codes: Vec<(u64, &str)> = stats
            .recent
            .iter()
            .map(|d| (d.seq, d.code.as_str()))
            .collect();
        assert_eq!(
            codes,
            vec![
                (1, "known-malicious"),
                (2, "known-malicious"),
                (3, "does-not-resolve"),
                (4, "not-checked")
            ]
        );
        assert_eq!(stats.recent[0].destination, "rift-demo.invalid:80");
        assert!(
            stats.recent[0]
                .reason
                .contains("rift-demo.invalid/known-bad"),
            "{}",
            stats.recent[0].reason
        );
        assert_eq!(stats.recent[1].destination, tunnel);
    }

    #[test]
    fn pages_named_after_a_protected_brand_are_flagged() {
        let navigator = Navigator::new(vec!["paypal.com".into()], Vec::new());
        let found = navigator.assess_page(
            "https://login-help.example/".into(),
            "PayPal".into(),
            true,
            false,
            String::new(),
        );
        let codes: Vec<(&str, bool)> = found.iter().map(|f| (f.code.as_str(), f.warn)).collect();
        assert_eq!(
            codes,
            vec![("page-claims-brand", true), ("page-asks-password", false)]
        );
        assert!(
            navigator
                .assess_page(
                    "not a url\u{0}".repeat(5000),
                    "PayPal".into(),
                    true,
                    false,
                    String::new()
                )
                .is_empty()
        );
    }

    #[test]
    fn rift_ai_reads_a_phishing_kit_page_and_says_why() {
        let navigator = Navigator::new(Vec::new(), Vec::new());
        let kit = r#"{"pw":1,"fm":1,"fx":1,"fphp":1,"hi":3,"a":4,"an":4,"r":6,"rx":5,"fv":1,"sc":2,"sx":1,"ob":2,"hb":4000,"el":60,
            "title":"PayPal: Log in to your account","text":"Your account has been limited. Verify your identity within 24 hours. Email Password Log In"}"#;
        let found = navigator.assess_page(
            "https://paypa1-secure.example/".into(),
            String::new(),
            true,
            false,
            kit.into(),
        );
        let ai = found.iter().find(|f| f.code == "page-ai").unwrap();
        assert!(ai.warn, "{}", ai.text);
        assert!(ai.text.contains("resembling phishing"), "{}", ai.text);
        // Malformed counts are ignored, not guessed at.
        let none = navigator.assess_page(
            "https://paypa1-secure.example/".into(),
            String::new(),
            true,
            false,
            "{".into(),
        );
        assert!(none.iter().all(|f| f.code != "page-ai"));
    }

    #[test]
    fn an_inspected_link_passes_the_proxy_in_its_session_only() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let generation = sessions.start().unwrap();
        let intel = Intel::open(dir.path().join("intel").to_string_lossy().into_owned()).unwrap();
        let (trusted_root, repo) = demo_repository(&dir.path().join("publisher"));
        install(&intel, trusted_root, repo);
        let endpoint = sessions
            .egress(generation, Some(intel.clone()), None)
            .unwrap();
        assert!(!sessions.is_inspected(generation, rift_pack::DEMO_URL.into()));
        assert!(sessions.allow_inspection(generation, rift_pack::DEMO_URL.into()));
        assert!(sessions.is_inspected(generation, rift_pack::DEMO_URL.into()));
        assert!(!sessions.allow_inspection(generation, "javascript:alert(1)".into()));

        // Past the database check, to the next one: .invalid never resolves.
        assert_eq!(
            get_through(&endpoint, rift_pack::DEMO_URL).unwrap(),
            "HTTP/1.1 403 Forbidden"
        );
        // Another listed host is still refused, before it is resolved.
        let tunnel = format!("cdn.{}:443", rift_pack::DEMO_HOST);
        assert_eq!(
            connect_through(&endpoint, &tunnel).unwrap(),
            "HTTP/1.1 403 Forbidden"
        );
        let codes: Vec<String> = sessions
            .egress_stats(generation)
            .unwrap()
            .recent
            .into_iter()
            .map(|d| d.code)
            .collect();
        assert_eq!(codes, vec!["does-not-resolve", "known-malicious"]);

        // The allowance goes with the session.
        sessions.reset().unwrap();
        let next = sessions.start().unwrap();
        assert!(!sessions.is_inspected(next, rift_pack::DEMO_URL.into()));
        assert!(!sessions.allow_inspection(generation, rift_pack::DEMO_URL.into()));
        let endpoint = sessions.egress(next, Some(intel), None).unwrap();
        assert_eq!(
            get_through(&endpoint, rift_pack::DEMO_URL).unwrap(),
            "HTTP/1.1 403 Forbidden"
        );
        let codes: Vec<String> = sessions
            .egress_stats(next)
            .unwrap()
            .recent
            .into_iter()
            .map(|d| d.code)
            .collect();
        assert_eq!(codes, vec!["known-malicious"]);
    }

    #[test]
    fn the_egress_proxy_belongs_to_one_session_and_ends_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let generation = sessions.start().unwrap();
        assert!(
            sessions.egress_stats(generation).is_none(),
            "not started until asked for"
        );
        let endpoint = sessions.egress(generation, None, None).unwrap();
        assert_eq!(
            sessions.egress(generation, None, None).unwrap(),
            endpoint,
            "one proxy per session"
        );
        let target = format!("localhost:{}", serve(b"through the proxy"));

        // Loopback needs the user's per-host exception, which reaches the running proxy.
        assert_eq!(
            connect_through(&endpoint, &target).unwrap(),
            "HTTP/1.1 403 Forbidden"
        );
        assert!(sessions.allow_local_host(generation, "localhost".into()));
        assert_eq!(
            connect_through(&endpoint, &target).unwrap(),
            "HTTP/1.1 200 Connection Established"
        );
        let stats = sessions.egress_stats(generation).unwrap();
        assert_eq!((stats.allowed, stats.denied), (1, 1));
        assert_eq!(stats.recent[0].destination, target);
        assert!(
            stats.recent[0].reason.contains("private address"),
            "{}",
            stats.recent[0].reason
        );

        // Reset stops it; the next session gets a new port and token.
        sessions.reset().unwrap();
        assert!(
            connect_through(&endpoint, &target).map_or(true, |line| line.is_empty()),
            "the old proxy answers nothing"
        );
        assert!(matches!(
            sessions.egress(generation, None, None),
            Err(EgressFailure::NoActiveSession)
        ));
        let next = sessions.start().unwrap();
        let fresh = sessions.egress(next, None, None).unwrap();
        assert_ne!(fresh.token, endpoint.token);
        assert_eq!(
            connect_through(&fresh, &target).unwrap(),
            "HTTP/1.1 403 Forbidden",
            "exceptions do not carry over"
        );
    }

    #[test]
    fn the_forwarded_proxy_follows_the_session_and_ends_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let generation = sessions.start().unwrap();
        let proxy = sessions.forwarded_egress(generation, None).unwrap();
        assert!(Arc::ptr_eq(
            &proxy,
            &sessions.forwarded_egress(generation, None).unwrap()
        ));
        assert!(
            matches!(
                sessions.egress(generation, None, None),
                Err(EgressFailure::Start { .. })
            ),
            "one kind of proxy per session"
        );
        let target = format!("localhost:{}", serve(b"through the proxy"));
        let ask = |proxy: &rift_core::egress::ForwardedEgress| {
            use std::io::Write as _;
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let mut engine = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            proxy.serve(listener.accept().unwrap().0).unwrap();
            engine
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            engine
                .write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
                .unwrap();
            let mut line = String::new();
            let _read =
                std::io::BufRead::read_line(&mut std::io::BufReader::new(engine), &mut line);
            line.trim_end().to_owned()
        };
        assert_eq!(ask(&proxy), "HTTP/1.1 403 Forbidden");
        assert!(sessions.allow_local_host(generation, "localhost".into()));
        assert_eq!(ask(&proxy), "HTTP/1.1 200 Connection Established");
        let stats = sessions.egress_stats(generation).unwrap();
        assert_eq!(
            (stats.allowed, stats.denied, stats.unauthenticated),
            (1, 1, 0)
        );
        sessions.reset().unwrap();
        assert_eq!(ask(&proxy), "", "closed unserved after the reset");
        let next = sessions.start().unwrap();
        let fresh = sessions.forwarded_egress(next, None).unwrap();
        assert_eq!(
            ask(&fresh),
            "HTTP/1.1 403 Forbidden",
            "exceptions do not carry over"
        );
    }

    #[test]
    fn downloads_belong_to_one_session_and_end_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let generation = sessions.start().unwrap();
        let url = format!("http://localhost:{}/report", serve(b"quarantined bytes"));

        // INV-13: local destinations only after an explicit, per-host allowance.
        assert!(matches!(
            sessions.download(generation, info(url.clone())),
            Err(DownloadFailure::NotCaptured { .. })
        ));
        assert!(sessions.allow_local_host(generation, "LocalHost".into()));
        assert_eq!(
            sessions.local_hosts(generation),
            vec!["localhost".to_owned()]
        );
        let file = sessions.download(generation, info(url.clone())).unwrap();
        assert_eq!(file.size, 17);
        assert_eq!(file.display_name, "rfdp.exe");
        assert_eq!(sessions.quarantine(generation), vec![file]);

        // Results for an old generation are refused, and nothing carries over.
        sessions.reset().unwrap();
        let next = sessions.start().unwrap();
        assert!(matches!(
            sessions.download(generation, info(url.clone())),
            Err(DownloadFailure::SessionEnded)
        ));
        assert!(sessions.quarantine(next).is_empty());
        assert!(sessions.local_hosts(next).is_empty());
        assert!(!sessions.allow_local_host(generation, "localhost".into()));
        assert!(
            !dir.path()
                .join("sessions")
                .join(generation.to_string())
                .exists()
        );
    }

    /// 1x1 RGBA PNG.
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52, 0,
        0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0x0d, 0x49, 0x44,
        0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0, 0x05, 0x00, 0x01, 0xff,
        0x89, 0x99, 0x3d, 0x1d, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ];

    #[test]
    fn previews_go_through_a_validated_worker_exchange() {
        use rift_worker_ffi::WorkerEngine;
        let dir = tempfile::tempdir().unwrap();
        let sessions = Sessions::open(root(&dir), Arc::new(FakeDisposal::default())).unwrap();
        let generation = sessions.start().unwrap();
        assert!(sessions.allow_local_host(generation, "localhost".into()));
        let png = sessions
            .download(
                generation,
                info(format!("http://localhost:{}/", serve(PNG))),
            )
            .unwrap();
        let text = sessions
            .download(
                generation,
                info(format!(
                    "http://localhost:{}/",
                    serve(b"plain\r\ntext \xe2\x80\xae")
                )),
            )
            .unwrap();
        let binary = sessions
            .download(
                generation,
                info(format!("http://localhost:{}/", serve(b"MZ\x90\x00"))),
            )
            .unwrap();

        // Content decides the kind; the hostile ".exe" name is irrelevant.
        assert!(matches!(
            sessions.clone().preview(generation, text.id, 64, 64),
            Ok(Preview::Text { text, truncated: false, replaced: false })
                if text == "plain\ntext \\u{202e}"
        ));
        assert!(matches!(
            sessions.clone().preview(generation, binary.id, 64, 64),
            Err(PreviewFailure::Unsupported)
        ));
        assert!(matches!(
            sessions
                .clone()
                .preview(generation, "00".repeat(16), 64, 64),
            Err(PreviewFailure::NotFound)
        ));
        let Ok(Preview::Rendered { job }) =
            sessions.clone().preview(generation, png.id.clone(), 64, 64)
        else {
            panic!("expected a worker job for a PNG");
        };
        assert_eq!(job.kind(), PreviewKind::Image);
        assert_eq!(job.input(), PNG);

        // A worker that does not report seccomp is refused before any input.
        let unconfined = WorkerEngine::new(false, false);
        assert!(matches!(
            job.accept_hello(unconfined.handle(job.hello_frame(), None).frame),
            Err(PreviewFailure::Unconfined { .. })
        ));
        let worker = WorkerEngine::new(true, false);
        let hello = worker.handle(job.hello_frame(), None).frame;
        job.accept_hello(hello.clone()).unwrap();

        // Replies for another request, garbage and bitmaps larger than the region are rejected.
        assert!(matches!(
            job.accept(hello, 4),
            Err(PreviewFailure::BadReply { .. })
        ));
        assert!(matches!(
            job.accept(b"junk".to_vec(), 4),
            Err(PreviewFailure::BadReply { .. })
        ));
        let reply = worker.handle(job.request_frame(), Some(job.input()));
        let pixels = reply.pixels.clone().unwrap();
        assert!(matches!(
            job.accept(reply.frame.clone(), 3),
            Err(PreviewFailure::BadReply { .. })
        ));
        assert_eq!(
            job.accept(reply.frame.clone(), pixels.len() as u64)
                .unwrap(),
            PreviewBitmap {
                width: 1,
                height: 1,
                stride: 4
            }
        );

        // A malformed image becomes a typed worker error, not a bitmap.
        let broken = worker.handle(
            job.request_frame(),
            Some(b"\x89PNG\r\n\x1a\nbroken".to_vec()),
        );
        assert!(matches!(
            job.accept(broken.frame, 0),
            Err(PreviewFailure::Worker { .. })
        ));

        // Once the session ends, its previews are discarded.
        sessions.reset().unwrap();
        assert!(matches!(
            job.accept(reply.frame, pixels.len() as u64),
            Err(PreviewFailure::SessionEnded)
        ));
        assert!(matches!(
            sessions.clone().preview(generation, png.id, 64, 64),
            Err(PreviewFailure::SessionEnded)
        ));
    }

    #[test]
    fn content_sniffing() {
        assert_eq!(sniff(PNG), Some(PreviewKind::Image));
        assert_eq!(sniff(b"\xff\xd8\xff\xe0rest"), Some(PreviewKind::Image));
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Some(PreviewKind::Image));
        assert_eq!(sniff(b"RIFF\0\0\0\0WAVEfmt "), None);
        assert_eq!(sniff(b"junk\n%PDF-1.7\n"), Some(PreviewKind::Pdf));
        assert_eq!(sniff(b"MZ\x90\0"), None);
        assert_eq!(sniff(b""), None);
    }

    #[test]
    fn display_helpers_neutralize_hostile_text() {
        assert_eq!(
            display_name("../../evil\u{202e}gpj.pdf".into()),
            "evilgpj.pdf"
        );
        assert_eq!(display_safe("a\u{202e}b".into()), "a\\u{202e}b");
    }
}
