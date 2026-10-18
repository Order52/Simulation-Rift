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
use rift_core::heuristics::HeuristicConfig;
use rift_core::policy::{self, Decision, IntelState, NavigationContext};
use rift_core::session::{RecoveryReport, SessionError, SessionManager, SessionPlatform};
use rift_core::store::StoredObject;
use rift_protocol::{Envelope, PROTOCOL_VERSION, Request, Response};

uniffi::setup_scaffolding!();

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
}

#[uniffi::export]
impl Navigator {
    #[uniffi::constructor]
    pub fn new(protected_domains: Vec<String>, shorteners: Vec<String>) -> Arc<Self> {
        Arc::new(Self {
            heuristics: HeuristicConfig {
                protected_domains,
                shorteners,
                ..HeuristicConfig::default()
            },
        })
    }

    /// Decides a navigation to `url`. `sandbox_verified` is the result of the
    /// platform's renderer checks (§8.4); without it everything is blocked.
    /// Signed intelligence arrives in Phase 3, so until then no indicator
    /// table is consulted and every decision says so.
    pub fn decide(&self, url: String, sandbox_verified: bool) -> Navigation {
        let ctx = NavigationContext {
            sandbox_verified,
            indicators: None,
            intel_state: IntelState::Missing,
            heuristics: &self.heuristics,
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
            | SessionError::Vault(_)
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
    files: Vec<QuarantinedFile>,
    /// Where each of `files` is stored, for reading it back.
    objects: Vec<StoredObject>,
    /// Committed bytes plus reservations of downloads in progress.
    reserved: u64,
}

impl SessionExtras {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            cancel: Arc::new(AtomicBool::new(false)),
            local_hosts: Vec::new(),
            files: Vec::new(),
            objects: Vec::new(),
            reserved: 0,
        }
    }
}

/// Largest quarantined file decrypted for a preview; it is held in memory
/// in both the controller and the worker.
const MAX_PREVIEW_INPUT: u64 = 32 * 1024 * 1024;

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
    #[error("Rift previews PNG, JPEG, WebP and PDF content only")]
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

/// One preview of one file by one fresh worker. The controller sends
/// `hello_frame`, checks the reply with `accept_hello`, and only then passes
/// `input` and `request_frame`; every reply is validated against the request.
#[derive(Debug, uniffi::Object)]
pub struct PreviewJob {
    sessions: Arc<Sessions>,
    generation: u64,
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
        if !self.sessions.is_current(self.generation) {
            return Err(PreviewFailure::SessionEnded);
        }
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
        let mut reader = reply;
        let body = rift_protocol::read_frame(&mut reader).map_err(|e| bad_reply(&e.to_string()))?;
        if !reader.is_empty() {
            return Err(bad_reply("trailing bytes after the reply"));
        }
        rift_protocol::decode_response(&body, request)
            .map(rift_protocol::Validated::into_inner)
            .map_err(|e| bad_reply(&e.to_string()))
    }
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
        state.extras = Some(SessionExtras::new(generation));
        Ok(generation)
    }

    /// Destroys the active session and returns its generation. Transfers
    /// are cancelled first. Succeeds only after disposal and deletion were
    /// verified.
    pub fn reset(&self) -> Result<u64, SessionFailure> {
        let mut state = self.lock()?;
        if let Some(extras) = state.extras.take() {
            extras.cancel.store(true, Ordering::SeqCst);
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
        true
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

    /// Prepares a preview of quarantined file `id` (§8.6): decrypts and
    /// verifies it, and identifies the format from its content, never from
    /// its name or the server's label. The returned job frames the worker
    /// requests and checks every reply.
    pub fn preview(
        self: Arc<Self>,
        generation: u64,
        id: String,
        max_width: u32,
        max_height: u32,
    ) -> Result<Arc<PreviewJob>, PreviewFailure> {
        // Decrypted under the lock (the key never leaves the session), so a
        // reset waits for this bounded local read instead of racing it.
        let input = {
            let mut state = self.state.lock().map_err(|_| PreviewFailure::Poisoned)?;
            let object = state
                .current(generation)
                .ok_or(PreviewFailure::SessionEnded)?
                .objects
                .iter()
                .find(|o| o.id.to_hex() == id)
                .copied()
                .ok_or(PreviewFailure::NotFound)?;
            if object.sealed.size > MAX_PREVIEW_INPUT {
                return Err(PreviewFailure::TooLarge {
                    limit: MAX_PREVIEW_INPUT,
                });
            }
            let session = state.manager.active().ok_or(PreviewFailure::SessionEnded)?;
            let mut input = Vec::new();
            session
                .quarantine()
                .read(
                    object.id,
                    session.quarantine_key(),
                    &object.sealed,
                    &mut input,
                )
                .map_err(|e| PreviewFailure::Storage {
                    detail: e.to_string(),
                })?;
            input
        };
        let kind = sniff(&input).ok_or(PreviewFailure::Unsupported)?;
        let job_id = self.next_job.fetch_add(1, Ordering::SeqCst);
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
        Ok(Arc::new(PreviewJob {
            sessions: self,
            generation,
            kind,
            hello: envelope(job_id, generation, Request::Hello),
            request: envelope(job_id.saturating_add(1), generation, request),
            input,
        }))
    }
}

impl Sessions {
    fn lock(&self) -> Result<MutexGuard<'_, State>, SessionFailure> {
        self.state.lock().map_err(|_| SessionFailure::Poisoned)
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

    #[test]
    fn decisions_carry_codes_and_sentences() {
        let navigator = Navigator::new(vec!["paypal.com".into()], vec!["bit.ly".into()]);
        assert_eq!(
            navigator.decide("https://example.org/".into(), false),
            Navigation::Block {
                reason: Fact {
                    code: "sandbox-unavailable".into(),
                    text: rift_core::policy::BlockReason::SandboxUnavailable.explain(),
                },
                inspect_anyway: false,
            }
        );
        match navigator.decide("https://paypa1.com/login".into(), true) {
            Navigation::Confirm { reasons, notes } => {
                assert_eq!(reasons.first().map(|r| r.code.as_str()), Some("lookalike"));
                assert!(notes.iter().any(|n| n.code == "intel-missing"));
            }
            other => panic!("expected confirm, got {other:?}"),
        }
        match navigator.decide("intent://scan/#Intent;end".into(), true) {
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
                info(format!("http://localhost:{}/", serve(b"plain text"))),
            )
            .unwrap();

        // Content decides the kind; the hostile ".exe" name is irrelevant.
        assert!(matches!(
            sessions.clone().preview(generation, text.id, 64, 64),
            Err(PreviewFailure::Unsupported)
        ));
        assert!(matches!(
            sessions
                .clone()
                .preview(generation, "00".repeat(16), 64, 64),
            Err(PreviewFailure::NotFound)
        ));
        let job = sessions
            .clone()
            .preview(generation, png.id.clone(), 64, 64)
            .unwrap();
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
