//! UniFFI bindings for the Android controller (docs/architecture.md §6, §8.3).
//!
//! Only the trusted main process loads this library; `:browser` reaches the
//! core through the main process's Binder interface instead. Everything that
//! crosses into Kotlin is a plain value: keys, stores and other rift-core
//! internals stay on the Rust side.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use rift_core::heuristics::HeuristicConfig;
use rift_core::policy::{self, Decision, IntelState, NavigationContext};
use rift_core::session::{RecoveryReport, SessionError, SessionManager, SessionPlatform};

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

/// Disposable sessions (§15, INV-8).
#[derive(Debug, uniffi::Object)]
pub struct Sessions {
    manager: Mutex<SessionManager<Platform>>,
    recovery: Recovery,
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
            manager: Mutex::new(manager),
            recovery: report.into(),
        }))
    }

    pub fn recovery(&self) -> Recovery {
        self.recovery.clone()
    }

    /// Starts a session and returns its generation.
    pub fn start(&self) -> Result<u64, SessionFailure> {
        Ok(self.lock()?.start()?.generation())
    }

    /// Destroys the active session and returns its generation. Succeeds only
    /// after disposal and deletion were verified.
    pub fn reset(&self) -> Result<u64, SessionFailure> {
        Ok(self.lock()?.reset()?)
    }

    pub fn current_generation(&self) -> Option<u64> {
        self.lock().ok()?.active().map(|s| s.generation())
    }

    /// True only for the active generation; results tagged with anything
    /// else must be discarded. False if the state is unusable.
    pub fn is_current(&self, generation: u64) -> bool {
        self.lock().is_ok_and(|m| m.is_current(generation))
    }
}

impl Sessions {
    fn lock(&self) -> Result<MutexGuard<'_, SessionManager<Platform>>, SessionFailure> {
        self.manager.lock().map_err(|_| SessionFailure::Poisoned)
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

    #[test]
    fn display_helpers_neutralize_hostile_text() {
        assert_eq!(
            display_name("../../evil\u{202e}gpj.pdf".into()),
            "evilgpj.pdf"
        );
        assert_eq!(display_safe("a\u{202e}b".into()), "a\\u{202e}b");
    }
}
