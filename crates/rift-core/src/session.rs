//! Disposable browsing sessions (docs/architecture.md §15, INV-8).
//!
//! * Generations are monotonic across launches, so results from an old
//!   session can never be mistaken for the current one.
//! * Each session's quarantine is encrypted with an ephemeral key that only
//!   ever exists in memory; dropping it makes leftover ciphertext unreadable
//!   (crypto-shredding), whatever the flash storage retains.
//! * A persisted marker records ACTIVE/RESETTING, so a reset interrupted by a
//!   crash is completed on the next launch *before* any session is presented
//!   as fresh.
//! * Engine-specific disposal (killing the browser process, deleting WebView
//!   data) is delegated to a [`SessionPlatform`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::seal::{SealError, SealKey};
use crate::store::ObjectStore;

const MARKER: &str = "session.marker";
const MARKER_TEMP: &str = "session.marker.tmp";
const SESSIONS: &str = "sessions";

/// Engine-side disposal for one generation, implemented per platform.
pub trait SessionPlatform {
    /// Terminates the generation's browser processes and deletes its engine
    /// data. Must be idempotent: recovery may call it again after a crash.
    fn destroy_browser_state(&mut self, generation: u64) -> Result<(), String>;
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("storage error: {0}")]
    Storage(#[from] io::Error),
    #[error("{0}")]
    Sealed(#[from] SealError),
    #[error("session marker is malformed")]
    MalformedMarker,
    #[error("no active session")]
    NoActiveSession,
    #[error("a session is already active")]
    AlreadyActive,
    /// Cleanup did not complete; the session is NOT reported destroyed and
    /// recovery will retry on the next launch.
    #[error("cleanup of generation {generation} failed: {reason}")]
    CleanupFailed { generation: u64, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerState {
    Active,
    Resetting,
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marker {
    state: MarkerState,
    generation: u64,
}

/// What launch-time recovery found and did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryReport {
    /// A session was left ACTIVE or RESETTING by a previous run.
    pub interrupted_generation: Option<u64>,
    /// Quarantine directories of old generations that were deleted.
    pub removed_generations: Vec<u64>,
}

#[derive(Debug)]
pub struct ActiveSession {
    generation: u64,
    quarantine_key: SealKey,
    quarantine: ObjectStore,
}

impl ActiveSession {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn quarantine(&self) -> &ObjectStore {
        &self.quarantine
    }

    /// The in-memory key that encrypts this session's quarantine.
    pub fn quarantine_key(&self) -> &SealKey {
        &self.quarantine_key
    }
}

#[derive(Debug)]
pub struct SessionManager<P: SessionPlatform> {
    root: PathBuf,
    platform: P,
    last_generation: u64,
    active: Option<ActiveSession>,
}

impl<P: SessionPlatform> SessionManager<P> {
    /// Opens the session area and performs recovery. Returns an error (and no
    /// manager) if an interrupted cleanup still cannot complete, so the UI can
    /// report it instead of presenting a session as fresh.
    pub fn open(
        root: impl Into<PathBuf>,
        platform: P,
    ) -> Result<(Self, RecoveryReport), SessionError> {
        let root = root.into();
        fs::create_dir_all(root.join(SESSIONS))?;
        let marker = read_marker(&root)?;
        let mut manager = Self {
            root,
            platform,
            last_generation: marker.map_or(0, |m| m.generation),
            active: None,
        };
        let mut report = RecoveryReport::default();
        if let Some(Marker {
            state: MarkerState::Active | MarkerState::Resetting,
            generation,
        }) = marker
        {
            report.interrupted_generation = Some(generation);
            manager.write_marker(MarkerState::Resetting, generation)?;
            manager.destroy(generation)?;
        }
        report.removed_generations = manager.remove_stale_generations(None)?;
        Ok((manager, report))
    }

    pub fn active(&self) -> Option<&ActiveSession> {
        self.active.as_ref()
    }

    /// True only for the generation of the currently active session.
    pub fn is_current(&self, generation: u64) -> bool {
        self.active
            .as_ref()
            .is_some_and(|s| s.generation == generation)
    }

    pub fn start(&mut self) -> Result<&ActiveSession, SessionError> {
        if self.active.is_some() {
            return Err(SessionError::AlreadyActive);
        }
        let generation = self
            .last_generation
            .checked_add(1)
            .ok_or(SessionError::MalformedMarker)?;
        self.write_marker(MarkerState::Active, generation)?;
        self.last_generation = generation;
        let quarantine = ObjectStore::open(self.generation_dir(generation).join("quarantine"))?;
        Ok(self.active.insert(ActiveSession {
            generation,
            quarantine_key: SealKey::generate(),
            quarantine,
        }))
    }

    /// Destroys the active session. On failure the session is not reported
    /// destroyed.
    pub fn reset(&mut self) -> Result<u64, SessionError> {
        let session = self.active.take().ok_or(SessionError::NoActiveSession)?;
        let generation = session.generation;
        self.write_marker(MarkerState::Resetting, generation)?;
        // Crypto-shred first: once the key is gone, leftover ciphertext is
        // unreadable even if deletion below fails or flash retains blocks.
        drop(session);
        self.destroy(generation)?;
        Ok(generation)
    }

    fn destroy(&mut self, generation: u64) -> Result<(), SessionError> {
        let failed = |reason: String| SessionError::CleanupFailed { generation, reason };
        self.platform
            .destroy_browser_state(generation)
            .map_err(failed)?;
        let dir = self.generation_dir(generation);
        match fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(failed(format!("delete {}: {e}", dir.display()))),
        }
        if dir.exists() {
            return Err(failed(
                "session directory still present after deletion".into(),
            ));
        }
        self.write_marker(MarkerState::Destroyed, generation)
    }

    /// Deletes quarantine directories of any generation except `keep`.
    fn remove_stale_generations(&self, keep: Option<u64>) -> Result<Vec<u64>, SessionError> {
        let mut removed = Vec::new();
        for entry in fs::read_dir(self.root.join(SESSIONS))? {
            let entry = entry?;
            let Some(generation) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u64>().ok())
            else {
                continue;
            };
            if Some(generation) != keep {
                fs::remove_dir_all(entry.path())?;
                removed.push(generation);
            }
        }
        removed.sort_unstable();
        Ok(removed)
    }

    fn generation_dir(&self, generation: u64) -> PathBuf {
        self.root.join(SESSIONS).join(generation.to_string())
    }

    fn write_marker(&self, state: MarkerState, generation: u64) -> Result<(), SessionError> {
        let label = match state {
            MarkerState::Active => "ACTIVE",
            MarkerState::Resetting => "RESETTING",
            MarkerState::Destroyed => "DESTROYED",
        };
        let temp = self.root.join(MARKER_TEMP);
        fs::write(&temp, format!("{label} {generation}\n"))?;
        fs::File::open(&temp)?.sync_all()?;
        fs::rename(&temp, self.root.join(MARKER))?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

fn read_marker(root: &Path) -> Result<Option<Marker>, SessionError> {
    let text = match fs::read_to_string(root.join(MARKER)) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let (label, generation) = text
        .trim()
        .split_once(' ')
        .ok_or(SessionError::MalformedMarker)?;
    let generation = generation
        .parse()
        .map_err(|_| SessionError::MalformedMarker)?;
    let state = match label {
        "ACTIVE" => MarkerState::Active,
        "RESETTING" => MarkerState::Resetting,
        "DESTROYED" => MarkerState::Destroyed,
        _ => return Err(SessionError::MalformedMarker),
    };
    Ok(Some(Marker { state, generation }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Write;
    use std::rc::Rc;

    /// Records destroy calls; can be told to fail.
    #[derive(Clone, Default)]
    struct FakePlatform {
        destroyed: Rc<RefCell<Vec<u64>>>,
        fail: Rc<RefCell<bool>>,
    }

    impl SessionPlatform for FakePlatform {
        fn destroy_browser_state(&mut self, generation: u64) -> Result<(), String> {
            if *self.fail.borrow() {
                return Err("browser process did not exit".into());
            }
            self.destroyed.borrow_mut().push(generation);
            Ok(())
        }
    }

    fn quarantine_one(manager: &SessionManager<FakePlatform>) {
        let session = manager.active().unwrap();
        let mut pending = session
            .quarantine()
            .begin(&session.quarantine_key().recipient(), 1 << 20)
            .unwrap();
        pending.write_all(b"downloaded").unwrap();
        pending.commit().unwrap();
    }

    #[test]
    fn reset_destroys_engine_state_and_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let platform = FakePlatform::default();
        let (mut manager, report) = SessionManager::open(dir.path(), platform.clone()).unwrap();
        assert_eq!(report, RecoveryReport::default());
        let generation = manager.start().unwrap().generation();
        quarantine_one(&manager);
        assert_eq!(manager.reset().unwrap(), generation);
        assert_eq!(*platform.destroyed.borrow(), vec![generation]);
        assert!(
            !dir.path()
                .join(SESSIONS)
                .join(generation.to_string())
                .exists()
        );
        assert!(!manager.is_current(generation));
    }

    #[test]
    fn generations_are_monotonic_across_launches() {
        let dir = tempfile::tempdir().unwrap();
        let (mut manager, _) = SessionManager::open(dir.path(), FakePlatform::default()).unwrap();
        let first = manager.start().unwrap().generation();
        manager.reset().unwrap();
        drop(manager);
        let (mut manager, _) = SessionManager::open(dir.path(), FakePlatform::default()).unwrap();
        let second = manager.start().unwrap().generation();
        assert!(second > first);
        assert!(manager.is_current(second) && !manager.is_current(first));
    }

    #[test]
    fn crash_with_active_session_is_cleaned_before_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let (mut manager, _) = SessionManager::open(dir.path(), FakePlatform::default()).unwrap();
        let crashed = manager.start().unwrap().generation();
        quarantine_one(&manager);
        drop(manager); // the app is killed: no reset ran

        let platform = FakePlatform::default();
        let (mut manager, report) = SessionManager::open(dir.path(), platform.clone()).unwrap();
        assert_eq!(report.interrupted_generation, Some(crashed));
        assert_eq!(*platform.destroyed.borrow(), vec![crashed]);
        assert!(!dir.path().join(SESSIONS).join(crashed.to_string()).exists());
        assert!(manager.start().unwrap().generation() > crashed);
    }

    #[test]
    fn failed_cleanup_is_reported_and_retried_on_next_launch() {
        let dir = tempfile::tempdir().unwrap();
        let platform = FakePlatform::default();
        let (mut manager, _) = SessionManager::open(dir.path(), platform.clone()).unwrap();
        let generation = manager.start().unwrap().generation();
        *platform.fail.borrow_mut() = true;
        assert!(
            matches!(manager.reset(), Err(SessionError::CleanupFailed { generation: g, .. }) if g == generation)
        );
        drop(manager);

        // Still failing: opening refuses rather than presenting a fresh session.
        assert!(SessionManager::open(dir.path(), platform.clone()).is_err());
        // Once the platform can clean up, recovery completes.
        *platform.fail.borrow_mut() = false;
        let (_, report) = SessionManager::open(dir.path(), platform.clone()).unwrap();
        assert_eq!(report.interrupted_generation, Some(generation));
        assert_eq!(*platform.destroyed.borrow(), vec![generation]);
    }

    #[test]
    fn only_one_active_session() {
        let dir = tempfile::tempdir().unwrap();
        let (mut manager, _) = SessionManager::open(dir.path(), FakePlatform::default()).unwrap();
        manager.start().unwrap();
        assert!(matches!(manager.start(), Err(SessionError::AlreadyActive)));
    }

    #[test]
    fn malformed_marker_is_an_error_not_a_fresh_start() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(SESSIONS)).unwrap();
        fs::write(dir.path().join(MARKER), "ACTIVE not-a-number").unwrap();
        assert!(matches!(
            SessionManager::open(dir.path(), FakePlatform::default()),
            Err(SessionError::MalformedMarker)
        ));
    }

    #[test]
    fn stray_generation_directories_are_removed_at_launch() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(SESSIONS).join("41/quarantine")).unwrap();
        let (_, report) = SessionManager::open(dir.path(), FakePlatform::default()).unwrap();
        assert_eq!(report.removed_generations, vec![41]);
    }
}
