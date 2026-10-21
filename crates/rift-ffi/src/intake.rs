//! Files other apps hand to Rift (docs/architecture.md §11.1, intake).
//!
//! The platform reads the file it was given (Android: a `content:` URI it
//! was granted) and streams it here in chunks; nothing is parsed on the way.
//! It is sealed to the session's key and quarantined exactly as a download
//! is: the same quota, size limit and cancellation at reset, and only a
//! complete file is committed. The workspace forbids `unsafe`, so Rust does
//! not take the platform's file descriptor; the chunks are copies.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rift_core::download::DownloadPolicy;
use rift_core::store::PendingObject;
use rift_core::text::escape_for_display;
use rift_core::transfer::display_name;

use crate::{DownloadFailure, QuarantinedFile, SESSION_QUOTA, Sessions};

/// What a handed-over file shows as its source: the sender cannot be
/// verified (an app can claim any referrer), so none is named.
const SOURCE: &str = "another app";

/// As for a server's label: enough for display, bounded.
const MAX_CONTENT_TYPE_CHARS: usize = 100;

/// One file being taken in. Write its bytes in order, then [`finish`]; a
/// failure or a drop before then discards it and frees its reservation.
///
/// [`finish`]: Intake::finish
#[derive(Debug, uniffi::Object)]
pub struct Intake {
    sessions: Arc<Sessions>,
    generation: u64,
    /// Bytes reserved against the session's quota: the most this file may be.
    limit: u64,
    display_name: String,
    content_type: Option<String>,
    cancel: Arc<AtomicBool>,
    pending: Mutex<Option<PendingObject>>,
}

#[uniffi::export]
impl Sessions {
    /// Begins taking in a file another app handed over, into `generation`'s
    /// quarantine. `name` and `content_type` are what the other app said;
    /// both are display metadata only.
    pub fn begin_intake(
        self: Arc<Self>,
        generation: u64,
        name: String,
        content_type: Option<String>,
    ) -> Result<Arc<Intake>, DownloadFailure> {
        let (limit, cancel, pending) = {
            let mut state = self.state.lock().map_err(|_| DownloadFailure::Poisoned)?;
            let (store, recipient) = state
                .manager
                .active()
                .filter(|s| s.generation() == generation)
                .map(|s| (s.quarantine().clone(), s.quarantine_key().recipient()))
                .ok_or(DownloadFailure::SessionEnded)?;
            let extras = state
                .current(generation)
                .ok_or(DownloadFailure::SessionEnded)?;
            let room = SESSION_QUOTA.saturating_sub(extras.reserved);
            let limit = room.min(DownloadPolicy::default().max_bytes);
            if limit == 0 {
                return Err(DownloadFailure::QuotaExceeded {
                    limit: SESSION_QUOTA,
                });
            }
            let pending =
                store
                    .begin(&recipient, limit)
                    .map_err(|e| DownloadFailure::NotCaptured {
                        reason: escape_for_display(&format!("storage error: {e}")),
                    })?;
            extras.reserved = extras.reserved.saturating_add(limit);
            (limit, extras.cancel.clone(), pending)
        };
        Ok(Arc::new(Intake {
            sessions: self,
            generation,
            limit,
            display_name: display_name(&name),
            content_type: content_type.map(|t| {
                escape_for_display(&t.chars().take(MAX_CONTENT_TYPE_CHARS).collect::<String>())
            }),
            cancel,
            pending: Mutex::new(Some(pending)),
        }))
    }
}

#[uniffi::export]
impl Intake {
    /// Appends `chunk`. After an error the file is discarded, and every
    /// later call fails.
    pub fn write(&self, chunk: Vec<u8>) -> Result<(), DownloadFailure> {
        let mut slot = self.pending.lock().map_err(|_| DownloadFailure::Poisoned)?;
        let Some(pending) = slot.as_mut() else {
            return Err(Self::closed());
        };
        let failure = if self.cancel.load(Ordering::SeqCst) {
            Some(DownloadFailure::SessionEnded)
        } else {
            match pending.write_all(&chunk) {
                Ok(()) => None,
                Err(e) if e.kind() == io::ErrorKind::FileTooLarge => {
                    Some(DownloadFailure::NotCaptured {
                        reason: format!("the file is larger than the {}-byte limit", self.limit),
                    })
                }
                Err(e) => Some(DownloadFailure::NotCaptured {
                    reason: escape_for_display(&format!("storage error: {e}")),
                }),
            }
        };
        match failure {
            None => Ok(()),
            Some(failure) => {
                // Dropping the pending object deletes what it wrote.
                slot.take();
                drop(slot);
                self.release(self.limit);
                Err(failure)
            }
        }
    }

    /// Commits the file to the quarantine and lists it with the session's
    /// downloads. Kept only if the session is still current.
    pub fn finish(&self) -> Result<QuarantinedFile, DownloadFailure> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| DownloadFailure::Poisoned)?
            .take()
            .ok_or_else(Self::closed)?;
        if self.cancel.load(Ordering::SeqCst) {
            drop(pending);
            self.release(self.limit);
            return Err(DownloadFailure::SessionEnded);
        }
        let object = match pending.commit() {
            Ok(object) => object,
            Err(e) => {
                self.release(self.limit);
                return Err(DownloadFailure::NotCaptured {
                    reason: escape_for_display(&format!("storage error: {e}")),
                });
            }
        };
        let mut state = self
            .sessions
            .state
            .lock()
            .map_err(|_| DownloadFailure::Poisoned)?;
        let Some(extras) = state.current(self.generation) else {
            // Reset ran meanwhile: its directory is already deleted.
            return Err(DownloadFailure::SessionEnded);
        };
        let unused = self.limit.saturating_sub(object.sealed.size);
        extras.reserved = extras.reserved.saturating_sub(unused);
        let file = QuarantinedFile {
            id: object.id.to_hex(),
            display_name: self.display_name.clone(),
            size: object.sealed.size,
            sha256: hex::encode(object.sealed.sha256),
            content_type: self.content_type.clone(),
            source: SOURCE.into(),
            redirects: 0,
        };
        extras.files.push(file.clone());
        extras.objects.push(object);
        Ok(file)
    }
}

impl Intake {
    fn closed() -> DownloadFailure {
        DownloadFailure::NotCaptured {
            reason: "the file was already finished or discarded".into(),
        }
    }

    /// Gives back `bytes` of the session's quota, if it is still current.
    fn release(&self, bytes: u64) {
        if let Ok(mut state) = self.sessions.state.lock()
            && let Some(extras) = state.current(self.generation)
        {
            extras.reserved = extras.reserved.saturating_sub(bytes);
        }
    }
}

impl Drop for Intake {
    fn drop(&mut self) {
        // Abandoned before `finish`: the pending object deletes itself.
        let abandoned = self
            .pending
            .get_mut()
            .map(|slot| slot.take().is_some())
            .unwrap_or(false);
        if abandoned {
            self.release(self.limit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrowserDisposal, DisposalError, Preview};

    struct NoBrowser;

    impl BrowserDisposal for NoBrowser {
        fn destroy_browser_state(&self, _generation: u64) -> Result<(), DisposalError> {
            Ok(())
        }
    }

    fn open(dir: &tempfile::TempDir) -> (Arc<Sessions>, u64) {
        let sessions = Sessions::open(
            dir.path().to_string_lossy().into_owned(),
            Arc::new(NoBrowser),
        )
        .unwrap();
        let generation = sessions.start().unwrap();
        (sessions, generation)
    }

    fn reserved(sessions: &Sessions, generation: u64) -> u64 {
        sessions
            .state
            .lock()
            .unwrap()
            .current(generation)
            .unwrap()
            .reserved
    }

    #[test]
    fn a_handed_over_file_is_quarantined_and_previewed_as_a_download_is() {
        let dir = tempfile::tempdir().unwrap();
        let (sessions, generation) = open(&dir);
        let intake = Arc::clone(&sessions)
            .begin_intake(
                generation,
                "../notes\u{202e}txt.exe".into(),
                Some("text/plain".into()),
            )
            .unwrap();
        intake.write(b"hello ".to_vec()).unwrap();
        intake.write(b"from another app".to_vec()).unwrap();
        let file = intake.finish().unwrap();
        assert_eq!(file.size, 22);
        assert_eq!(file.source, "another app");
        assert!(!file.display_name.contains('/'), "{}", file.display_name);
        assert!(
            !file.display_name.contains('\u{202e}'),
            "{}",
            file.display_name
        );
        assert_eq!(sessions.quarantine(generation), vec![file.clone()]);
        assert_eq!(reserved(&sessions, generation), 22);
        match Arc::clone(&sessions)
            .preview(generation, file.id, 64, 64)
            .unwrap()
        {
            Preview::Text { text, .. } => assert_eq!(text, "hello from another app"),
            other => panic!("expected text, got {other:?}"),
        }
        // Nothing readable on disk.
        for entry in walk(dir.path()) {
            let bytes = std::fs::read(&entry).unwrap();
            assert!(
                !bytes.windows(10).any(|w| w == b"from anoth"),
                "{}",
                entry.display()
            );
        }
    }

    #[test]
    fn a_file_over_the_limit_is_discarded_and_frees_its_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let (sessions, generation) = open(&dir);
        let intake = Arc::clone(&sessions)
            .begin_intake(generation, "big.bin".into(), None)
            .unwrap();
        let limit = DownloadPolicy::default().max_bytes;
        assert_eq!(reserved(&sessions, generation), limit);
        let chunk = vec![0u8; 8 * 1024 * 1024];
        let failure = (0..=limit / chunk.len() as u64)
            .find_map(|_| intake.write(chunk.clone()).err())
            .expect("the limit was not enforced");
        assert!(
            matches!(failure, DownloadFailure::NotCaptured { .. }),
            "{failure:?}"
        );
        assert!(intake.finish().is_err());
        assert_eq!(reserved(&sessions, generation), 0);
        assert!(sessions.quarantine(generation).is_empty());
    }

    #[test]
    fn a_reset_ends_an_intake_and_nothing_reaches_the_next_session() {
        let dir = tempfile::tempdir().unwrap();
        let (sessions, generation) = open(&dir);
        let intake = Arc::clone(&sessions)
            .begin_intake(generation, "a.txt".into(), None)
            .unwrap();
        intake.write(b"before the reset".to_vec()).unwrap();
        sessions.reset().unwrap();
        let next = sessions.start().unwrap();
        assert!(matches!(
            intake.write(b"after".to_vec()),
            Err(DownloadFailure::SessionEnded)
        ));
        assert!(intake.finish().is_err());
        assert!(sessions.quarantine(next).is_empty());
        assert!(matches!(
            Arc::clone(&sessions).begin_intake(generation, "late.txt".into(), None),
            Err(DownloadFailure::SessionEnded)
        ));
    }

    #[test]
    fn an_abandoned_intake_frees_its_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let (sessions, generation) = open(&dir);
        let intake = Arc::clone(&sessions)
            .begin_intake(generation, "a.txt".into(), None)
            .unwrap();
        intake.write(b"partial".to_vec()).unwrap();
        drop(intake);
        assert_eq!(reserved(&sessions, generation), 0);
        assert!(sessions.quarantine(generation).is_empty());
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walk(&path));
            } else {
                found.push(path);
            }
        }
        found
    }
}
