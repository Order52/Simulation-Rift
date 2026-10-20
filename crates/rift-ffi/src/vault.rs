//! The Rift Vault for the Android controller (docs/architecture.md §14):
//! rift-core's `locker::Vault` behind one mutex, with the platform key
//! (Android Keystore, §8.7) as a foreign trait.
//!
//! Secrets cross into Kotlin only where the platform must handle them: the
//! identity secret for Keystore to wrap, and back once Keystore unwrapped it.
//! They cross as bytes, which both sides overwrite after use (best effort:
//! Rift does not claim that every runtime copy is erased, §14.2).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rift_core::locker::{
    self, ExposeSecret, LockerError, NewObject, Protection, SecretString, Vault,
};
use rift_core::scan::Status;
use rift_core::text::escape_for_display;
use rift_core::vault::{IndexEntry, KeptScan, KeptStatus, VaultError};

use crate::{
    Content, MAX_PREVIEW_INPUT, Preview, PreviewFailure, PreviewOwner, ReadFailure, ScanStatus,
    Sessions, Verdict, prepare_preview,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultProtection {
    Passphrase,
    /// Wrapped by a key the platform holds (Android Keystore).
    Platform,
}

/// One saved object, as the vault screen shows it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultEntry {
    pub id: String,
    /// Escaped for display.
    pub display_name: String,
    pub media_type: String,
    pub size: u64,
    pub sha256: String,
    pub source_url: Option<String>,
    pub created_unix: u64,
    /// The verdict when it was kept, if it had been scanned.
    pub scan: Option<KeptVerdict>,
}

/// The scan verdict a kept file had when it was kept: history, bound to the
/// database and engine it names, never a current verdict (§12.3).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeptVerdict {
    pub status: ScanStatus,
    /// "Known malicious", "Suspicious", "Not flagged" or "Not fully scanned".
    pub label: String,
    pub snapshot: Option<String>,
    pub engine: String,
    pub demo: bool,
    /// `check:id` of each finding.
    pub findings: Vec<String>,
    pub scanned_unix: u64,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultFailure {
    #[error("there is no vault")]
    Missing,
    #[error("a vault already exists")]
    Exists,
    #[error("the vault is locked")]
    Locked,
    #[error("the passphrase must have at least {minimum} characters")]
    WeakPassphrase { minimum: u32 },
    /// The passphrase or the unwrapped secret does not open this vault.
    #[error("the vault could not be unlocked with this secret")]
    WrongSecret,
    #[error("the vault is protected another way")]
    WrongProtection,
    #[error("the vault has no such object")]
    UnknownObject,
    #[error("the vault has no recovery passphrase")]
    NoRecovery,
    #[error("the file is larger than the vault's {limit}-byte limit")]
    TooLarge { limit: u64 },
    /// Stored data failed its check (a swapped object, a malformed index).
    #[error("vault data failed its check: {detail}")]
    Damaged { detail: String },
    #[error("vault storage failed: {detail}")]
    Storage { detail: String },
    /// The platform key could not wrap the secret (no lock screen, auth refused).
    #[error("the platform key failed: {detail}")]
    Platform { detail: String },
    #[error("the session has ended")]
    SessionEnded,
    #[error("no such file in this session")]
    NotFound,
    #[error("vault state is unusable after an internal error")]
    Poisoned,
}

impl From<LockerError> for VaultFailure {
    fn from(error: LockerError) -> Self {
        match error {
            LockerError::Missing => Self::Missing,
            LockerError::Exists => Self::Exists,
            LockerError::Locked => Self::Locked,
            LockerError::WeakPassphrase => Self::WeakPassphrase {
                minimum: u32::try_from(locker::MIN_PASSPHRASE_CHARS).unwrap_or(u32::MAX),
            },
            LockerError::WrongProtection(_) => Self::WrongProtection,
            LockerError::UnknownObject(_) => Self::UnknownObject,
            LockerError::NoRecovery => Self::NoRecovery,
            LockerError::Vault(e) => match e {
                // A wrong key cannot decrypt or authenticate the index.
                VaultError::Decrypt(_) | VaultError::IndexNotAuthentic | VaultError::InvalidKey => {
                    Self::WrongSecret
                }
                VaultError::TooLarge(limit) => Self::TooLarge { limit },
                VaultError::ContentMismatch
                | VaultError::IndexMalformed(_)
                | VaultError::IndexMissing => Self::Damaged {
                    detail: e.to_string(),
                },
                other => Self::Storage {
                    detail: other.to_string(),
                },
            },
        }
    }
}

/// The platform's half of a [`VaultProtection::Platform`] vault: wraps the
/// new identity's secret with a key the platform holds. Unwrapping is the
/// platform's too; the result goes to [`VaultHandle::unlock_with_secret`].
#[uniffi::export(with_foreign)]
pub trait PlatformKey: Send + Sync {
    fn wrap(&self, secret: Vec<u8>) -> Result<Vec<u8>, VaultFailure>;
}

/// How the vault in `dir` is protected; `None` if there is no vault.
#[uniffi::export]
pub fn vault_protection(dir: String) -> Option<VaultProtection> {
    Vault::protection(std::path::Path::new(&dir)).map(|p| match p {
        Protection::Passphrase => VaultProtection::Passphrase,
        Protection::Platform => VaultProtection::Platform,
    })
}

/// Whether the platform vault in `dir` also has a recovery passphrase (§8.7).
#[uniffi::export]
pub fn vault_has_recovery(dir: String) -> bool {
    Vault::has_recovery(std::path::Path::new(&dir))
}

#[derive(Debug, uniffi::Object)]
pub struct VaultHandle {
    vault: Mutex<Vault>,
    /// Counts locks, so that a preview started before a lock is refused
    /// even if the vault was unlocked again meanwhile.
    locks: AtomicU64,
    next_job: AtomicU64,
}

#[uniffi::export]
impl VaultHandle {
    /// Creates a vault protected by `passphrase`, unlocked.
    #[uniffi::constructor]
    pub fn create_with_passphrase(
        dir: String,
        passphrase: Vec<u8>,
    ) -> Result<Arc<Self>, VaultFailure> {
        let passphrase = secret_from(passphrase)?;
        Ok(Self::wrap(Vault::create_with_passphrase(
            std::path::Path::new(&dir),
            passphrase,
        )?))
    }

    /// Creates a vault whose identity `key` wraps, unlocked.
    #[uniffi::constructor]
    pub fn create_for_platform(
        dir: String,
        key: Arc<dyn PlatformKey>,
    ) -> Result<Arc<Self>, VaultFailure> {
        let dir = std::path::Path::new(&dir);
        // Before the platform prompts the user for a key that would go unused.
        if Vault::protection(dir).is_some() {
            return Err(VaultFailure::Exists);
        }
        let mut failure = None;
        let created = Vault::create_for_platform(dir, |secret| {
            key.wrap(secret.expose_secret().as_bytes().to_vec())
                .map_err(|e| {
                    failure = Some(e);
                    // Mapped back below; the vault was not created.
                    LockerError::Missing
                })
        });
        match (created, failure) {
            (Ok(vault), _) => Ok(Self::wrap(vault)),
            (Err(_), Some(platform)) => Err(platform),
            (Err(e), None) => Err(e.into()),
        }
    }

    /// Opens the vault in `dir`, locked.
    #[uniffi::constructor]
    pub fn open(dir: String) -> Result<Arc<Self>, VaultFailure> {
        Ok(Self::wrap(Vault::open(std::path::Path::new(&dir))?))
    }

    pub fn is_unlocked(&self) -> bool {
        self.lock_state().is_ok_and(|v| v.is_unlocked())
    }

    pub fn unlock_with_passphrase(&self, passphrase: Vec<u8>) -> Result<(), VaultFailure> {
        let passphrase = secret_from(passphrase)?;
        Ok(self.lock_state()?.unlock_with_passphrase(passphrase)?)
    }

    /// Sets the recovery passphrase of an unlocked platform vault.
    pub fn set_recovery_passphrase(&self, passphrase: Vec<u8>) -> Result<(), VaultFailure> {
        let passphrase = secret_from(passphrase)?;
        Ok(self.lock_state()?.set_recovery_passphrase(passphrase)?)
    }

    /// Unlocks a platform vault whose platform key is lost.
    pub fn unlock_with_recovery(&self, passphrase: Vec<u8>) -> Result<(), VaultFailure> {
        let passphrase = secret_from(passphrase)?;
        Ok(self.lock_state()?.unlock_with_recovery(passphrase)?)
    }

    /// Protects the unlocked platform vault's identity with a new platform
    /// key (after recovery), replacing the stored wrapped identity.
    pub fn rewrap_for_platform(&self, key: Arc<dyn PlatformKey>) -> Result<(), VaultFailure> {
        let mut failure = None;
        let rewrapped = self.lock_state()?.rewrap_for_platform(|secret| {
            key.wrap(secret.expose_secret().as_bytes().to_vec())
                .map_err(|e| {
                    failure = Some(e);
                    // Mapped back below; the stored identity is unchanged.
                    LockerError::Missing
                })
        });
        match (rewrapped, failure) {
            (Ok(()), _) => Ok(()),
            (Err(_), Some(platform)) => Err(platform),
            (Err(e), None) => Err(e.into()),
        }
    }

    /// The stored wrapped identity, for the platform to unwrap.
    pub fn platform_wrapped(&self) -> Result<Vec<u8>, VaultFailure> {
        Ok(self.lock_state()?.platform_wrapped()?)
    }

    pub fn unlock_with_secret(&self, secret: Vec<u8>) -> Result<(), VaultFailure> {
        let secret = secret_from(secret)?;
        Ok(self.lock_state()?.unlock_with_secret(&secret)?)
    }

    /// Drops the identity and the index from memory, and ends every
    /// preview of a vault object that has not finished.
    pub fn lock(&self) {
        self.locks.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut vault) = self.lock_state() {
            vault.lock();
        }
    }

    pub fn entries(&self) -> Result<Vec<VaultEntry>, VaultFailure> {
        Ok(self.lock_state()?.entries()?.iter().map(entry).collect())
    }

    /// The verified plaintext of object `id`, for an export the user chose.
    pub fn read(&self, id: String) -> Result<Vec<u8>, VaultFailure> {
        let mut out = Vec::new();
        self.lock_state()?.read(&id, &mut out)?;
        Ok(out)
    }

    pub fn remove(&self, id: String) -> Result<(), VaultFailure> {
        Ok(self.lock_state()?.remove(&id)?)
    }

    /// Prepares a preview of object `id` exactly as for a quarantined file
    /// (§11.3): the verified plaintext goes to a fresh isolated worker, or is
    /// shown as escaped text. The result is refused if the vault is locked
    /// before the worker answers.
    pub fn preview(
        self: Arc<Self>,
        id: String,
        max_width: u32,
        max_height: u32,
    ) -> Result<Preview, PreviewFailure> {
        let unlock = self.locks.load(Ordering::SeqCst);
        let input = {
            let vault = self.lock_state().map_err(|_| PreviewFailure::Poisoned)?;
            let entries = vault.entries().map_err(|_| PreviewFailure::Locked)?;
            let size = entries
                .iter()
                .find(|e| e.id.to_hex() == id)
                .ok_or(PreviewFailure::NotFound)?
                .sealed
                .size;
            if size > MAX_PREVIEW_INPUT {
                return Err(PreviewFailure::TooLarge {
                    limit: MAX_PREVIEW_INPUT,
                });
            }
            let mut input = Vec::new();
            vault
                .read(&id, &mut input)
                .map_err(|e| PreviewFailure::Storage {
                    detail: e.to_string(),
                })?;
            input
        };
        let job_id = self.next_job.fetch_add(2, Ordering::SeqCst);
        let owner = PreviewOwner::Vault {
            vault: self,
            unlock,
        };
        // Vault previews belong to no session; generation 0 is never a session's.
        prepare_preview(owner, 0, job_id, input, max_width, max_height)
    }
}

impl VaultHandle {
    fn wrap(vault: Vault) -> Arc<Self> {
        Arc::new(Self {
            vault: Mutex::new(vault),
            locks: AtomicU64::new(0),
            next_job: AtomicU64::new(1),
        })
    }

    /// Unlocked, and not locked since `unlock` was read.
    pub(crate) fn still_unlocked(&self, unlock: u64) -> bool {
        self.locks.load(Ordering::SeqCst) == unlock && self.is_unlocked()
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, Vault>, VaultFailure> {
        self.vault.lock().map_err(|_| VaultFailure::Poisoned)
    }
}

#[uniffi::export]
impl Sessions {
    /// Copies quarantined file `file_id` of `generation` into the unlocked
    /// vault (§14): decrypted with the session key in memory, verified, and
    /// sealed to the vault identity. The quarantined copy is unchanged and
    /// still ends with the session.
    pub fn save_to_vault(
        &self,
        generation: u64,
        file_id: String,
        vault: Arc<VaultHandle>,
        now_unix: u64,
    ) -> Result<VaultEntry, VaultFailure> {
        let (file, content) = self
            .read_quarantined(generation, &file_id, locker::MAX_OBJECT_BYTES)
            .map_err(|e| match e {
                ReadFailure::SessionEnded => VaultFailure::SessionEnded,
                ReadFailure::NotFound => VaultFailure::NotFound,
                ReadFailure::Storage(detail) => VaultFailure::Storage { detail },
                ReadFailure::Poisoned => VaultFailure::Poisoned,
            })?;
        let Content::Whole(bytes) = content else {
            return Err(VaultFailure::TooLarge {
                limit: locker::MAX_OBJECT_BYTES,
            });
        };
        let scan = self
            .verdict(generation, file_id)
            .map(|v| kept_scan(&v, now_unix));
        // The quarantine keeps only the display-safe forms; escaping them
        // again when shown changes nothing, as escapes contain no characters
        // that are escaped.
        let saved = vault.lock_state()?.add(
            bytes.as_slice(),
            NewObject {
                display_name: file.display_name,
                media_type: file
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".into()),
                source_url: Some(file.source),
                created_unix: now_unix,
                scan,
            },
        )?;
        Ok(entry(&saved))
    }
}

fn kept_scan(v: &Verdict, now_unix: u64) -> KeptScan {
    KeptScan {
        status: match v.status {
            ScanStatus::KnownMalicious => KeptStatus::KnownMalicious,
            ScanStatus::Suspicious => KeptStatus::Suspicious,
            ScanStatus::NotFlagged => KeptStatus::NotFlagged,
            ScanStatus::NotFullyScanned => KeptStatus::NotFullyScanned,
        },
        snapshot: v.snapshot.clone(),
        engine: v.engine.clone(),
        demo: v.demo,
        findings: v
            .findings
            .iter()
            .map(|f| format!("{}:{}", f.check, f.id))
            .collect(),
        scanned_unix: now_unix,
    }
}

fn kept_verdict(k: &KeptScan) -> KeptVerdict {
    let (status, core) = match k.status {
        KeptStatus::KnownMalicious => (ScanStatus::KnownMalicious, Status::KnownMalicious),
        KeptStatus::Suspicious => (ScanStatus::Suspicious, Status::Suspicious),
        KeptStatus::NotFlagged => (ScanStatus::NotFlagged, Status::NotFlagged),
        KeptStatus::NotFullyScanned => (ScanStatus::NotFullyScanned, Status::NotFullyScanned),
    };
    KeptVerdict {
        status,
        label: core.label().to_owned(),
        snapshot: k.snapshot.as_deref().map(escape_for_display),
        engine: escape_for_display(&k.engine),
        demo: k.demo,
        findings: k.findings.iter().map(|f| escape_for_display(f)).collect(),
        scanned_unix: k.scanned_unix,
    }
}

fn entry(e: &IndexEntry) -> VaultEntry {
    VaultEntry {
        id: e.id.to_hex(),
        display_name: escape_for_display(&e.display_name),
        media_type: escape_for_display(&e.media_type),
        size: e.sealed.size,
        sha256: hex::encode(e.sealed.sha256),
        source_url: e.source_url.as_deref().map(escape_for_display),
        created_unix: e.created_unix,
        scan: e.scan.as_ref().map(kept_verdict),
    }
}

/// Takes a secret that crossed the FFI as bytes; the byte copy is overwritten.
fn secret_from(mut bytes: Vec<u8>) -> Result<SecretString, VaultFailure> {
    let text = String::from_utf8(bytes.clone()).map_err(|_| VaultFailure::WrongSecret);
    bytes.fill(0);
    Ok(SecretString::from(text?))
}
