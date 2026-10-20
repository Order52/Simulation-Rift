//! The Rift Vault on disk (docs/architecture.md §14): the files the user
//! chose to keep after a session, encrypted to the vault identity, with the
//! authenticated index from [`crate::vault`].
//!
//! Layout under the vault directory:
//!
//! * `identity.pass`: the identity, age passphrase-encrypted (scrypt), or
//! * `identity.platform`: the identity wrapped by a platform key (Android
//!   Keystore). The platform does the wrapping; this module stores and
//!   returns the opaque blob and never sees the platform key.
//! * `identity.recovery` (optional, platform vaults only): the same identity,
//!   age passphrase-encrypted, for when the platform key is lost (§8.7).
//! * `index.age` (+ `.prev`): the authenticated index.
//! * `objects/<ObjectId>.age`: one age file per saved object.
//!
//! The identity is in memory only while a [`Vault`] is unlocked, and is
//! dropped by [`Vault::lock`] or when the value is dropped. Plaintext is
//! never written to disk by this module: objects are sealed while streamed
//! in and verified while streamed out.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Re-exported so callers hand secrets over without depending on age.
pub use age::secrecy::{ExposeSecret, SecretString};

use crate::vault::{
    self, IndexEntry, KeptScan, ObjectId, VaultError, VaultIndex, VaultKey, read_index, write_index,
};

const PASS_IDENTITY: &str = "identity.pass";
const PLATFORM_IDENTITY: &str = "identity.platform";
const RECOVERY_IDENTITY: &str = "identity.recovery";
const OBJECTS: &str = "objects";
/// A wrapped identity is a few hundred bytes; anything larger is not one.
const MAX_IDENTITY_BYTES: u64 = 64 * 1024;
/// The shortest passphrase accepted for a new vault.
pub const MIN_PASSPHRASE_CHARS: usize = 10;
/// The largest object a vault holds: as large as a quarantined download.
pub const MAX_OBJECT_BYTES: u64 = 100 * 1024 * 1024;

/// How the vault identity is protected at rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Passphrase,
    Platform,
}

#[derive(Debug, thiserror::Error)]
pub enum LockerError {
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("a vault already exists here")]
    Exists,
    #[error("there is no vault here")]
    Missing,
    #[error("the vault is locked")]
    Locked,
    #[error("the passphrase is shorter than {MIN_PASSPHRASE_CHARS} characters")]
    WeakPassphrase,
    #[error("the vault is protected by {0:?}, not by this method")]
    WrongProtection(Protection),
    #[error("the vault has no object {0}")]
    UnknownObject(String),
    #[error("the vault has no recovery passphrase")]
    NoRecovery,
}

/// What a new object is, as the user will see it in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewObject {
    pub display_name: String,
    pub media_type: String,
    pub source_url: Option<String>,
    pub created_unix: u64,
    /// The verdict it had when it was kept, if it was scanned.
    pub scan: Option<KeptScan>,
}

/// An opened vault directory, locked or unlocked.
#[derive(Debug)]
pub struct Vault {
    dir: PathBuf,
    unlocked: Option<Unlocked>,
}

#[derive(Debug)]
struct Unlocked {
    key: VaultKey,
    index: VaultIndex,
}

impl Vault {
    /// How the vault in `dir` is protected, or `None` if there is none.
    pub fn protection(dir: &Path) -> Option<Protection> {
        if dir.join(PASS_IDENTITY).is_file() {
            Some(Protection::Passphrase)
        } else if dir.join(PLATFORM_IDENTITY).is_file() {
            Some(Protection::Platform)
        } else {
            None
        }
    }

    /// Creates a vault whose identity is protected by `passphrase` (age scrypt).
    pub fn create_with_passphrase(
        dir: &Path,
        passphrase: SecretString,
    ) -> Result<Self, LockerError> {
        if passphrase.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(LockerError::WeakPassphrase);
        }
        let key = VaultKey::generate();
        let wrapped = key.wrap_with_passphrase(passphrase)?;
        Self::create(dir, key, PASS_IDENTITY, &wrapped)
    }

    /// Creates a vault whose identity the platform wraps: `wrap` receives the
    /// identity's secret and returns the wrapped form, which is stored. The
    /// secret is not kept anywhere else.
    pub fn create_for_platform(
        dir: &Path,
        wrap: impl FnOnce(&SecretString) -> Result<Vec<u8>, LockerError>,
    ) -> Result<Self, LockerError> {
        let key = VaultKey::generate();
        let wrapped = wrap(&key.export_secret())?;
        Self::create(dir, key, PLATFORM_IDENTITY, &wrapped)
    }

    fn create(dir: &Path, key: VaultKey, name: &str, wrapped: &[u8]) -> Result<Self, LockerError> {
        if Self::protection(dir).is_some() {
            return Err(LockerError::Exists);
        }
        fs::create_dir_all(dir.join(OBJECTS)).map_err(VaultError::from)?;
        // A recovery copy without its vault (left by an interrupted delete)
        // holds another identity; it must not pass for this vault's.
        match fs::remove_file(dir.join(RECOVERY_IDENTITY)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(VaultError::from(e).into());
            }
            _ => {}
        }
        let index = VaultIndex::default();
        write_index(dir, &key, &index)?;
        // The identity last: until it exists, there is no vault to open.
        write_atomically(dir, name, wrapped)?;
        Ok(Self {
            dir: dir.to_owned(),
            unlocked: Some(Unlocked { key, index }),
        })
    }

    /// Opens the vault in `dir`, locked.
    pub fn open(dir: &Path) -> Result<Self, LockerError> {
        Self::protection(dir).ok_or(LockerError::Missing)?;
        Ok(Self {
            dir: dir.to_owned(),
            unlocked: None,
        })
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    pub fn unlock_with_passphrase(&mut self, passphrase: SecretString) -> Result<(), LockerError> {
        let wrapped = self.wrapped(Protection::Passphrase)?;
        let key = VaultKey::unwrap_with_passphrase(&wrapped, passphrase)?;
        self.unlock(key)
    }

    /// The stored platform-wrapped identity, for the platform to unwrap.
    pub fn platform_wrapped(&self) -> Result<Vec<u8>, LockerError> {
        self.wrapped(Protection::Platform)
    }

    /// Unlocks with the identity secret the platform unwrapped from [`Self::platform_wrapped`].
    pub fn unlock_with_secret(&mut self, secret: &SecretString) -> Result<(), LockerError> {
        self.expect_protection(Protection::Platform)?;
        self.unlock(VaultKey::import_secret(secret)?)
    }

    /// Whether the platform vault in `dir` also has a recovery passphrase.
    pub fn has_recovery(dir: &Path) -> bool {
        Self::protection(dir) == Some(Protection::Platform) && dir.join(RECOVERY_IDENTITY).is_file()
    }

    /// Sets (or replaces) the recovery passphrase of an unlocked platform
    /// vault: a second copy of the identity, age scrypt-encrypted, which
    /// opens the vault if the platform key is lost (§8.7).
    pub fn set_recovery_passphrase(&self, passphrase: SecretString) -> Result<(), LockerError> {
        self.expect_protection(Protection::Platform)?;
        if passphrase.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(LockerError::WeakPassphrase);
        }
        let wrapped = self.state()?.key.wrap_with_passphrase(passphrase)?;
        write_atomically(&self.dir, RECOVERY_IDENTITY, &wrapped)?;
        Ok(())
    }

    /// Unlocks a platform vault with its recovery passphrase.
    pub fn unlock_with_recovery(&mut self, passphrase: SecretString) -> Result<(), LockerError> {
        self.expect_protection(Protection::Platform)?;
        if !self.dir.join(RECOVERY_IDENTITY).is_file() {
            return Err(LockerError::NoRecovery);
        }
        let wrapped = self.read_identity(RECOVERY_IDENTITY)?;
        let key = VaultKey::unwrap_with_passphrase(&wrapped, passphrase)?;
        self.unlock(key)
    }

    /// Replaces the stored platform-wrapped identity of an unlocked platform
    /// vault, after its platform key was lost and it was opened with the
    /// recovery passphrase: `wrap` wraps the identity with the new key.
    pub fn rewrap_for_platform(
        &self,
        wrap: impl FnOnce(&SecretString) -> Result<Vec<u8>, LockerError>,
    ) -> Result<(), LockerError> {
        self.expect_protection(Protection::Platform)?;
        let wrapped = wrap(&self.state()?.key.export_secret())?;
        write_atomically(&self.dir, PLATFORM_IDENTITY, &wrapped)?;
        Ok(())
    }

    fn expect_protection(&self, expected: Protection) -> Result<(), LockerError> {
        let actual = Self::protection(&self.dir).ok_or(LockerError::Missing)?;
        if actual != expected {
            return Err(LockerError::WrongProtection(actual));
        }
        Ok(())
    }

    fn wrapped(&self, expected: Protection) -> Result<Vec<u8>, LockerError> {
        self.expect_protection(expected)?;
        self.read_identity(match expected {
            Protection::Passphrase => PASS_IDENTITY,
            Protection::Platform => PLATFORM_IDENTITY,
        })
    }

    /// One identity file, bounded: a wrapped identity is a few hundred bytes.
    fn read_identity(&self, name: &str) -> Result<Vec<u8>, LockerError> {
        let mut bytes = Vec::new();
        File::open(self.dir.join(name))
            .map_err(VaultError::from)?
            .take(MAX_IDENTITY_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(VaultError::from)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_IDENTITY_BYTES {
            return Err(VaultError::InvalidKey.into());
        }
        Ok(bytes)
    }

    /// The index must authenticate under `key`; a wrong key or a forged
    /// index fails here, before anything is shown. Then objects the index
    /// does not list (an interrupted save) are removed.
    fn unlock(&mut self, key: VaultKey) -> Result<(), LockerError> {
        let index = read_index(&self.dir, &key)?;
        let listed: Vec<String> = index.entries.iter().map(|e| object_name(e.id)).collect();
        for entry in fs::read_dir(self.dir.join(OBJECTS)).map_err(VaultError::from)? {
            let entry = entry.map_err(VaultError::from)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !listed.contains(&name) {
                fs::remove_file(entry.path()).map_err(VaultError::from)?;
            }
        }
        self.unlocked = Some(Unlocked { key, index });
        Ok(())
    }

    /// Drops the identity and the index from memory (best effort, §14.2).
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    pub fn entries(&self) -> Result<&[IndexEntry], LockerError> {
        Ok(&self.state()?.index.entries)
    }

    /// Seals at most [`MAX_OBJECT_BYTES`] of `plaintext` as a new object.
    /// The object file is complete before the index lists it; on any error
    /// the vault is unchanged.
    pub fn add(
        &mut self,
        plaintext: impl Read,
        object: NewObject,
    ) -> Result<IndexEntry, LockerError> {
        let dir = self.dir.clone();
        let state = self.state_mut()?;
        let id = ObjectId::random()?;
        let name = object_name(id);
        let temp = dir.join(OBJECTS).join(format!("{name}.tmp"));
        let sealed = (|| {
            let mut file = File::create(&temp)?;
            let sealed = vault::seal(
                &state.key.recipient(),
                plaintext,
                &mut file,
                MAX_OBJECT_BYTES,
            )?;
            file.sync_all()?;
            fs::rename(&temp, dir.join(OBJECTS).join(&name))?;
            File::open(dir.join(OBJECTS))?.sync_all()?;
            Ok::<_, VaultError>(sealed)
        })();
        let sealed = match sealed {
            Ok(sealed) => sealed,
            Err(e) => {
                let _ = fs::remove_file(&temp); // nothing was listed; unlock sweeps it otherwise
                return Err(e.into());
            }
        };
        let entry = IndexEntry {
            id,
            sealed,
            display_name: object.display_name,
            media_type: object.media_type,
            source_url: object.source_url,
            created_unix: object.created_unix,
            scan: object.scan,
        };
        let mut next = state.index.clone();
        next.generation = next.generation.saturating_add(1);
        next.entries.push(entry.clone());
        write_index(&dir, &state.key, &next)?;
        state.index = next;
        Ok(entry)
    }

    /// Decrypts object `id` into `out`, verified against the index. On any
    /// error the bytes written to `out` must be discarded.
    pub fn read(&self, id: &str, out: impl Write) -> Result<(), LockerError> {
        let state = self.state()?;
        let entry = find(&state.index, id)?;
        let file = File::open(self.dir.join(OBJECTS).join(object_name(entry.id)))
            .map_err(VaultError::from)?;
        vault::open(&state.key, file, &entry.sealed, out)?;
        Ok(())
    }

    /// Removes object `id`: first from the index, then its file.
    pub fn remove(&mut self, id: &str) -> Result<(), LockerError> {
        let dir = self.dir.clone();
        let state = self.state_mut()?;
        let target = find(&state.index, id)?.id;
        let mut next = state.index.clone();
        next.generation = next.generation.saturating_add(1);
        next.entries.retain(|e| e.id != target);
        write_index(&dir, &state.key, &next)?;
        state.index = next;
        fs::remove_file(dir.join(OBJECTS).join(object_name(target))).map_err(VaultError::from)?;
        Ok(())
    }

    /// Replaces the scan result recorded for object `id`, for a scan with
    /// a later database. Only the index changes.
    pub fn set_scan(&mut self, id: &str, scan: KeptScan) -> Result<IndexEntry, LockerError> {
        let dir = self.dir.clone();
        let state = self.state_mut()?;
        let mut next = state.index.clone();
        next.generation = next.generation.saturating_add(1);
        let entry = next
            .entries
            .iter_mut()
            .find(|e| e.id.to_hex() == id)
            .ok_or_else(|| LockerError::UnknownObject(id.to_owned()))?;
        entry.scan = Some(scan);
        let updated = entry.clone();
        write_index(&dir, &state.key, &next)?;
        state.index = next;
        Ok(updated)
    }

    fn state(&self) -> Result<&Unlocked, LockerError> {
        self.unlocked.as_ref().ok_or(LockerError::Locked)
    }

    fn state_mut(&mut self) -> Result<&mut Unlocked, LockerError> {
        self.unlocked.as_mut().ok_or(LockerError::Locked)
    }
}

fn find<'a>(index: &'a VaultIndex, id: &str) -> Result<&'a IndexEntry, LockerError> {
    index
        .entries
        .iter()
        .find(|e| e.id.to_hex() == id)
        .ok_or_else(|| LockerError::UnknownObject(id.to_owned()))
}

fn object_name(id: ObjectId) -> String {
    format!("{}.age", id.to_hex())
}

/// Temp file, fsync, rename, fsync the directory.
fn write_atomically(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), VaultError> {
    let temp = dir.join(format!("{name}.tmp"));
    {
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp, dir.join(name))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &[u8] = b"RIFT-VAULT-PLAINTEXT-MARKER";

    fn object(name: &str) -> NewObject {
        NewObject {
            display_name: name.into(),
            media_type: "text/plain".into(),
            source_url: Some("https://example.org/report.txt".into()),
            created_unix: 1_000,
            scan: None,
        }
    }

    fn pass(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn read(vault: &Vault, id: &str) -> Result<Vec<u8>, LockerError> {
        let mut out = Vec::new();
        vault.read(id, &mut out).map(|()| out)
    }

    /// Every byte of every file under `dir`.
    fn disk(dir: &Path) -> Vec<u8> {
        let mut all = Vec::new();
        let mut stack = vec![dir.to_owned()];
        while let Some(d) = stack.pop() {
            for entry in fs::read_dir(d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    all.extend(fs::read(path).unwrap());
                }
            }
        }
        all
    }

    #[test]
    fn a_passphrase_vault_keeps_objects_across_lock_and_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        assert_eq!(Vault::protection(&path), None);
        assert!(matches!(
            Vault::create_with_passphrase(&path, pass("short")),
            Err(LockerError::WeakPassphrase)
        ));
        let mut vault =
            Vault::create_with_passphrase(&path, pass("correct horse battery")).unwrap();
        assert_eq!(Vault::protection(&path), Some(Protection::Passphrase));
        let plaintext = [MARKER, b" report body"].concat();
        let entry = vault
            .add(plaintext.as_slice(), object("report.txt"))
            .unwrap();
        let id = entry.id.to_hex();
        assert_eq!(read(&vault, &id).unwrap(), plaintext);
        assert!(matches!(
            Vault::create_with_passphrase(&path, pass("correct horse battery")),
            Err(LockerError::Exists)
        ));

        vault.lock();
        assert!(!vault.is_unlocked());
        assert!(matches!(vault.entries(), Err(LockerError::Locked)));
        assert!(matches!(read(&vault, &id), Err(LockerError::Locked)));

        let mut reopened = Vault::open(&path).unwrap();
        assert!(
            reopened
                .unlock_with_passphrase(pass("wrong horse battery"))
                .is_err()
        );
        assert!(!reopened.is_unlocked());
        reopened
            .unlock_with_passphrase(pass("correct horse battery"))
            .unwrap();
        assert_eq!(reopened.entries().unwrap(), [entry]);
        assert_eq!(read(&reopened, &id).unwrap(), plaintext);
        assert!(matches!(
            reopened.unlock_with_secret(&pass("x")),
            Err(LockerError::WrongProtection(Protection::Passphrase))
        ));

        // No plaintext and no display name anywhere on disk.
        let bytes = disk(&path);
        assert!(!bytes.windows(MARKER.len()).any(|w| w == MARKER));
        assert!(!bytes.windows(10).any(|w| w == b"report.txt"));

        reopened.remove(&id).unwrap();
        assert!(reopened.entries().unwrap().is_empty());
        assert!(matches!(
            read(&reopened, &id),
            Err(LockerError::UnknownObject(_))
        ));
        assert_eq!(fs::read_dir(path.join(OBJECTS)).unwrap().count(), 0);
    }

    #[test]
    fn a_platform_vault_stores_only_the_wrapped_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        // A stand-in for Keystore: reverses the bytes. The vault must store
        // exactly what the platform returned, never the secret itself.
        let mut seen = None;
        let mut vault = Vault::create_for_platform(&path, |secret| {
            seen = Some(secret.expose_secret().to_owned());
            Ok(secret.expose_secret().bytes().rev().collect())
        })
        .unwrap();
        let secret = seen.unwrap();
        let entry = vault.add(MARKER, object("a.txt")).unwrap();
        vault.lock();
        let bytes = disk(&path);
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));

        let mut reopened = Vault::open(&path).unwrap();
        assert!(matches!(
            reopened.unlock_with_passphrase(pass("correct horse battery")),
            Err(LockerError::WrongProtection(Protection::Platform))
        ));
        let unwrapped: String = String::from_utf8(
            reopened
                .platform_wrapped()
                .unwrap()
                .into_iter()
                .rev()
                .collect(),
        )
        .unwrap();
        assert_eq!(unwrapped, secret);
        // Another identity cannot authenticate this vault's index.
        let other = VaultKey::generate().export_secret();
        assert!(reopened.unlock_with_secret(&other).is_err());
        reopened
            .unlock_with_secret(&SecretString::from(unwrapped))
            .unwrap();
        assert_eq!(read(&reopened, &entry.id.to_hex()).unwrap(), MARKER);
    }

    #[test]
    fn a_later_scan_replaces_the_recorded_one_and_only_the_index_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let mut vault =
            Vault::create_with_passphrase(&path, pass("correct horse battery")).unwrap();
        let entry = vault.add(MARKER, object("kept.txt")).unwrap();
        let id = entry.id.to_hex();
        let object_file = path.join(OBJECTS).join(object_name(entry.id));
        let before = fs::read(&object_file).unwrap();
        let scan = KeptScan {
            status: vault::KeptStatus::Suspicious,
            snapshot: Some("demo-2".into()),
            engine: "yara-x".into(),
            demo: true,
            findings: vec!["rules:demo".into()],
            scanned_unix: 2_000,
        };
        assert!(matches!(
            vault.set_scan("00", scan.clone()),
            Err(LockerError::UnknownObject(_))
        ));
        assert_eq!(
            vault.set_scan(&id, scan.clone()).unwrap().scan,
            Some(scan.clone())
        );
        assert_eq!(fs::read(&object_file).unwrap(), before);

        vault.lock();
        assert!(matches!(
            vault.set_scan(&id, scan.clone()),
            Err(LockerError::Locked)
        ));
        let mut reopened = Vault::open(&path).unwrap();
        reopened
            .unlock_with_passphrase(pass("correct horse battery"))
            .unwrap();
        assert_eq!(reopened.entries().unwrap()[0].scan, Some(scan));
        assert_eq!(read(&reopened, &id).unwrap(), MARKER);
    }

    #[test]
    fn the_recovery_passphrase_opens_a_vault_whose_platform_key_is_lost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let reverse = |s: &SecretString| Ok(s.expose_secret().bytes().rev().collect());
        let mut vault = Vault::create_for_platform(&path, reverse).unwrap();
        let entry = vault.add(MARKER, object("kept.txt")).unwrap();
        assert!(!Vault::has_recovery(&path));
        assert!(matches!(
            vault.set_recovery_passphrase(pass("too short")),
            Err(LockerError::WeakPassphrase)
        ));
        vault
            .set_recovery_passphrase(pass("recovery passphrase"))
            .unwrap();
        assert!(Vault::has_recovery(&path));
        vault.lock();
        assert!(matches!(
            vault.set_recovery_passphrase(pass("another passphrase")),
            Err(LockerError::Locked)
        ));

        // The platform key is gone: only the recovery passphrase opens it.
        let mut lost = Vault::open(&path).unwrap();
        assert!(
            lost.unlock_with_recovery(pass("not the passphrase"))
                .is_err()
        );
        assert!(!lost.is_unlocked());
        lost.unlock_with_recovery(pass("recovery passphrase"))
            .unwrap();
        assert_eq!(read(&lost, &entry.id.to_hex()).unwrap(), MARKER);
        // Protected by a new platform key; the old blob is replaced.
        let rotate = |s: &SecretString| {
            let mut bytes: Vec<u8> = s.expose_secret().bytes().collect();
            bytes.rotate_left(1);
            Ok(bytes)
        };
        lost.rewrap_for_platform(rotate).unwrap();
        let mut renewed = Vault::open(&path).unwrap();
        let mut secret = renewed.platform_wrapped().unwrap();
        secret.rotate_right(1);
        renewed
            .unlock_with_secret(&SecretString::from(String::from_utf8(secret).unwrap()))
            .unwrap();
        assert_eq!(renewed.entries().unwrap(), [entry]);
        assert!(!disk(&path).windows(MARKER.len()).any(|w| w == MARKER));

        // Passphrase vaults have no recovery copy; a vault without one says so.
        let other = dir.path().join("other");
        let mut plain = Vault::create_with_passphrase(&other, pass("correct horse")).unwrap();
        assert!(matches!(
            plain.set_recovery_passphrase(pass("recovery passphrase")),
            Err(LockerError::WrongProtection(Protection::Passphrase))
        ));
        assert!(matches!(
            plain.unlock_with_recovery(pass("recovery passphrase")),
            Err(LockerError::WrongProtection(Protection::Passphrase))
        ));
        let bare = dir.path().join("bare");
        Vault::create_for_platform(&bare, reverse).unwrap();
        assert!(matches!(
            Vault::open(&bare)
                .unwrap()
                .unlock_with_recovery(pass("recovery passphrase")),
            Err(LockerError::NoRecovery)
        ));
    }

    #[test]
    fn a_stale_recovery_copy_does_not_survive_into_a_new_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let reverse = |s: &SecretString| Ok(s.expose_secret().bytes().rev().collect());
        let vault = Vault::create_for_platform(&path, reverse).unwrap();
        vault
            .set_recovery_passphrase(pass("recovery passphrase"))
            .unwrap();
        // As if a delete stopped after removing the platform identity.
        fs::remove_file(path.join(PLATFORM_IDENTITY)).unwrap();
        drop(vault);
        Vault::create_for_platform(&path, reverse).unwrap();
        assert!(!Vault::has_recovery(&path));
    }

    #[test]
    fn an_interrupted_save_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let mut vault =
            Vault::create_with_passphrase(&path, pass("correct horse battery")).unwrap();
        let kept = vault.add(MARKER, object("kept.txt")).unwrap();
        // As if the process died after writing an object but before the index.
        fs::write(
            path.join(OBJECTS)
                .join("0123456789abcdef0123456789abcdef.age"),
            b"orphan",
        )
        .unwrap();
        fs::write(path.join(OBJECTS).join("x.age.tmp"), b"partial").unwrap();
        vault.lock();
        vault
            .unlock_with_passphrase(pass("correct horse battery"))
            .unwrap();
        let names: Vec<String> = fs::read_dir(path.join(OBJECTS))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [object_name(kept.id)]);
    }

    #[test]
    fn oversized_objects_are_refused_and_not_listed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let mut vault =
            Vault::create_with_passphrase(&path, pass("correct horse battery")).unwrap();
        let endless = std::io::repeat(b'x').take(MAX_OBJECT_BYTES + 1);
        assert!(matches!(
            vault.add(endless, object("big")),
            Err(LockerError::Vault(VaultError::TooLarge(_)))
        ));
        assert!(vault.entries().unwrap().is_empty());
        assert_eq!(fs::read_dir(path.join(OBJECTS)).unwrap().count(), 0);
    }

    #[test]
    fn a_swapped_object_fails_its_index_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let mut vault =
            Vault::create_with_passphrase(&path, pass("correct horse battery")).unwrap();
        let a = vault.add(&b"first object"[..], object("a")).unwrap();
        let b = vault.add(&b"second object"[..], object("b")).unwrap();
        fs::copy(
            path.join(OBJECTS).join(object_name(b.id)),
            path.join(OBJECTS).join(object_name(a.id)),
        )
        .unwrap();
        assert!(matches!(
            read(&vault, &a.id.to_hex()),
            Err(LockerError::Vault(VaultError::ContentMismatch))
        ));
    }
}
