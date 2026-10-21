//! The Rift Vault on Linux (docs/architecture.md §14): rift-core's vault,
//! protected by a passphrase only. Linux has no platform key Rift trusts
//! yet; the Secret portal is a later option (§9).
//!
//! The vault keeps the original files, still untrusted. Exporting one puts
//! a copy outside Rift's protection, where the user chose, through the file
//! chooser portal.
//!
//! The passphrase crosses from QML as a `QString`, whose memory Qt manages:
//! Rift overwrites its own copies after use, and does not claim that every
//! copy is erased (§14.2).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rift_ffi::{Sessions, VaultEntry, VaultHandle, VaultProtection, vault_protection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Missing,
    Locked,
    Unlocked,
    /// Made by a platform that holds its key elsewhere (not by Linux).
    Unusable,
}

#[derive(Debug)]
pub struct Locker {
    dir: PathBuf,
    handle: Mutex<Option<Arc<VaultHandle>>>,
}

impl Locker {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
            handle: Mutex::new(None),
        }
    }

    pub fn state(&self) -> State {
        match vault_protection(self.dir_string()) {
            None => State::Missing,
            Some(VaultProtection::Platform) => State::Unusable,
            Some(VaultProtection::Passphrase) => match &*self.handle() {
                Some(vault) if vault.is_unlocked() => State::Unlocked,
                _ => State::Locked,
            },
        }
    }

    /// Creates a vault protected by `passphrase` (10 characters or more),
    /// unlocked.
    pub fn create(&self, passphrase: String) -> Result<(), String> {
        let vault = VaultHandle::create_with_passphrase(self.dir_string(), secret(passphrase))
            .map_err(|e| e.to_string())?;
        *self.handle() = Some(vault);
        Ok(())
    }

    pub fn unlock(&self, passphrase: String) -> Result<(), String> {
        let mut handle = self.handle();
        let vault = match &*handle {
            Some(vault) => Arc::clone(vault),
            None => VaultHandle::open(self.dir_string()).map_err(|e| e.to_string())?,
        };
        vault
            .unlock_with_passphrase(secret(passphrase))
            .map_err(|e| e.to_string())?;
        *handle = Some(vault);
        Ok(())
    }

    /// Drops the identity and the index from memory.
    pub fn lock(&self) -> bool {
        match &*self.handle() {
            Some(vault) if vault.is_unlocked() => {
                vault.lock();
                true
            }
            _ => false,
        }
    }

    pub fn entries(&self) -> Result<Vec<VaultEntry>, String> {
        self.unlocked()?.entries().map_err(|e| e.to_string())
    }

    /// Copies quarantined file `file_id` of `generation` into the vault.
    pub fn keep(
        &self,
        sessions: &Sessions,
        generation: u64,
        file_id: &str,
        now_unix: u64,
    ) -> Result<VaultEntry, String> {
        sessions
            .save_to_vault(generation, file_id.to_owned(), self.unlocked()?, now_unix)
            .map_err(|e| e.to_string())
    }

    pub fn remove(&self, id: &str) -> Result<(), String> {
        self.unlocked()?
            .remove(id.to_owned())
            .map_err(|e| e.to_string())
    }

    /// Writes kept file `id` to `target`, which the user chose in the file
    /// chooser (and agreed to replace, if it exists), and returns its size.
    pub fn export(&self, id: &str, target: &Path) -> Result<u64, String> {
        let mut bytes = self
            .unlocked()?
            .read(id.to_owned())
            .map_err(|e| e.to_string())?;
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(target)
            .and_then(|mut file| {
                file.write_all(&bytes)?;
                file.sync_all()
            });
        let size = bytes.len();
        bytes.fill(0);
        written.map_err(|e| format!("the chosen file could not be written: {e}"))?;
        Ok(u64::try_from(size).unwrap_or(u64::MAX))
    }

    fn unlocked(&self) -> Result<Arc<VaultHandle>, String> {
        match &*self.handle() {
            Some(vault) if vault.is_unlocked() => Ok(Arc::clone(vault)),
            _ => Err("the vault is locked".into()),
        }
    }

    fn handle(&self) -> MutexGuard<'_, Option<Arc<VaultHandle>>> {
        self.handle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn dir_string(&self) -> String {
        self.dir.to_string_lossy().into_owned()
    }
}

/// The passphrase as bytes for rift-ffi, which overwrites them after use.
fn secret(passphrase: String) -> Vec<u8> {
    passphrase.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rift-vault-{name}-{}", std::process::id()));
        let _fresh = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_vault_is_created_locked_and_unlocked_only_with_its_passphrase() {
        let dir = scratch("cycle").join("vault");
        let locker = Locker::new(&dir);
        assert_eq!(locker.state(), State::Missing);
        assert!(locker.create("short".into()).is_err());
        assert_eq!(locker.state(), State::Missing);
        locker.create("a long enough passphrase".into()).unwrap();
        assert_eq!(locker.state(), State::Unlocked);
        assert!(locker.entries().unwrap().is_empty());
        assert!(locker.create("another long passphrase".into()).is_err());

        assert!(locker.lock());
        assert!(!locker.lock());
        assert_eq!(locker.state(), State::Locked);
        assert!(locker.entries().is_err());
        assert!(locker.unlock("the wrong passphrase".into()).is_err());
        assert_eq!(locker.state(), State::Locked);

        // A new controller opens it from disk.
        let again = Locker::new(&dir);
        assert_eq!(again.state(), State::Locked);
        again.unlock("a long enough passphrase".into()).unwrap();
        assert_eq!(again.state(), State::Unlocked);
        assert!(again.remove("no-such-object").is_err());
        let _cleaned = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn nothing_is_exported_while_locked_or_for_a_missing_object() {
        let root = scratch("export");
        let locker = Locker::new(&root.join("vault"));
        let target = root.join("out.bin");
        assert!(locker.export("x", &target).is_err());
        locker.create("a long enough passphrase".into()).unwrap();
        assert!(locker.export("no-such-object", &target).is_err());
        assert!(!target.exists());
        let _cleaned = std::fs::remove_dir_all(&root);
    }
}
