//! Sealed objects (docs/architecture.md §11.1): what each session's
//! quarantine stores on disk.
//!
//! * Objects are age v1 files encrypted to a key that exists only in memory
//!   for one session, so a session's files are unreadable once it ends.
//! * Each object's plaintext SHA-256 and size are recorded when it is sealed
//!   and checked after decryption, so swapped, truncated or substituted
//!   objects fail.

use std::fmt;
use std::io::{self, Read, Write};
use std::iter;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::transfer::SealingWriter;

const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed (wrong key, truncated, or tampered): {0}")]
    Decrypt(String),
    #[error("content exceeds the {0}-byte limit")]
    TooLarge(u64),
    #[error("decrypted content does not match its index record")]
    ContentMismatch,
    #[error("system randomness unavailable")]
    Randomness,
}

/// Random object identifier; storage names never reveal content hashes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObjectId([u8; 16]);

impl ObjectId {
    pub fn random() -> Result<Self, SealError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| SealError::Randomness)?;
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.to_hex())
    }
}

/// A key that seals objects to itself: each session's quarantine has its
/// own, held only in memory and dropped with the session. Never logged.
pub struct SealKey {
    identity: age::x25519::Identity,
}

impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealKey(<redacted>)")
    }
}

impl SealKey {
    pub fn generate() -> Self {
        Self {
            identity: age::x25519::Identity::generate(),
        }
    }

    pub fn recipient(&self) -> age::x25519::Recipient {
        self.identity.to_public()
    }
}

/// The hash and size of one sealed object's plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub sha256: [u8; 32],
    pub size: u64,
}

/// Encrypts at most `limit` bytes of `plaintext` into `out`, hashing as it goes.
/// On `TooLarge` the partial output must be discarded by the caller.
pub fn seal(
    recipient: &age::x25519::Recipient,
    mut plaintext: impl Read,
    out: impl Write,
    limit: u64,
) -> Result<Sealed, SealError> {
    let mut writer = SealingWriter::new(recipient, out, limit)?;
    io::copy(&mut plaintext, &mut writer).map_err(|e| {
        if e.kind() == io::ErrorKind::FileTooLarge {
            SealError::TooLarge(limit)
        } else {
            SealError::Io(e)
        }
    })?;
    writer.finish()
}

/// Decrypts `ciphertext` into `out` and verifies it against `expected`.
/// On any error, everything written to `out` must be discarded: the bytes are
/// only trustworthy once this function returns `Ok`.
pub fn open(
    key: &SealKey,
    ciphertext: impl Read,
    expected: &Sealed,
    mut out: impl Write,
) -> Result<(), SealError> {
    let mut reader = decryptor(ciphertext, &key.identity)?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|e| SealError::Decrypt(e.to_string()))?;
        let Some(chunk) = buffer.get(..n).filter(|c| !c.is_empty()) else {
            break;
        };
        size = size.saturating_add(u64::try_from(n).map_err(|_| SealError::ContentMismatch)?);
        if size > expected.size {
            return Err(SealError::ContentMismatch);
        }
        hasher.update(chunk);
        out.write_all(chunk)?;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if size != expected.size || digest != expected.sha256 {
        return Err(SealError::ContentMismatch);
    }
    Ok(())
}

fn decryptor<'a, R: Read + 'a>(
    ciphertext: R,
    identity: &'a dyn age::Identity,
) -> Result<impl Read + 'a, SealError> {
    let decryptor =
        age::Decryptor::new(ciphertext).map_err(|e| SealError::Decrypt(e.to_string()))?;
    decryptor
        .decrypt(iter::once(identity))
        .map_err(|e| SealError::Decrypt(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic on known-small values
mod tests {
    use super::*;

    const LIMIT: u64 = 10 * 1024 * 1024;

    fn sealed(key: &SealKey, plaintext: &[u8]) -> (Vec<u8>, Sealed) {
        let mut ciphertext = Vec::new();
        let record = seal(&key.recipient(), plaintext, &mut ciphertext, LIMIT);
        assert!(record.is_ok(), "{record:?}");
        (
            ciphertext,
            record.unwrap_or(Sealed {
                sha256: [0; 32],
                size: 0,
            }),
        )
    }

    fn opened(key: &SealKey, ciphertext: &[u8], record: &Sealed) -> Result<Vec<u8>, SealError> {
        let mut out = Vec::new();
        open(key, ciphertext, record, &mut out).map(|()| out)
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn round_trip_multi_chunk() {
        let key = SealKey::generate();
        let plaintext = sample(300_000); // > 4 STREAM chunks
        let (ciphertext, record) = sealed(&key, &plaintext);
        assert_eq!(record.size, 300_000);
        assert_eq!(opened(&key, &ciphertext, &record).ok(), Some(plaintext));
    }

    #[test]
    fn truncation_is_detected() {
        let key = SealKey::generate();
        let (ciphertext, record) = sealed(&key, &sample(200_000));
        for cut in [1, 17, 65_536, ciphertext.len() / 2] {
            let truncated = &ciphertext[..ciphertext.len() - cut];
            assert!(
                opened(&key, truncated, &record).is_err(),
                "truncation by {cut} accepted"
            );
        }
    }

    #[test]
    fn tampering_is_detected_anywhere() {
        let key = SealKey::generate();
        let (ciphertext, record) = sealed(&key, &sample(150_000));
        for position in [10, 200, ciphertext.len() / 2, ciphertext.len() - 1] {
            let mut tampered = ciphertext.clone();
            tampered[position] ^= 0x01;
            assert!(
                opened(&key, &tampered, &record).is_err(),
                "flip at {position} accepted"
            );
        }
    }

    #[test]
    fn swapped_object_is_detected() {
        let key = SealKey::generate();
        let (ciphertext_a, _) = sealed(&key, b"document A");
        let (_, record_b) = sealed(&key, b"document B");
        assert!(matches!(
            opened(&key, &ciphertext_a, &record_b),
            Err(SealError::ContentMismatch)
        ));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (ciphertext, record) = sealed(&SealKey::generate(), b"secret");
        assert!(matches!(
            opened(&SealKey::generate(), &ciphertext, &record),
            Err(SealError::Decrypt(_))
        ));
    }

    #[test]
    fn seal_enforces_the_limit_on_the_stream() {
        let key = SealKey::generate();
        let result = seal(&key.recipient(), sample(5000).as_slice(), Vec::new(), 4096);
        assert!(matches!(result, Err(SealError::TooLarge(4096))));
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let key = SealKey::generate();
        assert_eq!(format!("{key:?}"), "SealKey(<redacted>)");
    }
}
