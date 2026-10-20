//! Vault storage format (docs/architecture.md §14).
//!
//! * Objects are age v1 files encrypted to the vault's X25519 recipient.
//! * The index is age-encrypted **and** authenticated with an HMAC keyed from
//!   the vault identity. age recipient encryption is not sender-authenticated —
//!   anyone holding the public recipient could produce a well-formed index — so
//!   the MAC is what makes the index trustworthy. It is verified before parsing.
//! * Each object's plaintext SHA-256 and size live in the authenticated index
//!   and are checked after decryption, so swapped or substituted objects fail.
//! * Index format 2 adds the scan verdict a file had when it was kept
//!   ([`KeptScan`]); format 1 indexes are still read, without one.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::iter;
use std::path::Path;

use age::secrecy::{ExposeSecret, SecretString};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::transfer::SealingWriter;

pub const INDEX_FORMAT_VERSION: u32 = 2;
/// The index is small metadata; anything larger is refused before decryption.
pub const MAX_INDEX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const INDEX_FILE: &str = "index.age";
const INDEX_PREVIOUS: &str = "index.age.prev";
const INDEX_TEMP: &str = "index.age.tmp";
const MAC_LEN: usize = 32;
const MAC_CONTEXT: &[u8] = b"simulation-rift vault index mac v1";
const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
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
    #[error("index authentication failed")]
    IndexNotAuthentic,
    #[error("index is malformed: {0}")]
    IndexMalformed(String),
    #[error("no index found")]
    IndexMissing,
    #[error("system randomness unavailable")]
    Randomness,
    #[error("invalid key material")]
    InvalidKey,
    /// A passphrase-wrapped identity asks for more scrypt work than Rift
    /// writes: not a wrong passphrase, and not a file Rift wrote.
    #[error(
        "the passphrase protection needs scrypt work factor {required}; Rift writes and accepts {allowed}"
    )]
    ExcessiveWork { required: u8, allowed: u8 },
}

/// The scrypt work factor (N = 2^17: 128 MiB, about a second on a phone)
/// for every passphrase-wrapped identity Rift writes, and the only one it
/// accepts. age would otherwise pick it by timing the device at that moment
/// and accept at most that measurement + 4; a busy moment at unlock then
/// refused the right passphrase before running scrypt (v2, Phase 4).
pub const PASSPHRASE_WORK_FACTOR: u8 = 17;

/// Random object identifier; storage names never reveal content hashes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObjectId([u8; 16]);

impl ObjectId {
    pub fn random() -> Result<Self, VaultError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| VaultError::Randomness)?;
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

/// The unlocked vault identity. Never logged; dropped on lock.
pub struct VaultKey {
    identity: age::x25519::Identity,
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

impl VaultKey {
    pub fn generate() -> Self {
        Self {
            identity: age::x25519::Identity::generate(),
        }
    }

    pub fn recipient(&self) -> age::x25519::Recipient {
        self.identity.to_public()
    }

    /// age's text form of the secret, for wrapping by a platform `KeyProvider`
    /// (e.g. Android Keystore). The caller must not persist it unwrapped.
    pub fn export_secret(&self) -> SecretString {
        self.identity.to_string()
    }

    pub fn import_secret(secret: &SecretString) -> Result<Self, VaultError> {
        let identity = secret
            .expose_secret()
            .parse()
            .map_err(|_| VaultError::InvalidKey)?;
        Ok(Self { identity })
    }

    /// Wraps the identity with an age passphrase (scrypt) — the Linux provider.
    pub fn wrap_with_passphrase(&self, passphrase: SecretString) -> Result<Vec<u8>, VaultError> {
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        recipient.set_work_factor(PASSPHRASE_WORK_FACTOR);
        let encryptor =
            age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
                .map_err(|e| VaultError::Encrypt(e.to_string()))?;
        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| VaultError::Encrypt(e.to_string()))?;
        writer.write_all(self.export_secret().expose_secret().as_bytes())?;
        writer.finish()?;
        Ok(out)
    }

    pub fn unwrap_with_passphrase(
        wrapped: &[u8],
        passphrase: SecretString,
    ) -> Result<Self, VaultError> {
        let mut identity = age::scrypt::Identity::new(passphrase);
        identity.set_max_work_factor(PASSPHRASE_WORK_FACTOR);
        let mut secret = String::new();
        decryptor(wrapped, &identity)?
            .read_to_string(&mut secret)
            .map_err(|e| VaultError::Decrypt(e.to_string()))?;
        Self::import_secret(&SecretString::from(secret))
    }

    fn index_mac(&self) -> Result<Hmac<Sha256>, VaultError> {
        let secret = self.export_secret();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.expose_secret().as_bytes())
            .map_err(|_| VaultError::InvalidKey)?;
        mac.update(MAC_CONTEXT);
        Ok(mac)
    }
}

/// What the index records about one object's plaintext.
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
) -> Result<Sealed, VaultError> {
    let mut writer = SealingWriter::new(recipient, out, limit)?;
    io::copy(&mut plaintext, &mut writer).map_err(|e| {
        if e.kind() == io::ErrorKind::FileTooLarge {
            VaultError::TooLarge(limit)
        } else {
            VaultError::Io(e)
        }
    })?;
    writer.finish()
}

/// Decrypts `ciphertext` into `out` and verifies it against `expected`.
/// On any error, everything written to `out` must be discarded: the bytes are
/// only trustworthy once this function returns `Ok`.
pub fn open(
    key: &VaultKey,
    ciphertext: impl Read,
    expected: &Sealed,
    mut out: impl Write,
) -> Result<(), VaultError> {
    let mut reader = decryptor(ciphertext, &key.identity)?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|e| VaultError::Decrypt(e.to_string()))?;
        let Some(chunk) = buffer.get(..n).filter(|c| !c.is_empty()) else {
            break;
        };
        size = size.saturating_add(u64::try_from(n).map_err(|_| VaultError::ContentMismatch)?);
        if size > expected.size {
            return Err(VaultError::ContentMismatch);
        }
        hasher.update(chunk);
        out.write_all(chunk)?;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if size != expected.size || digest != expected.sha256 {
        return Err(VaultError::ContentMismatch);
    }
    Ok(())
}

fn decryptor<'a, R: Read + 'a>(
    ciphertext: R,
    identity: &'a dyn age::Identity,
) -> Result<impl Read + 'a, VaultError> {
    let decryptor =
        age::Decryptor::new(ciphertext).map_err(|e| VaultError::Decrypt(e.to_string()))?;
    decryptor
        .decrypt(iter::once(identity))
        .map_err(|e| match e {
            age::DecryptError::ExcessiveWork { required, .. } => VaultError::ExcessiveWork {
                required,
                allowed: PASSPHRASE_WORK_FACTOR,
            },
            e => VaultError::Decrypt(e.to_string()),
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: ObjectId,
    pub sealed: Sealed,
    pub display_name: String,
    pub media_type: String,
    pub source_url: Option<String>,
    pub created_unix: u64,
    /// The verdict when the file was kept, if it had been scanned (format 2).
    pub scan: Option<KeptScan>,
}

/// The scan verdict a file had when it was kept. It is history: it was
/// bound to the database and engine named here, and is never shown as
/// current (§12.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptScan {
    pub status: KeptStatus,
    pub snapshot: Option<String>,
    pub engine: String,
    /// The database was a demo with no real coverage.
    pub demo: bool,
    /// `check:id` of each finding.
    pub findings: Vec<String>,
    pub scanned_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeptStatus {
    KnownMalicious,
    Suspicious,
    NotFlagged,
    NotFullyScanned,
}

/// An entry of format 1, which had no scan field.
#[derive(Deserialize)]
struct IndexEntryV1 {
    id: ObjectId,
    sealed: Sealed,
    display_name: String,
    media_type: String,
    source_url: Option<String>,
    created_unix: u64,
}

#[derive(Deserialize)]
struct VaultIndexV1 {
    generation: u64,
    entries: Vec<IndexEntryV1>,
}

impl From<VaultIndexV1> for VaultIndex {
    fn from(v1: VaultIndexV1) -> Self {
        Self {
            generation: v1.generation,
            entries: v1
                .entries
                .into_iter()
                .map(|e| IndexEntry {
                    id: e.id,
                    sealed: e.sealed,
                    display_name: e.display_name,
                    media_type: e.media_type,
                    source_url: e.source_url,
                    created_unix: e.created_unix,
                    scan: None,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultIndex {
    /// Incremented on every write; a reader can detect an older index.
    pub generation: u64,
    pub entries: Vec<IndexEntry>,
}

#[derive(Serialize, Deserialize)]
struct IndexFile {
    format_version: u32,
    index: VaultIndex,
}

/// Writes the index atomically: temp file + fsync, current → previous, temp →
/// current, then fsync the directory. A crash leaves either the old or the new
/// index readable, never a partial one.
pub fn write_index(dir: &Path, key: &VaultKey, index: &VaultIndex) -> Result<(), VaultError> {
    let mut payload = postcard::to_allocvec(&IndexFile {
        format_version: INDEX_FORMAT_VERSION,
        index: index.clone(),
    })
    .map_err(|e| VaultError::IndexMalformed(e.to_string()))?;
    let mut mac = key.index_mac()?;
    mac.update(&payload);
    payload.extend_from_slice(&mac.finalize().into_bytes());

    let temp = dir.join(INDEX_TEMP);
    {
        let mut file = File::create(&temp)?;
        seal(
            &key.recipient(),
            payload.as_slice(),
            &mut file,
            MAX_INDEX_FILE_BYTES,
        )?;
        file.sync_all()?;
    }
    let current = dir.join(INDEX_FILE);
    if current.exists() {
        fs::rename(&current, dir.join(INDEX_PREVIOUS))?;
    }
    fs::rename(&temp, &current)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Removes an index write that was interrupted before its rename (a crash or
/// a kill during [`write_index`]). It was never read: the current index, or
/// the previous one when the current is absent, is what counts.
pub fn discard_interrupted_index(dir: &Path) -> Result<(), VaultError> {
    match fs::remove_file(dir.join(INDEX_TEMP)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other.map_err(VaultError::from),
    }
}

/// Reads and authenticates the index. Falls back to the previous index only
/// when the current one is *absent* (a crash between renames) — never when it
/// is present but invalid, which would let an attacker force a rollback.
pub fn read_index(dir: &Path, key: &VaultKey) -> Result<VaultIndex, VaultError> {
    let current = dir.join(INDEX_FILE);
    let path = if current.exists() {
        current
    } else {
        let previous = dir.join(INDEX_PREVIOUS);
        if !previous.exists() {
            return Err(VaultError::IndexMissing);
        }
        previous
    };
    let file = File::open(&path)?;
    if file.metadata()?.len() > MAX_INDEX_FILE_BYTES {
        return Err(VaultError::TooLarge(MAX_INDEX_FILE_BYTES));
    }
    let mut decrypted = Vec::new();
    decryptor(file.take(MAX_INDEX_FILE_BYTES), &key.identity)?
        .read_to_end(&mut decrypted)
        .map_err(|e| VaultError::Decrypt(e.to_string()))?;

    let split = decrypted
        .len()
        .checked_sub(MAC_LEN)
        .ok_or(VaultError::IndexNotAuthentic)?;
    let (payload, tag) = decrypted.split_at(split);
    let mut mac = key.index_mac()?;
    mac.update(payload);
    mac.verify_slice(tag)
        .map_err(|_| VaultError::IndexNotAuthentic)?;

    // The version comes first, as `IndexFile` writes it; the rest is the
    // index of that version.
    let malformed = |e: postcard::Error| VaultError::IndexMalformed(e.to_string());
    let (version, rest): (u32, &[u8]) = postcard::take_from_bytes(payload).map_err(malformed)?;
    let index: VaultIndex = match version {
        1 => postcard::from_bytes::<VaultIndexV1>(rest)
            .map_err(malformed)?
            .into(),
        INDEX_FORMAT_VERSION => postcard::from_bytes(rest).map_err(malformed)?,
        other => {
            return Err(VaultError::IndexMalformed(format!(
                "unsupported version {other}"
            )));
        }
    };
    let mut ids: Vec<ObjectId> = index.entries.iter().map(|e| e.id).collect();
    ids.sort_unstable();
    if ids.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
        return Err(VaultError::IndexMalformed("duplicate object id".into()));
    }
    Ok(index)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // test arithmetic on known-small values
mod tests {
    use super::*;

    const LIMIT: u64 = 10 * 1024 * 1024;

    fn sealed(key: &VaultKey, plaintext: &[u8]) -> (Vec<u8>, Sealed) {
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

    fn opened(key: &VaultKey, ciphertext: &[u8], record: &Sealed) -> Result<Vec<u8>, VaultError> {
        let mut out = Vec::new();
        open(key, ciphertext, record, &mut out).map(|()| out)
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn round_trip_multi_chunk() {
        let key = VaultKey::generate();
        let plaintext = sample(300_000); // > 4 STREAM chunks
        let (ciphertext, record) = sealed(&key, &plaintext);
        assert_eq!(record.size, 300_000);
        assert_eq!(opened(&key, &ciphertext, &record).ok(), Some(plaintext));
    }

    #[test]
    fn truncation_is_detected() {
        let key = VaultKey::generate();
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
        let key = VaultKey::generate();
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
        let key = VaultKey::generate();
        let (ciphertext_a, _) = sealed(&key, b"document A");
        let (_, record_b) = sealed(&key, b"document B");
        assert!(matches!(
            opened(&key, &ciphertext_a, &record_b),
            Err(VaultError::ContentMismatch)
        ));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (ciphertext, record) = sealed(&VaultKey::generate(), b"secret");
        assert!(matches!(
            opened(&VaultKey::generate(), &ciphertext, &record),
            Err(VaultError::Decrypt(_))
        ));
    }

    #[test]
    fn seal_enforces_the_limit_on_the_stream() {
        let key = VaultKey::generate();
        let result = seal(&key.recipient(), sample(5000).as_slice(), Vec::new(), 4096);
        assert!(matches!(result, Err(VaultError::TooLarge(4096))));
    }

    #[test]
    fn passphrase_wrapping_round_trip_and_wrong_passphrase() {
        let key = VaultKey::generate();
        let wrapped = key.wrap_with_passphrase(SecretString::from("correct horse".to_owned()));
        let wrapped = wrapped.unwrap_or_default();
        let back = VaultKey::unwrap_with_passphrase(
            &wrapped,
            SecretString::from("correct horse".to_owned()),
        );
        assert_eq!(
            back.map(|k| k.recipient().to_string()).ok(),
            Some(key.recipient().to_string())
        );
        assert!(
            VaultKey::unwrap_with_passphrase(&wrapped, SecretString::from("wrong".to_owned()))
                .is_err()
        );
    }

    #[test]
    fn passphrase_work_is_fixed_and_more_is_not_a_wrong_passphrase() {
        let key = VaultKey::generate();
        let wrapped = key
            .wrap_with_passphrase(SecretString::from("correct horse".to_owned()))
            .unwrap();
        // The header names the work factor in the clear: `-> scrypt <salt> 17`.
        let header = String::from_utf8_lossy(&wrapped[..wrapped.len().min(200)]).into_owned();
        let stanza = header
            .lines()
            .find(|l| l.starts_with("-> scrypt "))
            .unwrap();
        assert_eq!(
            stanza.rsplit(' ').next(),
            Some(PASSPHRASE_WORK_FACTOR.to_string().as_str())
        );

        // More work than Rift writes: refused before scrypt runs, and said so.
        let mut heavier =
            age::scrypt::Recipient::new(SecretString::from("correct horse".to_owned()));
        heavier.set_work_factor(PASSPHRASE_WORK_FACTOR + 1);
        let mut out = Vec::new();
        let mut writer =
            age::Encryptor::with_recipients(iter::once(&heavier as &dyn age::Recipient))
                .unwrap()
                .wrap_output(&mut out)
                .unwrap();
        writer
            .write_all(key.export_secret().expose_secret().as_bytes())
            .unwrap();
        writer.finish().unwrap();
        assert!(matches!(
            VaultKey::unwrap_with_passphrase(&out, SecretString::from("correct horse".to_owned())),
            Err(VaultError::ExcessiveWork { required, allowed })
                if required == PASSPHRASE_WORK_FACTOR + 1 && allowed == PASSPHRASE_WORK_FACTOR
        ));
        // A wrong passphrase is still a decryption failure.
        assert!(matches!(
            VaultKey::unwrap_with_passphrase(&wrapped, SecretString::from("wrong".to_owned())),
            Err(VaultError::Decrypt(_))
        ));
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let key = VaultKey::generate();
        assert_eq!(format!("{key:?}"), "VaultKey(<redacted>)");
    }

    fn index_with(n: usize) -> VaultIndex {
        VaultIndex {
            generation: 7,
            entries: (0..n)
                .map(|i| IndexEntry {
                    id: ObjectId::random().unwrap_or(ObjectId([i as u8; 16])),
                    sealed: Sealed {
                        sha256: [i as u8; 32],
                        size: i as u64,
                    },
                    display_name: format!("file-{i}.pdf"),
                    media_type: "application/pdf".into(),
                    source_url: Some("https://example.org/a.pdf".into()),
                    created_unix: 1_760_000_000,
                    scan: (i % 2 == 1).then(|| KeptScan {
                        status: KeptStatus::NotFlagged,
                        snapshot: Some("demo-1".into()),
                        engine: "yara-x 1.21.0".into(),
                        demo: true,
                        findings: vec![],
                        scanned_unix: 1_760_000_000,
                    }),
                })
                .collect(),
        }
    }

    #[test]
    fn index_round_trip_and_atomic_replacement() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = VaultKey::generate();
        let first = index_with(3);
        assert!(write_index(dir.path(), &key, &first).is_ok());
        let mut second = index_with(5);
        second.generation = 8;
        assert!(write_index(dir.path(), &key, &second).is_ok());
        assert_eq!(read_index(dir.path(), &key).ok(), Some(second));
        assert!(dir.path().join(INDEX_PREVIOUS).exists());
        assert!(!dir.path().join(INDEX_TEMP).exists());
    }

    /// A format 1 index, as Phase 4's first build wrote it, still opens.
    #[test]
    fn a_format_1_index_is_read_without_scans() {
        #[derive(Serialize)]
        struct EntryV1 {
            id: ObjectId,
            sealed: Sealed,
            display_name: String,
            media_type: String,
            source_url: Option<String>,
            created_unix: u64,
        }
        #[derive(Serialize)]
        struct FileV1 {
            format_version: u32,
            generation: u64,
            entries: Vec<EntryV1>,
        }
        let dir = tempfile::tempdir().expect("temp dir");
        let key = VaultKey::generate();
        let current = index_with(2);
        let old = FileV1 {
            format_version: 1,
            generation: current.generation,
            entries: current
                .entries
                .iter()
                .map(|e| EntryV1 {
                    id: e.id,
                    sealed: e.sealed,
                    display_name: e.display_name.clone(),
                    media_type: e.media_type.clone(),
                    source_url: e.source_url.clone(),
                    created_unix: e.created_unix,
                })
                .collect(),
        };
        let mut payload = postcard::to_allocvec(&old).unwrap_or_default();
        let mut mac = key.index_mac().expect("mac");
        mac.update(&payload);
        payload.extend_from_slice(&mac.finalize().into_bytes());
        let mut file = File::create(dir.path().join(INDEX_FILE)).expect("create index");
        assert!(seal(&key.recipient(), payload.as_slice(), &mut file, LIMIT).is_ok());

        let read = read_index(dir.path(), &key).expect("format 1 reads");
        let mut expected = current;
        for e in &mut expected.entries {
            e.scan = None;
        }
        assert_eq!(read, expected);
        // Written back as format 2, with scans from then on.
        let next = index_with(2);
        assert!(write_index(dir.path(), &key, &next).is_ok());
        assert_eq!(read_index(dir.path(), &key).ok(), Some(next));
    }

    #[test]
    fn forged_index_from_public_recipient_is_rejected() {
        // An attacker who knows only the public recipient can produce a valid
        // age file; the MAC is what stops it from being accepted.
        let dir = tempfile::tempdir().expect("temp dir");
        let key = VaultKey::generate();
        let forged_payload = postcard::to_allocvec(&IndexFile {
            format_version: 1,
            index: index_with(1),
        })
        .unwrap_or_default();
        let mut with_fake_mac = forged_payload;
        with_fake_mac.extend_from_slice(&[0u8; MAC_LEN]);
        let mut file = File::create(dir.path().join(INDEX_FILE)).expect("create index");
        assert!(seal(&key.recipient(), with_fake_mac.as_slice(), &mut file, LIMIT).is_ok());
        assert!(matches!(
            read_index(dir.path(), &key),
            Err(VaultError::IndexNotAuthentic)
        ));
    }

    #[test]
    fn corrupt_current_index_does_not_fall_back_to_previous() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = VaultKey::generate();
        assert!(write_index(dir.path(), &key, &index_with(1)).is_ok());
        assert!(write_index(dir.path(), &key, &index_with(2)).is_ok());
        let current = dir.path().join(INDEX_FILE);
        let mut bytes = fs::read(&current).unwrap_or_default();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert!(fs::write(&current, bytes).is_ok());
        assert!(
            read_index(dir.path(), &key).is_err(),
            "corruption must not silently roll back"
        );
    }

    #[test]
    fn missing_current_index_recovers_previous() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = VaultKey::generate();
        assert!(write_index(dir.path(), &key, &index_with(1)).is_ok());
        assert!(write_index(dir.path(), &key, &index_with(2)).is_ok());
        // Simulate a crash after "current → previous" but before "temp → current".
        assert!(fs::remove_file(dir.path().join(INDEX_FILE)).is_ok());
        assert_eq!(
            read_index(dir.path(), &key).map(|i| i.entries.len()).ok(),
            Some(1)
        );
    }

    #[test]
    fn index_under_wrong_key_is_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(write_index(dir.path(), &VaultKey::generate(), &index_with(1)).is_ok());
        assert!(read_index(dir.path(), &VaultKey::generate()).is_err());
    }
}
