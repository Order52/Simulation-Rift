//! Controller-owned transfers: downloads into quarantine and update fetches
//! (docs/architecture.md §11.1, INV-13).

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha256};

use crate::vault::{Sealed, VaultError};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DestinationError {
    #[error("{0} is a loopback, private, link-local or otherwise non-public address")]
    NonPublic(IpAddr),
}

/// Refuses addresses a website should not be able to make Rift's own
/// transfers reach (DNS rebinding, router admin pages, cloud metadata).
/// Called for every resolved address of every hop, including redirects.
pub fn check_destination(addr: IpAddr) -> Result<(), DestinationError> {
    let public = match addr {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => is_public_v4(mapped),
            None => is_public_v6(v6),
        },
    };
    if public {
        Ok(())
    } else {
        Err(DestinationError::NonPublic(addr))
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0 // "this network"
        || (a == 100 && (64..=127).contains(&b)) // shared address space (CGNAT)
        || (a == 192 && b == 0 && ip.octets()[2] == 0) // IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || a >= 240) // reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (first & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (first & 0xffc0) == 0xfec0 // deprecated site-local
        || (first == 0x2001 && ip.segments()[1] == 0x0db8) // documentation
        || (first == 0x0064 && ip.segments()[1] == 0xff9b)) // NAT64 can reach IPv4 private space
}

/// Characters that reorder or hide text and must never reach a filename display.
const BIDI_AND_INVISIBLE: &[char] = &[
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}',
    '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{feff}',
];
const MAX_DISPLAY_NAME_CHARS: usize = 120;

/// Turns a server- or user-supplied filename into display metadata. Storage
/// never uses it (objects are stored under random ids), but it must not be
/// able to impersonate another name or extension in the trusted UI.
pub fn display_name(supplied: &str) -> String {
    let last = supplied.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && !BIDI_AND_INVISIBLE.contains(c))
        .collect::<String>()
        .trim_matches(|c: char| c.is_whitespace() || c == '.')
        .chars()
        .take(MAX_DISPLAY_NAME_CHARS)
        .collect();
    if cleaned.is_empty() {
        "download".to_owned()
    } else {
        cleaned
    }
}

/// Streaming writer used for every object entering storage: it enforces the
/// byte limit on the stream itself (never trusting Content-Length), hashes
/// the plaintext, and encrypts it with age as the bytes arrive.
pub struct SealingWriter<W: Write> {
    inner: age::stream::StreamWriter<W>,
    hasher: Sha256,
    size: u64,
    limit: u64,
}

impl<W: Write> std::fmt::Debug for SealingWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealingWriter")
            .field("size", &self.size)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl<W: Write> SealingWriter<W> {
    pub fn new(recipient: &age::x25519::Recipient, out: W, limit: u64) -> Result<Self, VaultError> {
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
                .map_err(|e| VaultError::Encrypt(e.to_string()))?;
        let inner = encryptor
            .wrap_output(out)
            .map_err(|e| VaultError::Encrypt(e.to_string()))?;
        Ok(Self {
            inner,
            hasher: Sha256::new(),
            size: 0,
            limit,
        })
    }

    pub fn bytes_written(&self) -> u64 {
        self.size
    }

    /// Completes the age stream. Only after this succeeds may the object be
    /// committed; on any error the caller deletes the partial output.
    pub fn finish(self) -> Result<Sealed, VaultError> {
        self.finish_into_inner().map(|(sealed, _)| sealed)
    }

    /// Like [`finish`](Self::finish), also returning the underlying writer
    /// (e.g. so the caller can fsync the file before publishing it).
    pub fn finish_into_inner(self) -> Result<(Sealed, W), VaultError> {
        let inner = self.inner.finish()?;
        let sealed = Sealed {
            sha256: self.hasher.finalize().into(),
            size: self.size,
        };
        Ok((sealed, inner))
    }
}

impl<W: Write> Write for SealingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buf.len()).map_err(|_| io::Error::other("chunk too large"))?;
        let total = self
            .size
            .checked_add(len)
            .ok_or_else(|| io::Error::other("size overflow"))?;
        if total > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                VaultError::TooLarge(self.limit),
            ));
        }
        self.inner.write_all(buf)?;
        self.hasher.update(buf);
        self.size = total;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{VaultKey, open};

    #[test]
    fn non_public_destinations_are_refused() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.10",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
            "64:ff9b::a00:1",
            "2001:db8::1",
        ] {
            let addr: IpAddr = blocked.parse().unwrap();
            assert!(
                check_destination(addr).is_err(),
                "{blocked} should be refused"
            );
        }
        for allowed in [
            "93.184.215.14",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            let addr: IpAddr = allowed.parse().unwrap();
            assert!(
                check_destination(addr).is_ok(),
                "{allowed} should be allowed"
            );
        }
    }

    #[test]
    fn display_names_cannot_traverse_or_impersonate() {
        assert_eq!(display_name("../../etc/passwd"), "passwd");
        assert_eq!(display_name("C:\\Users\\x\\evil.exe"), "evil.exe");
        // Right-to-left override would display "invoice_fdp.exe" as "invoice_exe.pdf".
        assert_eq!(display_name("invoice_\u{202e}fdp.exe"), "invoice_fdp.exe");
        assert_eq!(display_name("bell\u{7}\nname.txt"), "bellname.txt");
        assert_eq!(display_name("   ...  "), "download");
        assert_eq!(display_name(""), "download");
        assert_eq!(
            display_name(&"a".repeat(500)).chars().count(),
            MAX_DISPLAY_NAME_CHARS
        );
        assert_eq!(display_name("résumé.pdf"), "résumé.pdf");
    }

    #[test]
    fn sealing_writer_enforces_limit_on_the_stream() {
        let key = VaultKey::generate();
        let mut writer = SealingWriter::new(&key.recipient(), Vec::new(), 1000).unwrap();
        writer.write_all(&[1u8; 600]).unwrap();
        let error = writer.write_all(&[1u8; 600]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(writer.bytes_written(), 600);
    }

    #[test]
    fn sealing_writer_output_opens_and_verifies() {
        let key = VaultKey::generate();
        let mut ciphertext = Vec::new();
        let mut writer = SealingWriter::new(&key.recipient(), &mut ciphertext, 1 << 20).unwrap();
        for chunk in [&b"streamed "[..], b"in ", b"pieces"] {
            writer.write_all(chunk).unwrap();
        }
        let sealed = writer.finish().unwrap();
        let mut plaintext = Vec::new();
        open(&key, ciphertext.as_slice(), &sealed, &mut plaintext).unwrap();
        assert_eq!(plaintext, b"streamed in pieces");
    }
}
