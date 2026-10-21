//! Controller-owned transfers: downloads into quarantine and update fetches
//! (docs/architecture.md §11.1, INV-13).

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha256};

use crate::seal::{SealError, Sealed};
use crate::text::is_hidden_or_control;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DestinationError {
    #[error("{0}, a loopback, private, link-local or otherwise non-public address")]
    NonPublic(IpAddr),
}

/// Refuses addresses a website should not be able to make Rift's own
/// transfers reach (DNS rebinding, router admin pages, cloud metadata).
/// Called for every resolved address of every hop, including redirects.
pub fn check_destination(addr: IpAddr) -> Result<(), DestinationError> {
    let public = match addr {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped().or_else(|| nat64_well_known(v6)) {
            Some(carried) => is_public_v4(carried),
            None => is_public_v6(v6),
        },
    };
    if public {
        Ok(())
    } else {
        Err(DestinationError::NonPublic(addr))
    }
}

/// The IPv4 address in RFC 6052's well-known prefix `64:ff9b::/96`, which a
/// NAT64 gateway translates to. DNS64 networks (common on IPv6-only mobile
/// networks) answer with such an address for every IPv4-only host, so it is
/// judged by the address it carries; refusing the prefix outright refused
/// those hosts (Phase 7). The rest of `64:ff9b::/32`, including RFC 8215's
/// local-use `64:ff9b:1::/48`, stays refused.
fn nat64_well_known(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let [a, b, c, d, e, f, ..] = ip.segments();
    if [a, b, c, d, e, f] != [0x0064, 0xff9b, 0, 0, 0, 0] {
        return None;
    }
    let [.., w, x, y, z] = ip.octets();
    Some(Ipv4Addr::new(w, x, y, z))
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
        || (first == 0x0064 && ip.segments()[1] == 0xff9b)) // NAT64 other than the well-known /96
}

const MAX_DISPLAY_NAME_CHARS: usize = 120;
/// Longest final extension (after the last '.') kept visible when shortening.
const MAX_KEPT_EXTENSION_CHARS: usize = 16;

/// Turns a server- or user-supplied filename into display metadata. Storage
/// never uses it (objects are stored under random ids), but it must not be
/// able to impersonate another name or extension in the trusted UI.
pub fn display_name(supplied: &str) -> String {
    let last = supplied.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = last.chars().filter(|&c| !is_hidden_or_control(c)).collect();
    let trimmed = cleaned.trim_matches(|c: char| c.is_whitespace() || c == '.');
    if trimmed.is_empty() {
        "download".to_owned()
    } else {
        shorten(trimmed)
    }
}

/// Fits a cleaned, trimmed name in [`MAX_DISPLAY_NAME_CHARS`]. The final
/// extension decides how the file would be opened, so it stays visible:
/// `report<padding>.pdf.exe` is shown as `report<padding>….exe`, never as
/// `report<padding>.pdf`.
fn shorten(name: &str) -> String {
    if name.chars().count() <= MAX_DISPLAY_NAME_CHARS {
        return name.to_owned();
    }
    let extension = name
        .rfind('.')
        .and_then(|dot| name.get(dot..))
        .filter(|ext| ext.chars().count() <= MAX_KEPT_EXTENSION_CHARS.saturating_add(1))
        .unwrap_or_default();
    let stem_chars = MAX_DISPLAY_NAME_CHARS
        .saturating_sub(1)
        .saturating_sub(extension.chars().count());
    let stem: String = name.chars().take(stem_chars).collect();
    // The cut may land after a dot or space; trim so the result is stable.
    let stem = stem.trim_end_matches(|c: char| c.is_whitespace() || c == '.');
    format!("{stem}\u{2026}{extension}")
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
    pub fn new(recipient: &age::x25519::Recipient, out: W, limit: u64) -> Result<Self, SealError> {
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
                .map_err(|e| SealError::Encrypt(e.to_string()))?;
        let inner = encryptor
            .wrap_output(out)
            .map_err(|e| SealError::Encrypt(e.to_string()))?;
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
    pub fn finish(self) -> Result<Sealed, SealError> {
        self.finish_into_inner().map(|(sealed, _)| sealed)
    }

    /// Like [`finish`](Self::finish), also returning the underlying writer
    /// (e.g. so the caller can fsync the file before publishing it).
    pub fn finish_into_inner(self) -> Result<(Sealed, W), SealError> {
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
                SealError::TooLarge(self.limit),
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
    use crate::seal::{SealKey, open};

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
            "64:ff9b::a00:1",       // NAT64 of 10.0.0.1
            "64:ff9b::7f00:1",      // of 127.0.0.1
            "64:ff9b::a9fe:a9fe",   // of 169.254.169.254
            "64:ff9b:1::6814:179a", // RFC 8215 local-use prefix
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
            "64:ff9b::6814:179a", // DNS64's answer for 104.20.23.154
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
    fn shortening_keeps_the_real_extension_visible() {
        let disguised = format!("invoice{}.pdf.exe", "_".repeat(200));
        let shown = display_name(&disguised);
        assert_eq!(shown.chars().count(), MAX_DISPLAY_NAME_CHARS);
        assert!(shown.starts_with("invoice_"), "{shown}");
        assert!(shown.ends_with("\u{2026}.exe"), "{shown}");
        // An implausibly long "extension" is not kept; the head is.
        let shown = display_name(&format!("a.{}", "b".repeat(300)));
        assert!(
            shown.starts_with("a.bbb") && shown.ends_with('\u{2026}'),
            "{shown}"
        );
    }

    #[test]
    fn display_name_is_a_fixed_point() {
        // Found by the display_name fuzz target: a cut just before a dot left
        // a trailing "." that a second pass removed.
        let found = format!("2{}#{}||||||I#II.\u{10}.0.", "I".repeat(65), "I".repeat(41));
        for input in [
            found.as_str(),
            "x.pdf",
            &"a. ".repeat(100),
            &"a".repeat(500),
        ] {
            let once = display_name(input);
            assert_eq!(display_name(&once), once, "{input:?}");
        }
    }

    #[test]
    fn sealing_writer_enforces_limit_on_the_stream() {
        let key = SealKey::generate();
        let mut writer = SealingWriter::new(&key.recipient(), Vec::new(), 1000).unwrap();
        writer.write_all(&[1u8; 600]).unwrap();
        let error = writer.write_all(&[1u8; 600]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        assert_eq!(writer.bytes_written(), 600);
    }

    #[test]
    fn sealing_writer_output_opens_and_verifies() {
        let key = SealKey::generate();
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
