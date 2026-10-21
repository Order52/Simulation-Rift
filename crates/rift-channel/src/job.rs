//! A worker job's input and output (docs/architecture.md §8.6): bytes in a
//! memfd sealed so that neither side can change them after the hand-off.

use std::fs::File;
use std::io::{self, Seek, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;

use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, memfd_create};

/// The seals both sides require: no write, grow or shrink, and no change to
/// the seals themselves.
const SEALS: SealFlags = SealFlags::SHRINK
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE)
    .union(SealFlags::SEAL);

/// `bytes` in a sealed memfd, positioned at its start (the worker reads
/// it with plain reads, which share this position).
pub fn sealed(name: &str, bytes: &[u8]) -> io::Result<OwnedFd> {
    let fd = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.rewind()?;
    let fd = OwnedFd::from(file);
    fcntl_add_seals(&fd, SEALS)?;
    Ok(fd)
}

/// Reads a memfd the other side sent, refusing one that is not fully sealed
/// (it could still change under the reader) or holds more than `max` bytes.
pub fn read_sealed(fd: OwnedFd, max: u64) -> io::Result<Vec<u8>> {
    let seals = fcntl_get_seals(&fd)?;
    if !seals.contains(SEALS) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the memfd is not sealed",
        ));
    }
    let file = File::from(fd);
    let size = file.metadata()?.len();
    if size > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the memfd holds {size} bytes, more than {max}"),
        ));
    }
    let mut bytes = vec![0; usize::try_from(size).map_err(io::Error::other)?];
    // From the start, whatever the shared position is.
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Read;

    use super::*;

    #[test]
    fn sealed_bytes_read_back_and_cannot_change() {
        let fd = sealed("test", b"pixels").unwrap();
        let mut file = File::from(fd.try_clone().unwrap());
        assert!(file.write_all(b"x").is_err());
        assert!(file.set_len(1).is_err());
        let mut read = Vec::new();
        file.read_to_end(&mut read).unwrap();
        assert_eq!(read, b"pixels");
        assert_eq!(read_sealed(fd.try_clone().unwrap(), 6).unwrap(), b"pixels");
        assert!(read_sealed(fd, 5).is_err());
    }

    #[test]
    fn an_unsealed_memfd_is_refused() {
        let fd = memfd_create("open", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING).unwrap();
        let mut file = File::from(fd);
        file.write_all(b"changeable").unwrap();
        assert!(read_sealed(OwnedFd::from(file), 100).is_err());
    }
}
