//! Minimal datagram transport: one UTF-8 text message per SEQPACKET datagram,
//! optionally carrying one file descriptor via SCM_RIGHTS.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, UnixAddr, recvmsg, sendmsg};

/// Upper bound for a control message; anything larger is rejected, not truncated.
pub const MAX_MESSAGE: usize = 4096;

pub struct Message {
    pub text: String,
    pub fd: Option<OwnedFd>,
}

pub fn send(sock: BorrowedFd<'_>, text: &str, fd: Option<BorrowedFd<'_>>) -> nix::Result<()> {
    if text.len() > MAX_MESSAGE {
        return Err(Errno::EMSGSIZE);
    }
    let iov = [IoSlice::new(text.as_bytes())];
    let raw: [RawFd; 1];
    let cmsgs: &[ControlMessage<'_>] = match fd {
        Some(fd) => {
            raw = [fd.as_raw_fd()];
            &[ControlMessage::ScmRights(&raw)]
        }
        None => &[],
    };
    sendmsg::<UnixAddr>(sock.as_raw_fd(), &iov, cmsgs, MsgFlags::empty(), None)?;
    Ok(())
}

pub fn recv(sock: BorrowedFd<'_>) -> nix::Result<Message> {
    let mut buf = [0u8; MAX_MESSAGE];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);
    let mut iov = [IoSliceMut::new(&mut buf)];
    let msg = recvmsg::<UnixAddr>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )?;

    let mut received: Option<OwnedFd> = None;
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            for raw in fds {
                // SAFETY: the kernel installed `raw` into our descriptor table
                // for this message; nothing else refers to it, so we own it.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                // Keep the first descriptor; extra ones are closed on drop.
                received.get_or_insert(owned);
            }
        }
    }
    if msg
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
    {
        return Err(Errno::EMSGSIZE);
    }
    let len = msg.bytes;
    if len == 0 {
        return Err(Errno::ECONNRESET);
    }
    let text = std::str::from_utf8(&buf[..len])
        .map_err(|_| Errno::EBADMSG)?
        .to_owned();
    Ok(Message { text, fd: received })
}
