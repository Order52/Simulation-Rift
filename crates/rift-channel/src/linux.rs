use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rift_protocol::session::{
    FromBrowser, MAX_MESSAGE_BYTES, ToBrowser, decode_from_browser, decode_to_browser,
    encode_message,
};
use rustix::fs::{Mode, OFlags};
use rustix::io::fcntl_dupfd_cloexec;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType, recvmsg,
    sendmsg, socketpair,
};

/// One end of a session channel.
#[derive(Debug)]
pub struct Channel {
    fd: OwnedFd,
}

/// One datagram as received.
#[derive(Debug)]
pub struct Received {
    pub bytes: Vec<u8>,
    pub attached: Option<OwnedFd>,
}

impl Channel {
    /// A connected pair: this process's end (close-on-exec), and the end for
    /// the child, to be passed as its stdin (`Stdio::from`).
    pub fn pair() -> io::Result<(Self, OwnedFd)> {
        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        Ok((Self { fd: ours }, theirs))
    }

    /// The browser host's end, taken from stdin: duplicated close-on-exec,
    /// after which stdin is pointed at `/dev/null`, so that no process the
    /// engine starts inherits the channel. Fails unless stdin is a
    /// `SOCK_SEQPACKET` socket.
    pub fn from_stdin() -> io::Result<Self> {
        let stdin = rustix::stdio::stdin();
        if rustix::net::sockopt::socket_type(stdin)? != SocketType::SEQPACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stdin is not the session channel",
            ));
        }
        let fd = fcntl_dupfd_cloexec(stdin, 3)?;
        let null = rustix::fs::open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())?;
        rustix::stdio::dup2_stdin(&null)?;
        Ok(Self { fd })
    }

    /// Another handle to the same end, for a second thread.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
        })
    }

    /// Sends one datagram, with `attached` passed along if given.
    pub fn send(&self, message: &[u8], attached: Option<BorrowedFd<'_>>) -> io::Result<()> {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let fds;
        if let Some(fd) = attached {
            fds = [fd];
            if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
                return Err(io::Error::other("no room for the descriptor"));
            }
        }
        let sent = sendmsg(
            &self.fd,
            &[IoSlice::new(message)],
            &mut control,
            SendFlags::NOSIGNAL,
        )?;
        if sent != message.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "the datagram was cut short",
            ));
        }
        Ok(())
    }

    /// Receives one datagram; `None` when the other end is closed. A
    /// datagram longer than [`MAX_MESSAGE_BYTES`], or with more than one
    /// descriptor, is an error (the kernel closes any descriptor that did
    /// not fit).
    pub fn recv(&self) -> io::Result<Option<Received>> {
        let mut bytes = vec![0u8; MAX_MESSAGE_BYTES.saturating_add(1)];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = recvmsg(
            &self.fd,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        let mut fds: Vec<OwnedFd> = Vec::new();
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = message {
                fds.extend(rights);
            }
        }
        if received
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            || received.bytes > MAX_MESSAGE_BYTES
        {
            return Err(invalid("the datagram or its descriptors were cut short"));
        }
        if fds.len() > 1 {
            return Err(invalid("more than one descriptor was attached"));
        }
        if received.bytes == 0 && fds.is_empty() {
            return Ok(None);
        }
        bytes.truncate(received.bytes);
        Ok(Some(Received {
            bytes,
            attached: fds.pop(),
        }))
    }

    /// Sends a message from the browser host. Only `Connection` carries a
    /// descriptor, and it must.
    pub fn send_from_browser(
        &self,
        message: &FromBrowser,
        attached: Option<BorrowedFd<'_>>,
    ) -> io::Result<()> {
        if matches!(message, FromBrowser::Connection) != attached.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only a Connection carries a descriptor",
            ));
        }
        self.send(&encode_message(message).map_err(unencodable)?, attached)
    }

    /// Receives and validates a message from the browser host; `None` when
    /// it closed the channel. A `Connection` comes with its descriptor.
    pub fn recv_from_browser(&self) -> io::Result<Option<(FromBrowser, Option<OwnedFd>)>> {
        let Some(received) = self.recv()? else {
            return Ok(None);
        };
        let message = decode_from_browser(&received.bytes).map_err(invalid)?;
        if matches!(message, FromBrowser::Connection) != received.attached.is_some() {
            return Err(invalid("a descriptor arrived with the wrong message"));
        }
        Ok(Some((message, received.attached)))
    }

    pub fn send_to_browser(&self, message: &ToBrowser) -> io::Result<()> {
        self.send(&encode_message(message).map_err(unencodable)?, None)
    }

    /// Receives a message from the controller; `None` when it closed the
    /// channel. Messages from the controller never carry descriptors.
    pub fn recv_to_browser(&self) -> io::Result<Option<ToBrowser>> {
        let Some(received) = self.recv()? else {
            return Ok(None);
        };
        if received.attached.is_some() {
            return Err(invalid("the controller attached a descriptor"));
        }
        decode_to_browser(&received.bytes)
            .map(Some)
            .map_err(invalid)
    }
}

impl AsFd for Channel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn unencodable(error: rift_protocol::ProtocolError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use rift_protocol::session::Decision;

    use super::*;

    #[test]
    fn messages_and_a_connection_cross_the_pair() {
        let (controller, theirs) = Channel::pair().unwrap();
        let browser = Channel { fd: theirs };
        browser
            .send_from_browser(
                &FromBrowser::Hello {
                    version: 1,
                    engine: "test".into(),
                },
                None,
            )
            .unwrap();
        let (hello, fd) = controller.recv_from_browser().unwrap().unwrap();
        assert!(matches!(hello, FromBrowser::Hello { version: 1, .. }));
        assert!(fd.is_none());

        // A TCP connection accepted on one side is served on the other.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut engine = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        browser
            .send_from_browser(&FromBrowser::Connection, Some(accepted.as_fd()))
            .unwrap();
        drop(accepted);
        let (message, fd) = controller.recv_from_browser().unwrap().unwrap();
        assert_eq!(message, FromBrowser::Connection);
        let mut served = TcpStream::from(fd.unwrap());
        engine.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        served.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");

        controller
            .send_to_browser(&ToBrowser::Answer {
                id: 3,
                decision: Decision::Proceed,
            })
            .unwrap();
        assert_eq!(
            browser.recv_to_browser().unwrap(),
            Some(ToBrowser::Answer {
                id: 3,
                decision: Decision::Proceed
            })
        );
        drop(browser);
        assert!(controller.recv_from_browser().unwrap().is_none());
    }

    #[test]
    fn descriptors_go_only_with_connections() {
        let (controller, theirs) = Channel::pair().unwrap();
        let browser = Channel { fd: theirs };
        let (spare, _) = Channel::pair().unwrap();
        assert!(
            browser
                .send_from_browser(&FromBrowser::Closing, Some(spare.as_fd()))
                .is_err()
        );
        assert!(
            browser
                .send_from_browser(&FromBrowser::Connection, None)
                .is_err()
        );
        // A hostile host could still send raw datagrams.
        let closing = encode_message(&FromBrowser::Closing).unwrap();
        browser.send(&closing, Some(spare.as_fd())).unwrap();
        let error = controller.recv_from_browser().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let connection = encode_message(&FromBrowser::Connection).unwrap();
        browser.send(&connection, None).unwrap();
        assert!(controller.recv_from_browser().is_err());
        controller
            .send(
                &encode_message(&ToBrowser::Close).unwrap(),
                Some(spare.as_fd()),
            )
            .unwrap();
        assert!(browser.recv_to_browser().is_err());
    }

    #[test]
    fn oversized_and_malformed_datagrams_are_refused() {
        let (controller, theirs) = Channel::pair().unwrap();
        let browser = Channel { fd: theirs };
        browser
            .send(&vec![0u8; MAX_MESSAGE_BYTES + 1], None)
            .unwrap();
        assert_eq!(
            controller.recv().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        browser.send(&[0xff, 0xff, 0xff], None).unwrap();
        assert!(controller.recv_from_browser().is_err());
        // The channel still works after a refused datagram.
        browser
            .send_from_browser(&FromBrowser::Closing, None)
            .unwrap();
        assert_eq!(
            controller.recv_from_browser().unwrap().unwrap().0,
            FromBrowser::Closing
        );
    }
}
