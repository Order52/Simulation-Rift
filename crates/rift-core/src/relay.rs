//! A session's connections sent on through a relay (docs/architecture.md
//! §8.12), so the sites a page reaches see the relay's address, not the
//! phone's: Tor through Orbot's SOCKS port, or a SOCKS5 proxy on a public
//! address the user gives.
//!
//! What it guarantees, for every connection through it:
//!
//! * Names go to the relay as names (SOCKS5 "domain"), so the phone's own
//!   DNS never sees them. Address literals are checked with
//!   [`check_destination`] first, and names that can only be local
//!   (`localhost`, `.local`, one label) are refused before the relay is asked.
//!   (Tor reaches `.onion` names; another relay refuses them itself.)
//! * A relay on loopback is used only if its [`RelayGuard`] says the
//!   listener is the app it should be (Orbot), for this connection: another
//!   app could listen on the same port once Orbot stops. A relay elsewhere
//!   must be at a public address.
//! * Nothing falls back to a direct connection: if the relay is down or
//!   refuses, the connection fails.
//!
//! It adds no trust in what comes back: TLS is still between the engine and
//! the site, and the relay sees what a network operator would.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::transfer::{DestinationError, check_destination};

/// Says whether the app listening on a loopback relay is the one it should
/// be. Asked for each connection, with that connection's two ends.
pub trait RelayGuard: Send + Sync + fmt::Debug {
    fn trusted(&self, local: SocketAddr, relay: SocketAddr) -> bool;
}

#[derive(Debug, Clone)]
pub struct Relay {
    address: SocketAddr,
    guard: Option<Arc<dyn RelayGuard>>,
}

impl PartialEq for Relay {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && match (&self.guard, &other.guard) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            }
    }
}

impl Eq for Relay {}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    #[error("a relay on this device needs a check of the app behind it")]
    Unguarded,
    #[error("the relay is at {0}")]
    NotPublic(DestinationError),
    #[error("the relay could not be reached")]
    Unreachable,
    #[error("the relay you chose is not confirmed running on its port")]
    NotTrusted,
    #[error("the relay could not reach the site ({0})")]
    Refused(&'static str),
    #[error("the relay answered in a way Rift does not understand")]
    Protocol,
    #[error("the name is too long to send to the relay")]
    NameTooLong,
}

impl Relay {
    /// A loopback relay needs `guard`; any other must be at a public address.
    pub fn new(
        address: SocketAddr,
        guard: Option<Arc<dyn RelayGuard>>,
    ) -> Result<Self, RelayError> {
        if address.ip().is_loopback() {
            if guard.is_none() {
                return Err(RelayError::Unguarded);
            }
        } else {
            check_destination(address.ip()).map_err(RelayError::NotPublic)?;
        }
        Ok(Self { address, guard })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// A connection to `host:port` through the relay. `host` is a name or an
    /// address literal (IPv6 without brackets), already checked by the caller
    /// against the threat database. `timeout` bounds the connection and the
    /// handshake; the stream comes back with no timeouts set.
    pub fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, RelayError> {
        let target = Target::of(host)?;
        let stream = TcpStream::connect_timeout(&self.address, timeout)
            .map_err(|_| RelayError::Unreachable)?;
        if let Some(guard) = &self.guard {
            let local = stream.local_addr().map_err(|_| RelayError::Unreachable)?;
            if !guard.trusted(local, self.address) {
                let _ = stream.shutdown(Shutdown::Both);
                return Err(RelayError::NotTrusted);
            }
        }
        let configured = stream.set_read_timeout(Some(timeout)).is_ok()
            && stream.set_write_timeout(Some(timeout)).is_ok();
        if !configured {
            return Err(RelayError::Unreachable);
        }
        let mut stream = stream;
        handshake(&mut stream, &target, port)?;
        let cleared =
            stream.set_read_timeout(None).is_ok() && stream.set_write_timeout(None).is_ok();
        if !cleared {
            return Err(RelayError::Unreachable);
        }
        Ok(stream)
    }
}

/// What the relay is asked to reach.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Ip(IpAddr),
    Name(String),
}

impl Target {
    fn of(host: &str) -> Result<Self, RelayError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            check_destination(ip).map_err(RelayError::NotPublic)?;
            return Ok(Self::Ip(ip));
        }
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        if only_local(&name) {
            return Err(RelayError::Refused("a local name"));
        }
        if name.len() > usize::from(u8::MAX) {
            return Err(RelayError::NameTooLong);
        }
        Ok(Self::Name(name))
    }
}

/// Names that cannot be a public site: through a relay they would mean the
/// relay's own network.
fn only_local(name: &str) -> bool {
    !name.contains('.')
        || ["localhost", "local", "internal", "home.arpa", "lan"]
            .iter()
            .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
}

/// SOCKS5 (RFC 1928) with no authentication: the greeting, CONNECT, and the
/// reply, read whole so no byte of it reaches the engine.
fn handshake(stream: &mut TcpStream, target: &Target, port: u16) -> Result<(), RelayError> {
    let io = |_: io::Error| RelayError::Protocol;
    stream
        .write_all(&[5, 1, 0])
        .map_err(|_| RelayError::Unreachable)?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).map_err(io)?;
    if choice != [5, 0] {
        return Err(RelayError::Protocol);
    }
    let mut request = vec![5, 1, 0];
    match target {
        Target::Ip(IpAddr::V4(v4)) => {
            request.push(1);
            request.extend_from_slice(&v4.octets());
        }
        Target::Ip(IpAddr::V6(v6)) => {
            request.push(4);
            request.extend_from_slice(&v6.octets());
        }
        Target::Name(name) => {
            request.push(3);
            request.push(u8::try_from(name.len()).map_err(|_| RelayError::NameTooLong)?);
            request.extend_from_slice(name.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).map_err(io)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(io)?;
    let [version, reply, _, kind] = head;
    if version != 5 {
        return Err(RelayError::Protocol);
    }
    if reply != 0 {
        return Err(RelayError::Refused(match reply {
            2 => "not allowed by the relay",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "timed out",
            _ => "the relay refused",
        }));
    }
    // The bound address, which says nothing Rift uses.
    let rest = match kind {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(io)?;
            usize::from(len[0]) + 2
        }
        _ => return Err(RelayError::Protocol),
    };
    let mut bound = vec![0u8; rest];
    stream.read_exact(&mut bound).map_err(io)
}

/// For tests elsewhere in the crate: a SOCKS5 relay that records the
/// names it is asked for and connects every request to `127.0.0.1:port`.
#[cfg(test)]
pub(crate) fn test_relay(port: u16) -> (Relay, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    #[derive(Debug)]
    struct Anyone;
    impl RelayGuard for Anyone {
        fn trusted(&self, _: SocketAddr, _: SocketAddr) -> bool {
            true
        }
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let names = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&names);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut client = stream.unwrap();
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                let mut head = [0u8; 3];
                client.read_exact(&mut head).unwrap();
                client.write_all(&[5, 0]).unwrap();
                let mut request = [0u8; 5];
                client.read_exact(&mut request).unwrap();
                assert_eq!(request[3], 3, "a name, not an address");
                let mut name = vec![0u8; usize::from(request[4]) + 2];
                client.read_exact(&mut name).unwrap();
                name.truncate(name.len().saturating_sub(2));
                seen.lock().unwrap().push(String::from_utf8(name).unwrap());
                let upstream = TcpStream::connect(("127.0.0.1", port)).unwrap();
                client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                let (mut a, mut b) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = io::copy(&mut a, &mut b);
                    let _ = b.shutdown(Shutdown::Write);
                });
                let (mut c, mut d) = (upstream, client);
                let _ = io::copy(&mut c, &mut d);
                let _ = d.shutdown(Shutdown::Write);
            });
        }
    });
    (Relay::new(address, Some(Arc::new(Anyone))).unwrap(), names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;

    #[derive(Debug)]
    struct Fixed(bool, Mutex<Vec<(SocketAddr, SocketAddr)>>);

    impl RelayGuard for Fixed {
        fn trusted(&self, local: SocketAddr, relay: SocketAddr) -> bool {
            self.1.lock().unwrap().push((local, relay));
            self.0
        }
    }

    /// A SOCKS5 relay that records each request and answers `reply`, then
    /// echoes what it gets.
    fn relay(reply: u8) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut s = stream.unwrap();
                let mut greeting = [0u8; 3];
                if s.read_exact(&mut greeting).is_err() {
                    continue;
                }
                s.write_all(&[5, 0]).unwrap();
                let mut request = vec![0u8; 4];
                s.read_exact(&mut request).unwrap();
                let extra = match request[3] {
                    1 => 6,
                    4 => 18,
                    _ => {
                        let mut len = [0u8; 1];
                        s.read_exact(&mut len).unwrap();
                        request.push(len[0]);
                        usize::from(len[0]) + 2
                    }
                };
                let mut tail = vec![0u8; extra];
                s.read_exact(&mut tail).unwrap();
                request.extend(tail);
                record.lock().unwrap().push(request);
                s.write_all(&[5, reply, 0, 3, 4, b'h', b'o', b's', b't', 0, 80])
                    .unwrap();
                let mut buf = [0u8; 64];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        });
        (address, seen)
    }

    fn guard(trusted: bool) -> Arc<Fixed> {
        Arc::new(Fixed(trusted, Mutex::new(Vec::new())))
    }

    #[test]
    fn names_go_to_the_relay_as_names_and_bytes_pass_both_ways() {
        let (address, seen) = relay(0);
        let checker = guard(true);
        let relay = Relay::new(address, Some(checker.clone() as Arc<dyn RelayGuard>)).unwrap();
        let mut s = relay
            .connect("Example.COM.", 443, Duration::from_secs(5))
            .unwrap();
        s.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
        let request = seen.lock().unwrap()[0].clone();
        let mut expected = vec![5, 1, 0, 3, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(request, expected);
        let asked = checker.1.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].1, address);
        assert_eq!(asked[0].0, s.local_addr().unwrap());
    }

    #[test]
    fn address_literals_are_checked_and_sent_as_addresses() {
        let (address, seen) = relay(0);
        let relay = Relay::new(address, Some(guard(true))).unwrap();
        relay
            .connect("93.184.216.34", 80, Duration::from_secs(5))
            .unwrap();
        relay
            .connect("2606:4700::1", 443, Duration::from_secs(5))
            .unwrap();
        let requests = seen.lock().unwrap();
        assert_eq!(requests[0], vec![5, 1, 0, 1, 93, 184, 216, 34, 0, 80]);
        assert_eq!(requests[1][3], 4);
        for host in [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.8",
            "::1",
            "169.254.169.254",
        ] {
            assert!(
                matches!(
                    relay.connect(host, 80, Duration::from_secs(5)),
                    Err(RelayError::NotPublic(_))
                ),
                "{host}"
            );
        }
        assert_eq!(requests.len(), 2, "refused before the relay was asked");
    }

    #[test]
    fn local_names_never_reach_the_relay() {
        let (address, seen) = relay(0);
        let relay = Relay::new(address, Some(guard(true))).unwrap();
        for host in [
            "localhost",
            "router",
            "printer.local",
            "nas.lan",
            "x.home.arpa",
            "a.localhost",
            "svc.internal",
        ] {
            assert_eq!(
                relay.connect(host, 80, Duration::from_secs(5)).unwrap_err(),
                RelayError::Refused("a local name"),
                "{host}"
            );
        }
        assert!(seen.lock().unwrap().is_empty());
        let long = format!("{}.com", "a".repeat(260));
        assert_eq!(
            relay
                .connect(&long, 80, Duration::from_secs(5))
                .unwrap_err(),
            RelayError::NameTooLong
        );
    }

    #[test]
    fn an_untrusted_listener_gets_nothing() {
        let (address, seen) = relay(0);
        let relay = Relay::new(address, Some(guard(false))).unwrap();
        assert_eq!(
            relay
                .connect("example.com", 443, Duration::from_secs(5))
                .unwrap_err(),
            RelayError::NotTrusted
        );
        thread::sleep(Duration::from_millis(100));
        assert!(seen.lock().unwrap().is_empty(), "no request was sent");
    }

    #[test]
    fn loopback_relays_need_a_guard_and_others_a_public_address() {
        assert_eq!(
            Relay::new("127.0.0.1:9050".parse().unwrap(), None).unwrap_err(),
            RelayError::Unguarded
        );
        assert!(matches!(
            Relay::new("192.168.0.2:1080".parse().unwrap(), None),
            Err(RelayError::NotPublic(_))
        ));
        assert!(Relay::new("203.0.114.9:1080".parse().unwrap(), None).is_ok());
    }

    #[test]
    fn a_refusal_or_a_dead_relay_fails_without_falling_back() {
        let (address, _) = relay(5);
        let relay = Relay::new(address, Some(guard(true))).unwrap();
        assert_eq!(
            relay
                .connect("example.com", 443, Duration::from_secs(5))
                .unwrap_err(),
            RelayError::Refused("connection refused")
        );
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let dead = Relay::new(closed, Some(guard(true))).unwrap();
        assert_eq!(
            dead.connect("example.com", 443, Duration::from_secs(2))
                .unwrap_err(),
            RelayError::Unreachable
        );
    }

    #[test]
    fn a_relay_that_asks_for_a_password_is_not_understood() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).unwrap();
            s.write_all(&[5, 0xff]).unwrap();
        });
        let relay = Relay::new(address, Some(guard(true))).unwrap();
        assert_eq!(
            relay
                .connect("example.com", 443, Duration::from_secs(5))
                .unwrap_err(),
            RelayError::Protocol
        );
    }
}
