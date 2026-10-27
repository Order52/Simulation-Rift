//! The relay setting (docs/architecture.md §8.12): where a session's
//! connections and downloads, and Where it goes, are sent on to.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use rift_core::relay::{Relay, RelayError, RelayGuard};

/// Says whether the app listening on a loopback relay is the one the user
/// chose (Android: the socket's owner is Orbot, with Orbot's certificate).
/// Asked for every connection; it must not call back into Rift.
#[uniffi::export(with_foreign)]
pub trait RelayCheck: Send + Sync {
    /// `local_port` is Rift's end of the connection, `relay_port` the relay's.
    fn trusted(&self, local_port: u16, relay_port: u16) -> bool;
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RelayFailure {
    #[error("not an address and port: {detail}")]
    Address { detail: String },
    #[error("{detail}")]
    Refused { detail: String },
}

struct Checked(Arc<dyn RelayCheck>);

impl fmt::Debug for Checked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayCheck")
    }
}

impl RelayGuard for Checked {
    fn trusted(&self, local: SocketAddr, relay: SocketAddr) -> bool {
        self.0.trusted(local.port(), relay.port())
    }
}

/// A relay, checked: on loopback only with `check`, elsewhere only at a
/// public address. Given to [`crate::Sessions::set_relay`] and
/// [`crate::Navigator::trace`].
#[derive(Debug, uniffi::Object)]
pub struct RelaySetting {
    pub(crate) relay: Relay,
}

#[uniffi::export]
impl RelaySetting {
    /// `address` is `ip:port` (`[ip]:port` for IPv6); names are not taken,
    /// since looking one up would leave the phone's DNS.
    #[uniffi::constructor]
    pub fn new(
        address: String,
        check: Option<Arc<dyn RelayCheck>>,
    ) -> Result<Arc<Self>, RelayFailure> {
        let address: SocketAddr = address.trim().parse().map_err(|_| RelayFailure::Address {
            detail: rift_core::text::escape_for_display(&address),
        })?;
        let guard = check.map(|c| Arc::new(Checked(c)) as Arc<dyn RelayGuard>);
        let relay = Relay::new(address, guard).map_err(|e: RelayError| RelayFailure::Refused {
            detail: e.to_string(),
        })?;
        Ok(Arc::new(Self { relay }))
    }

    /// `ip:port`, for display.
    pub fn address(&self) -> String {
        self.relay.address().to_string()
    }
}
