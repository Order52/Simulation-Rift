//! The browser's egress proxy for the Android controller (docs/architecture.md
//! §8.8, INV-14). One proxy per session: it starts when the browser first
//! asks for it, follows the session's local-host exceptions, and stops when
//! the session ends, before the browser is wiped.

use rift_core::egress::{Egress, EgressPolicy, Refusal};
use rift_core::text::escape_for_display;

use crate::{SessionFailure, Sessions};

/// Where and how the browser reaches the proxy. The token is a secret: it
/// goes to the browser over the signature-checked Binder interface only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EgressEndpoint {
    pub port: u16,
    pub token: String,
    pub realm: String,
}

/// A refused connection, already escaped for the trusted UI.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EgressDenial {
    pub destination: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EgressStats {
    pub allowed: u64,
    pub denied: u64,
    /// Requests without the token: the browser's first try of each kind, or another app.
    pub unauthenticated: u64,
    /// The most recent refusals, oldest first.
    pub recent: Vec<EgressDenial>,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum EgressFailure {
    #[error("no session is active for this request")]
    NoActiveSession,
    #[error("the egress proxy could not start: {detail}")]
    Start { detail: String },
    #[error("session state is unusable after an internal error")]
    Poisoned,
}

impl From<SessionFailure> for EgressFailure {
    fn from(_: SessionFailure) -> Self {
        Self::Poisoned
    }
}

#[uniffi::export]
impl Sessions {
    /// This session's proxy, started on first use.
    pub fn egress(&self, generation: u64) -> Result<EgressEndpoint, EgressFailure> {
        let mut state = self.lock()?;
        let extras = state
            .current(generation)
            .ok_or(EgressFailure::NoActiveSession)?;
        if extras.egress.is_none() {
            let started = Egress::start(EgressPolicy {
                local_hosts: extras.local_hosts.clone(),
                ..EgressPolicy::default()
            })
            .map_err(|e| EgressFailure::Start {
                detail: e.to_string(),
            })?;
            extras.egress = Some(started);
        }
        let egress = extras.egress.as_ref().ok_or(EgressFailure::Poisoned)?;
        Ok(EgressEndpoint {
            port: egress.port(),
            token: egress.token().to_owned(),
            realm: egress.realm().to_owned(),
        })
    }

    /// What the proxy did in this session; None if it never started.
    pub fn egress_stats(&self, generation: u64) -> Option<EgressStats> {
        let mut state = self.lock().ok()?;
        let egress = state.current(generation)?.egress.as_ref()?;
        let counts = egress.counts();
        Some(EgressStats {
            allowed: counts.allowed,
            denied: counts.denied,
            unauthenticated: counts.unauthenticated,
            recent: egress
                .denials()
                .into_iter()
                .map(|d| EgressDenial {
                    destination: escape_for_display(&if d.host.contains(':') {
                        format!("[{}]:{}", d.host, d.port)
                    } else {
                        format!("{}:{}", d.host, d.port)
                    }),
                    reason: escape_for_display(&describe(&d.refusal)),
                })
                .collect(),
        })
    }
}

fn describe(refusal: &Refusal) -> String {
    match refusal {
        Refusal::Destination(_) => {
            "a local or private address (pages may reach only public ones)".to_owned()
        }
        other => other.to_string(),
    }
}
