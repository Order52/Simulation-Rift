//! The browser's egress proxy (docs/architecture.md §8.8, §9.2, INV-14). One
//! proxy per session: it starts when the browser first asks for it, follows
//! the session's local-host exceptions, and stops when the session ends,
//! before the browser is wiped. Android's listens on loopback behind a
//! token; Linux's has no listener and serves the connections the browser
//! host forwards ([`Sessions::forwarded_egress`]).

use std::sync::Arc;

use rift_core::egress::{
    Denial, Egress, EgressCounts, EgressPolicy, ForwardedEgress, Refusal, Screen,
};
use rift_core::text::escape_for_display;
use rift_core::urlcanon::CanonicalUrl;

use crate::{Intel, SessionFailure, Sessions};

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
    /// Counts this session's refusals from 1, so a reader can tell which are new.
    pub seq: u64,
    /// Stable: `local-address`, `known-malicious`, `not-checked`,
    /// `does-not-resolve`, `unreachable`, `malformed` or `busy`.
    pub code: String,
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
    /// This session's proxy, started on first use. With `intel`, every
    /// destination is checked against the installed threat database (the
    /// one current at each request) before it is resolved.
    pub fn egress(
        &self,
        generation: u64,
        intel: Option<Arc<Intel>>,
    ) -> Result<EgressEndpoint, EgressFailure> {
        let mut state = self.lock()?;
        let extras = state
            .current(generation)
            .ok_or(EgressFailure::NoActiveSession)?;
        if extras.egress.is_none() {
            let started =
                Egress::start(policy(&extras.local_hosts), screen(intel)).map_err(|e| {
                    EgressFailure::Start {
                        detail: e.to_string(),
                    }
                })?;
            extras.egress = Some(Proxy::Loopback(started));
        }
        match extras.egress.as_ref() {
            Some(Proxy::Loopback(egress)) => Ok(EgressEndpoint {
                port: egress.port(),
                token: egress.token().to_owned(),
                realm: egress.realm().to_owned(),
            }),
            Some(Proxy::Forwarded(_)) => Err(EgressFailure::Start {
                detail: "this session's proxy serves forwarded connections only".into(),
            }),
            None => Err(EgressFailure::Poisoned),
        }
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
                    seq: d.seq,
                    code: d.refusal.code().to_owned(),
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

impl Sessions {
    /// Linux: this session's forwarded proxy (§9.2), started on first use.
    /// The caller serves each connection the browser host forwards with
    /// [`ForwardedEgress::serve`]; only connections from that browser
    /// host's channel belong there. `reset` stops it, which closes every
    /// tunnel, and connections served after that are closed unserved.
    pub fn forwarded_egress(
        &self,
        generation: u64,
        intel: Option<Arc<Intel>>,
    ) -> Result<Arc<ForwardedEgress>, EgressFailure> {
        let mut state = self.lock()?;
        let extras = state
            .current(generation)
            .ok_or(EgressFailure::NoActiveSession)?;
        if extras.egress.is_none() {
            let started = ForwardedEgress::new(policy(&extras.local_hosts), screen(intel));
            extras.egress = Some(Proxy::Forwarded(Arc::new(started)));
        }
        match extras.egress.as_ref() {
            Some(Proxy::Forwarded(egress)) => Ok(Arc::clone(egress)),
            Some(Proxy::Loopback(_)) => Err(EgressFailure::Start {
                detail: "this session's proxy listens on loopback".into(),
            }),
            None => Err(EgressFailure::Poisoned),
        }
    }
}

/// A session's proxy, whichever kind the platform uses.
#[derive(Debug)]
pub(crate) enum Proxy {
    Loopback(Egress),
    Forwarded(Arc<ForwardedEgress>),
}

impl Proxy {
    pub(crate) fn stop(&self) {
        match self {
            Self::Loopback(egress) => egress.stop(),
            Self::Forwarded(egress) => egress.stop(),
        }
    }

    pub(crate) fn set_local_hosts(&self, hosts: Vec<String>) {
        match self {
            Self::Loopback(egress) => egress.set_local_hosts(hosts),
            Self::Forwarded(egress) => egress.set_local_hosts(hosts),
        }
    }

    fn counts(&self) -> EgressCounts {
        match self {
            Self::Loopback(egress) => egress.counts(),
            Self::Forwarded(egress) => egress.counts(),
        }
    }

    fn denials(&self) -> Vec<Denial> {
        match self {
            Self::Loopback(egress) => egress.denials(),
            Self::Forwarded(egress) => egress.denials(),
        }
    }
}

fn policy(local_hosts: &[String]) -> EgressPolicy {
    EgressPolicy {
        local_hosts: local_hosts.to_vec(),
        ..EgressPolicy::default()
    }
}

fn screen(intel: Option<Arc<Intel>>) -> Option<Arc<dyn Screen>> {
    intel.map(|intel| Arc::new(IntelScreen(intel)) as Arc<dyn Screen>)
}

fn describe(refusal: &Refusal) -> String {
    match refusal {
        Refusal::Destination(_) => {
            "a local or private address (pages may reach only public ones)".to_owned()
        }
        other => other.to_string(),
    }
}

/// The installed snapshot's URL indicators, as the proxy's screen.
#[derive(Debug)]
struct IntelScreen(Arc<Intel>);

impl Screen for IntelScreen {
    fn listed(&self, url: &CanonicalUrl) -> Option<String> {
        let pack = self.0.pack()?;
        pack.urls
            .matches(url)
            .into_iter()
            .next()
            .map(|(expression, _)| expression)
    }
}
