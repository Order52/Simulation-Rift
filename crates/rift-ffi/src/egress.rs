//! The browser's egress proxy (docs/architecture.md §8.8, §9.2, INV-14). One
//! proxy per session: it starts when the browser first asks for it, follows
//! the session's local-host exceptions, and stops when the session ends,
//! before the browser is wiped. Android's listens on loopback behind a
//! token; Linux's has no listener and serves the connections the browser
//! host forwards ([`Sessions::forwarded_egress`]).

use std::sync::{Arc, Mutex};

use rift_core::egress::{
    Denial, Egress, EgressCounts, EgressPolicy, ForwardedEgress, Refusal, Remark, Screen,
};
use rift_core::text::escape_for_display;
use rift_core::urlcanon::CanonicalUrl;
use rift_core::urlmodel::View;

use crate::{Ai, Intel, SessionFailure, Sessions};

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
    /// The most recent destinations let through with a remark (Rift AI),
    /// oldest first.
    pub remarks: Vec<EgressRemark>,
    /// The distinct destinations let through (`host:port`, escaped), first
    /// seen first; at most 64.
    pub contacted: Vec<String>,
}

/// A destination let through that Rift AI rates High, escaped for the UI.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EgressRemark {
    /// Counts this session's remarks from 1.
    pub seq: u64,
    pub destination: String,
    pub text: String,
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
    /// one current at each request) before it is resolved. With `ai`, each
    /// destination let through is also scored, and those it rates High are
    /// listed as remarks (never refused for it).
    pub fn egress(
        &self,
        generation: u64,
        intel: Option<Arc<Intel>>,
        ai: Option<Arc<Ai>>,
    ) -> Result<EgressEndpoint, EgressFailure> {
        let mut state = self.lock()?;
        let extras = state
            .current(generation)
            .ok_or(EgressFailure::NoActiveSession)?;
        if extras.egress.is_none() {
            let screen = screen(intel, ai, Arc::clone(&extras.inspected));
            extras.screen.clone_from(&screen);
            let started = Egress::start(policy(&extras.local_hosts), screen).map_err(|e| {
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
                    destination: destination(&d.host, d.port),
                    reason: escape_for_display(&describe(&d.refusal)),
                })
                .collect(),
            remarks: egress
                .remarks()
                .into_iter()
                .map(|r| EgressRemark {
                    seq: r.seq,
                    destination: destination(&r.host, r.port),
                    // Built from escaped parts by crate::ai::remark.
                    text: r.text,
                })
                .collect(),
            contacted: egress
                .contacted()
                .into_iter()
                .map(|(host, port)| destination(&host, port))
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
            let started = ForwardedEgress::new(
                policy(&extras.local_hosts),
                screen(intel, None, Arc::clone(&extras.inspected)),
            );
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

    fn remarks(&self) -> Vec<Remark> {
        match self {
            Self::Loopback(egress) => egress.remarks(),
            Self::Forwarded(egress) => egress.remarks(),
        }
    }

    fn contacted(&self) -> Vec<(String, u16)> {
        match self {
            Self::Loopback(egress) => egress.contacted(),
            Self::Forwarded(egress) => egress.contacted(),
        }
    }
}

fn policy(local_hosts: &[String]) -> EgressPolicy {
    EgressPolicy {
        local_hosts: local_hosts.to_vec(),
        ..EgressPolicy::default()
    }
}

fn screen(
    intel: Option<Arc<Intel>>,
    ai: Option<Arc<Ai>>,
    inspected: Arc<Mutex<Vec<String>>>,
) -> Option<Arc<dyn Screen>> {
    if intel.is_none() && ai.is_none() {
        return None;
    }
    Some(Arc::new(RiftScreen {
        intel,
        ai,
        inspected,
    }))
}

/// `host:port` (an IPv6 literal in brackets), escaped for the UI.
fn destination(host: &str, port: u16) -> String {
    escape_for_display(&if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

fn describe(refusal: &Refusal) -> String {
    match refusal {
        Refusal::Destination(_) => {
            "a local or private address (pages may reach only public ones)".to_owned()
        }
        other => other.to_string(),
    }
}

/// The proxy's screen: the installed snapshot's URL indicators refuse,
/// except on the hosts the user chose to open (`inspected`), and Rift AI
/// remarks.
#[derive(Debug)]
struct RiftScreen {
    intel: Option<Arc<Intel>>,
    ai: Option<Arc<Ai>>,
    inspected: Arc<Mutex<Vec<String>>>,
}

impl Screen for RiftScreen {
    fn remark(&self, url: &CanonicalUrl, view: View) -> Option<String> {
        // A current pack's model replaces the one the app ships.
        let pack = self.intel.as_ref().and_then(|intel| intel.pack());
        let model = pack
            .as_ref()
            .and_then(|pack| pack.model.as_deref())
            .or(self.ai.as_ref().map(|ai| &ai.model))?;
        crate::ai::remark(model, url, view)
    }

    fn listed(&self, url: &CanonicalUrl) -> Option<String> {
        let pack = self.intel.as_ref()?.pack()?;
        // A lock that cannot be read lets nothing through.
        let opened = self
            .inspected
            .lock()
            .is_ok_and(|hosts| hosts.iter().any(|h| h == url.host()));
        if opened {
            return None;
        }
        pack.urls
            .matches(url)
            .into_iter()
            .next()
            .map(|(expression, _)| expression)
    }
}
