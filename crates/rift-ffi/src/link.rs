//! The Check sheet's link tools (docs/architecture.md §10.10): an address
//! cleaned with the ClearURLs rules the user downloaded, and a link's
//! redirects followed to where it goes, each hop checked as the link itself
//! is before it is contacted.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rift_core::clean::{self, Rules};
use rift_core::download::{self, DownloadPolicy, TraceEnd};
use rift_core::text::escape_for_display;
use rift_core::trackers;

use crate::{Intel, LinkCheck, Navigation, Navigator, RelaySetting};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CleanFailure {
    #[error("{reason}")]
    Unusable { reason: String },
}

/// What cleaning did to an address.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CleanedLink {
    /// The cleaned address, to check, copy or open (ASCII: the engine's form).
    pub address: String,
    /// Names of the parameters removed, escaped for display.
    pub removed: Vec<String>,
    /// Addresses taken out of redirect links, outermost first, escaped for display.
    pub unwrapped: Vec<String>,
    /// The whole address is a tracker's: there is nothing to keep.
    pub tracker_only: bool,
    pub changed: bool,
}

/// Compiled ClearURLs rules.
#[derive(Debug, uniffi::Object)]
pub struct LinkCleaner {
    rules: Rules,
}

#[uniffi::export]
impl LinkCleaner {
    /// Compiles a ClearURLs rules file (`data.min.json`). Takes a few
    /// milliseconds: call it away from the main thread.
    #[uniffi::constructor]
    pub fn load(text: String) -> Result<Arc<Self>, CleanFailure> {
        let rules = Rules::parse(&text).map_err(|e| CleanFailure::Unusable {
            reason: e.to_string(),
        })?;
        Ok(Arc::new(Self { rules }))
    }

    /// The rules' providers in use.
    pub fn providers(&self) -> u32 {
        u32::try_from(self.rules.providers()).unwrap_or(u32::MAX)
    }

    /// Patterns left out because this engine cannot compile them.
    pub fn skipped(&self) -> u32 {
        u32::try_from(self.rules.skipped()).unwrap_or(u32::MAX)
    }

    /// Cleans `address` (an address in the engine's form, as a check shows it).
    pub fn clean(&self, address: String) -> CleanedLink {
        let cleaned = self.rules.clean(&address);
        CleanedLink {
            changed: cleaned.changed(&address),
            address: cleaned.url,
            removed: cleaned
                .removed
                .iter()
                .map(|n| escape_for_display(n))
                .collect(),
            unwrapped: cleaned
                .unwrapped
                .iter()
                .map(|u| escape_for_display(u))
                .collect(),
            tracker_only: cleaned.tracker_only,
        }
    }
}

/// A tracking parameter found in a link (§10.14).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TrackingParam {
    /// The parameter's name, escaped for display.
    pub name: String,
    pub who: String,
    pub what: String,
}

/// The tracking parameters Rift knows in `address`'s query, explained.
#[uniffi::export]
pub fn link_tracking(address: String) -> Vec<TrackingParam> {
    trackers::link_params(&address)
        .into_iter()
        .map(|(name, p)| TrackingParam {
            name,
            who: p.who.to_owned(),
            what: p.what.to_owned(),
        })
        .collect()
}

/// `address` without the tracking parameters [`link_tracking`] names; None
/// if it has none or is not a web address.
#[uniffi::export]
pub fn link_without_tracking(address: String) -> Option<String> {
    trackers::link_without_tracking(&address)
}

/// A tracker a page used (§10.14), with what it does.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TrackerInfo {
    pub name: String,
    pub company: String,
    /// "Analytics", "Advertising", "Session recording" or "Social network".
    pub kind: String,
    pub explanation: String,
}

/// The tracker Rift knows `host` (and `path`, for the few that need it) to
/// be, if any.
#[uniffi::export]
pub fn tracker_for(host: String, path: String) -> Option<TrackerInfo> {
    let tracker = trackers::tracker_for_url(&host, &path)?;
    Some(TrackerInfo {
        name: tracker.name.to_owned(),
        company: tracker.company.to_owned(),
        kind: tracker.kind.label().to_owned(),
        explanation: tracker.kind.explain().to_owned(),
    })
}

/// `address` without its query and fragment; None if it is not a web address.
#[uniffi::export]
pub fn link_without_query(address: String) -> Option<String> {
    clean::without_query(&address)
}

/// `address` over HTTPS; None if it is not an `http` address.
#[uniffi::export]
pub fn link_with_https(address: String) -> Option<String> {
    clean::with_https(&address)
}

/// One address a link led to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TraceHop {
    /// The address, to check, copy or open (ASCII: the engine's form).
    pub address: String,
    /// The hop checked as Check checks a link, before it was contacted.
    pub check: LinkCheck,
    /// What the server answered; None if it was not contacted.
    pub status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TraceOutcome {
    /// The last hop is where the link goes, as far as redirects tell.
    Arrived,
    /// Rift would not open the last hop (the threat database lists it, or it
    /// is no address the engine could load), so it was not contacted.
    Stopped,
    /// The last hop sends the link out of the web, to `address` (an app link,
    /// say, escaped for display). Not followed.
    LeavesTheWeb { address: String },
    /// The trace could not go on; `reason` is escaped for display.
    Failed { reason: String },
}

/// Where a link goes.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LinkTrace {
    /// Every address the link led to, the link itself first.
    pub hops: Vec<TraceHop>,
    pub outcome: TraceOutcome,
}

/// Short timeouts: a trace is one tap that someone is waiting on.
fn trace_policy(relay: Option<Arc<RelaySetting>>) -> DownloadPolicy {
    DownloadPolicy {
        relay: relay.map(|r| r.relay.clone()),
        connect_timeout: Duration::from_secs(10),
        response_timeout: Duration::from_secs(10),
        total_timeout: Duration::from_secs(30),
        ..DownloadPolicy::default()
    }
}

#[uniffi::export]
impl Navigator {
    /// Follows `url`'s redirects to where it goes, without loading any page
    /// (the core asks each address for its status and reads no body). Each
    /// hop is checked first, and one Rift would not open is not contacted.
    /// Contacting a link tells its server it was followed, so this runs only
    /// when the user asks. With `relay`, every hop goes through it (§8.12).
    /// Blocks for up to 30 seconds.
    pub fn trace(
        &self,
        url: String,
        intel: Option<Arc<Intel>>,
        now_unix: u64,
        user_agent: String,
        relay: Option<Arc<RelaySetting>>,
    ) -> LinkTrace {
        self.trace_with(&url, intel, now_unix, &user_agent, &trace_policy(relay))
    }
}

impl Navigator {
    pub(crate) fn trace_with(
        &self,
        url: &str,
        intel: Option<Arc<Intel>>,
        now_unix: u64,
        user_agent: &str,
        policy: &DownloadPolicy,
    ) -> LinkTrace {
        let mut checks = Vec::new();
        let traced = download::trace(url, policy, user_agent, &AtomicBool::new(false), |hop| {
            let check = self.check(hop.to_owned(), intel.clone(), now_unix);
            let go = !matches!(check.navigation, Navigation::Block { .. });
            checks.push(check);
            go
        });
        // The screen sees each hop once, just before it is recorded.
        let hops = traced
            .hops
            .into_iter()
            .zip(checks)
            .map(|(hop, check)| TraceHop {
                address: hop.url,
                check,
                status: hop.status,
            })
            .collect();
        let outcome = match traced.end {
            TraceEnd::Arrived => TraceOutcome::Arrived,
            TraceEnd::Stopped => TraceOutcome::Stopped,
            TraceEnd::LeavesTheWeb(address) => TraceOutcome::LeavesTheWeb {
                address: escape_for_display(&address),
            },
            TraceEnd::Failed(error) => TraceOutcome::Failed {
                reason: escape_for_display(&error.to_string()),
            },
        };
        LinkTrace { hops, outcome }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    #[test]
    fn trackers_in_a_link_are_explained_and_removed() {
        let link = "https://shop.example/item?id=7&utm_source=news&fbclid=IwAR0x&gclid=Cj0K";
        let names: Vec<String> = link_tracking(link.into())
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, vec!["utm_source", "fbclid", "gclid"]);
        assert!(
            link_tracking(link.into())
                .iter()
                .all(|p| !p.who.is_empty() && !p.what.is_empty())
        );
        assert_eq!(
            link_without_tracking(link.into()).as_deref(),
            Some("https://shop.example/item?id=7")
        );
        assert_eq!(
            link_without_tracking("https://shop.example/item?id=7".into()),
            None
        );
        let ga = tracker_for("region1.google-analytics.com".into(), String::new()).unwrap();
        assert_eq!(
            (ga.company.as_str(), ga.kind.as_str()),
            ("Google", "Analytics")
        );
        assert!(tracker_for("example.com".into(), String::new()).is_none());
    }

    const RULES: &str = r#"{"providers":{
        "globalRules":{"urlPattern":".*","rules":["(?:%3F)?utm(?:_[a-z_]*)?","evil.*"]},
        "google":{"urlPattern":"^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google(?:\\.[a-z]{2,}){1,}",
            "redirections":["^https?:\\/\\/(?:[a-z0-9-]+\\.)*?google(?:\\.[a-z]{2,}){1,}\\/url\\?.*?(?:url|q)=(https?[^&]+)"]}
    }}"#;

    #[test]
    fn cleaning_escapes_what_it_shows() {
        let cleaner = LinkCleaner::load(RULES.into()).unwrap();
        let c = cleaner.clean("https://a.example/?evil%E2%80%AE=1&id=2".into());
        assert_eq!(c.address, "https://a.example/?id=2");
        assert!(c.changed);
        assert!(!c.removed[0].contains('\u{202e}'), "{:?}", c.removed);
        let c = cleaner.clean(
            "https://www.google.com/url?q=https%3A%2F%2Fother.example%2F%3Futm_source%3Dx".into(),
        );
        assert_eq!(c.unwrapped, ["https://other.example/?utm_source=x"]);
        assert_eq!(c.address, "https://other.example/");
        assert!(matches!(
            LinkCleaner::load("{}".into()),
            Err(CleanFailure::Unusable { .. })
        ));
    }

    /// Serves `/a` -> `/b` -> `/c` (200) and `/out` -> an app link.
    fn server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut line = String::new();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let _ = reader.read_line(&mut line);
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                        break;
                    }
                }
                let head = match line.split(' ').nth(1).unwrap_or("/") {
                    "/a" => "302 Found\r\nLocation: /b".to_owned(),
                    "/b" => format!("301 Moved\r\nLocation: http://localhost:{port}/c"),
                    "/out" => "302 Found\r\nLocation: market://details?id=x".to_owned(),
                    _ => "200 OK".to_owned(),
                };
                let _ = stream.write_all(
                    format!("HTTP/1.1 {head}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                );
            }
        });
        port
    }

    fn local() -> DownloadPolicy {
        DownloadPolicy {
            local_hosts: vec!["localhost".into()],
            ..trace_policy(None)
        }
    }

    #[test]
    fn every_hop_is_checked_and_its_status_kept() {
        let port = server();
        let navigator = Navigator::new(Vec::new(), Vec::new());
        let t = navigator.trace_with(
            &format!("http://localhost:{port}/a"),
            None,
            0,
            "t",
            &local(),
        );
        assert_eq!(t.outcome, TraceOutcome::Arrived);
        let statuses: Vec<_> = t.hops.iter().map(|h| h.status).collect();
        assert_eq!(statuses, [Some(302), Some(301), Some(200)]);
        assert_eq!(t.hops[2].address, format!("http://localhost:{port}/c"));
        assert_eq!(
            t.hops[2].check.address,
            format!("http://localhost:{port}/c")
        );
        let t = navigator.trace_with(
            &format!("http://localhost:{port}/out"),
            None,
            0,
            "t",
            &local(),
        );
        assert_eq!(
            t.outcome,
            TraceOutcome::LeavesTheWeb {
                address: "market://details?id=x".into()
            }
        );
        // The phone's own network is refused, as for any transfer.
        let t = navigator.trace(
            format!("http://localhost:{port}/a"),
            None,
            0,
            "t".into(),
            None,
        );
        assert!(matches!(t.outcome, TraceOutcome::Failed { .. }), "{t:?}");
        assert_eq!(t.hops.len(), 1);
        assert_eq!(t.hops[0].status, None);
    }
}
