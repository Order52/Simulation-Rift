//! The controller's sessions (docs/architecture.md §9.2, §15): one browser
//! host at a time, each in a new generation, with every navigation decided
//! here, every connection served by this generation's checking proxy, and
//! every download fetched into its quarantine. Ending a session — by the
//! user, by the browser window closing, or by a failed check — destroys it
//! through rift-core, which calls [`Disposal`] for the browser host.

use std::net::TcpStream;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::worker::Workers;
use rift_channel::Channel;
use rift_ffi::{
    DownloadInfo, EgressStats, ForwardedEgress, Intel, IntelStatus, Navigation, Navigator,
    Recovery, Sessions, Verdict, display_safe, typed_address,
};
use rift_protocol::session::{
    Decision, Fact, FromBrowser, MAX_FACT_CODE_BYTES, MAX_FACT_TEXT_BYTES, MAX_FACTS,
    MAX_URL_BYTES, SESSION_PROTOCOL_VERSION, ToBrowser, check_renderer,
};
use rustix::net::SocketType;

use crate::browser::{Disposal, Launcher, Running};

/// The same lists as the Android app's.
const PROTECTED_DOMAINS: [&str; 10] = [
    "paypal.com",
    "google.com",
    "apple.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "netflix.com",
    "github.com",
];
const SHORTENERS: [&str; 7] = [
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
];

/// Downloads fetched at once per controller; more are refused, so that a
/// page cannot start an unbounded number of transfers.
const MAX_DOWNLOADS: usize = 4;

/// What the UI is told. Text is for display as plain text; anything from
/// the web in it has been escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Status(String),
    Started(u64),
    Ended(u64),
    Quarantined(String),
}

pub type Notify = Arc<dyn Fn(Event) + Send + Sync>;

/// Where the controller keeps its data, all inside the Flatpak's own.
#[derive(Debug, Clone)]
pub struct Paths<'a> {
    /// `$XDG_DATA_HOME/rift`: sessions and the threat database.
    pub data: &'a Path,
    /// `~/.var/app/<id>/sandbox`: the browser host's state directories.
    pub sandbox: &'a Path,
    /// The browser host inside the sub-sandbox.
    pub browser: &'a Path,
    /// The worker, started directly in the app's sandbox.
    pub worker: &'a Path,
    /// A demo threat database the build carries (`root.json` and `repo/`),
    /// installed when none is.
    pub demo_intel: Option<&'a Path>,
}

#[derive(Debug)]
pub struct Controller {
    sessions: Arc<Sessions>,
    disposal: Arc<Disposal>,
    navigator: Arc<Navigator>,
    intel: Option<Arc<Intel>>,
    intel_problem: Option<String>,
    launcher: Launcher,
    workers: Workers,
    demo_intel: Option<PathBuf>,
    /// Serializes starting and ending sessions, so that ending one never
    /// ends its successor.
    lifecycle: Mutex<()>,
    downloads: Arc<AtomicUsize>,
}

impl Controller {
    /// Opens the session area, completing any cleanup an earlier run left.
    pub fn open(paths: &Paths<'_>) -> Result<(Arc<Self>, Recovery), String> {
        let launcher = Launcher::new(paths.sandbox.to_owned(), paths.browser.to_owned());
        let disposal = Arc::new(Disposal::new(launcher.clone()));
        let root = utf8(&paths.data.join("sessions"))?;
        let sessions = Sessions::open(root, disposal.clone()).map_err(|e| e.to_string())?;
        let (intel, intel_problem) = match Intel::open(utf8(&paths.data.join("intel"))?) {
            Ok(intel) => (Some(intel), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let recovery = sessions.recovery();
        let controller = Arc::new(Self {
            sessions,
            disposal,
            navigator: Navigator::new(
                PROTECTED_DOMAINS.map(String::from).to_vec(),
                SHORTENERS.map(String::from).to_vec(),
            ),
            intel,
            intel_problem,
            launcher,
            workers: Workers::new(paths.worker),
            demo_intel: paths.demo_intel.map(Path::to_owned),
            lifecycle: Mutex::new(()),
            downloads: Arc::new(AtomicUsize::new(0)),
        });
        Ok((controller, recovery))
    }

    /// The threat database's state, for the UI.
    pub fn intel_summary(&self) -> String {
        let Some(intel) = &self.intel else {
            return format!(
                "The threat database could not be opened ({}); addresses are checked by heuristics only.",
                self.intel_problem.as_deref().unwrap_or("unknown error")
            );
        };
        match intel.status(now_unix()) {
            IntelStatus::Missing => {
                "No threat database is installed; addresses are checked by heuristics only.".into()
            }
            IntelStatus::Installed {
                snapshot, stale, ..
            } if stale => format!("Threat database {snapshot} is out of date."),
            IntelStatus::Installed { snapshot, .. } => format!("Threat database {snapshot}."),
            IntelStatus::Damaged { detail } => format!("The threat database is damaged: {detail}."),
        }
    }

    /// Installs the build's demo threat database if no database is
    /// installed, after a fresh worker has compiled its rules (§13.2).
    /// None if there was nothing to do. Blocks: call it off the UI thread.
    pub fn install_demo_intel(&self) -> Option<Result<String, String>> {
        let (intel, demo) = (self.intel.as_ref()?, self.demo_intel.as_ref()?);
        if !matches!(intel.status(now_unix()), IntelStatus::Missing) {
            return None;
        }
        let result = (|| {
            let root = std::fs::read(demo.join("root.json"))
                .map_err(|e| format!("the demo database's root could not be read: {e}"))?;
            let pending = Arc::clone(intel)
                .verify_offline(root, utf8(&demo.join("repo"))?)
                .map_err(|e| e.to_string())?;
            self.workers.install(&pending, now_unix())?;
            Ok(pending.snapshot())
        })();
        match &result {
            Ok(snapshot) => log(&format!(
                "demo threat database {snapshot} installed, its rules compiled by a confined worker"
            )),
            Err(error) => log(&format!(
                "the demo threat database was not installed: {error}"
            )),
        }
        Some(result)
    }

    /// Starts a new session at `input` (as typed), ending any current one.
    /// Blocks while the previous session is destroyed: call it off the UI
    /// thread.
    pub fn open_session(self: &Arc<Self>, input: &str, notify: Notify) -> Result<u64, String> {
        let url = typed_address(input.to_owned());
        if url.len() > MAX_URL_BYTES {
            return Err("This address is too long to check.".into());
        }
        let _lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(previous) = self.sessions.current_generation() {
            self.sessions.reset().map_err(|e| e.to_string())?;
            log(&format!("session {previous} destroyed"));
            notify(Event::Ended(previous));
        }
        let generation = self.sessions.start().map_err(|e| e.to_string())?;
        if let Err(error) = self.launch(generation, url, notify.clone()) {
            log(&format!("session {generation} did not start: {error}"));
            return Err(match self.sessions.reset() {
                Ok(_) => error,
                Err(cleanup) => format!("{error}; and its cleanup failed: {cleanup}"),
            });
        }
        log(&format!("session {generation} started"));
        Ok(generation)
    }

    /// Destroys the current session, or only `generation` if given. Returns
    /// the generation destroyed, if any.
    pub fn end_session(&self, generation: Option<u64>) -> Result<Option<u64>, String> {
        let _lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match self.sessions.current_generation() {
            Some(current) if generation.is_none_or(|g| g == current) => {
                if let Some(stats) = self.sessions.egress_stats(current) {
                    log(&format!(
                        "session {current}: proxy allowed {}, refused {}",
                        stats.allowed, stats.denied
                    ));
                }
                let ended = self.sessions.reset().map_err(|e| e.to_string())?;
                log(&format!("session {ended} destroyed"));
                Ok(Some(ended))
            }
            _ => Ok(None),
        }
    }

    pub fn stats(&self) -> Option<EgressStats> {
        let generation = self.sessions.current_generation()?;
        self.sessions.egress_stats(generation)
    }

    fn launch(
        self: &Arc<Self>,
        generation: u64,
        url: String,
        notify: Notify,
    ) -> Result<(), String> {
        let proxy = self
            .sessions
            .forwarded_egress(generation, self.intel.clone())
            .map_err(|e| e.to_string())?;
        let (ours, theirs) = Channel::pair().map_err(|e| format!("no session channel: {e}"))?;
        let reader = ours
            .try_clone()
            .map_err(|e| format!("no session channel: {e}"))?;
        let child = self
            .launcher
            .spawn(generation, theirs)
            .map_err(|e| format!("the browser could not be started: {e}"))?;
        self.disposal.attach(Running {
            generation,
            child,
            channel: ours,
        });
        let controller = Arc::clone(self);
        thread::Builder::new()
            .name(format!("rift-session-{generation}"))
            .spawn(move || controller.serve(generation, &reader, &proxy, &url, &notify))
            .map(drop)
            .map_err(|e| format!("the session could not be served: {e}"))
    }

    /// Serves one browser host until its channel closes or a check fails,
    /// then ends the session if it is still the current one.
    fn serve(
        &self,
        generation: u64,
        channel: &Channel,
        proxy: &ForwardedEgress,
        url: &str,
        notify: &Notify,
    ) {
        let mut verified = false;
        let mut loaded = false;
        let why = loop {
            let (message, attached) = match channel.recv_from_browser() {
                Ok(Some(received)) => received,
                Ok(None) => break "The browser window closed.".to_owned(),
                Err(error) => {
                    break format!("The browser sent a message Rift could not accept ({error}).");
                }
            };
            match message {
                FromBrowser::Hello { version, engine } => {
                    if version != SESSION_PROTOCOL_VERSION {
                        break format!(
                            "The browser speaks session protocol {version}, not {SESSION_PROTOCOL_VERSION}."
                        );
                    }
                    log(&format!(
                        "session {generation}: browser host {}",
                        display_safe(engine)
                    ));
                    notify(Event::Status(
                        "Checking that the page's renderer is sandboxed…".into(),
                    ));
                }
                FromBrowser::Renderer { renderer, host, .. } => {
                    if let Err(failure) = check_renderer(&renderer, &host) {
                        log(&format!(
                            "session {generation}: renderer not sandboxed: {failure}"
                        ));
                        break format!("A renderer is not sandboxed ({failure}).");
                    }
                    verified = true;
                    log(&format!("session {generation}: renderer sandboxed"));
                    if !loaded {
                        loaded = true;
                        let load = ToBrowser::Load {
                            url: url.to_owned(),
                        };
                        if let Err(error) = channel.send_to_browser(&load) {
                            break format!("The browser could not be reached ({error}).");
                        }
                        notify(Event::Status("Session open.".into()));
                    }
                }
                FromBrowser::Decide {
                    id, url, confirmed, ..
                } => {
                    let navigation =
                        self.navigator
                            .decide(url, verified, self.intel.clone(), now_unix());
                    let decision = answer(navigation, confirmed);
                    match &decision {
                        Decision::Proceed => {}
                        Decision::Confirm { reasons } => {
                            let codes: Vec<&str> =
                                reasons.iter().map(|r| r.code.as_str()).collect();
                            log(&format!(
                                "session {generation}: navigation needs confirming: {}",
                                codes.join(", ")
                            ));
                        }
                        Decision::Block { reason } => {
                            log(&format!(
                                "session {generation}: navigation blocked: {}",
                                reason.code
                            ));
                        }
                    }
                    if let Err(error) = channel.send_to_browser(&ToBrowser::Answer { id, decision })
                    {
                        break format!("The browser could not be reached ({error}).");
                    }
                }
                FromBrowser::Download { url, user_agent } => {
                    self.download(generation, url, user_agent, notify);
                }
                FromBrowser::Connection => {
                    if let Some(fd) = attached
                        && let Err(error) = serve_connection(proxy, fd)
                    {
                        log(&format!(
                            "session {generation}: a connection was not served: {error}"
                        ));
                    }
                }
                FromBrowser::Closing => {}
            }
        };
        log(&format!("session {generation} ending: {why}"));
        match self.end_session(Some(generation)) {
            Ok(Some(_)) => {
                notify(Event::Status(format!("{why} The session was destroyed.")));
                notify(Event::Ended(generation));
            }
            // Already ended by the user or replaced by a new session.
            Ok(None) => {}
            Err(error) => notify(Event::Status(format!(
                "{why} The session could not be destroyed: {error}. Rift will retry when it next starts."
            ))),
        }
    }

    fn download(&self, generation: u64, url: String, user_agent: String, notify: &Notify) {
        if self.downloads.fetch_add(1, Ordering::SeqCst) >= MAX_DOWNLOADS {
            self.downloads.fetch_sub(1, Ordering::SeqCst);
            notify(Event::Status(
                "A download was refused: too many are in progress.".into(),
            ));
            return;
        }
        let sessions = Arc::clone(&self.sessions);
        let workers = self.workers.clone();
        let intel = self.intel.clone();
        let downloads = Arc::clone(&self.downloads);
        let report = Arc::clone(notify);
        let started = thread::Builder::new()
            .name("rift-download".into())
            .spawn(move || {
                let info = DownloadInfo {
                    url,
                    // The session's cookies stay in the browser host.
                    cookie: None,
                    user_agent,
                    referer: None,
                    content_disposition: None,
                };
                match sessions.download(generation, info) {
                    Ok(file) => {
                        let verdict = match intel {
                            Some(intel) => Arc::clone(&sessions)
                                .scan(generation, file.id.clone(), intel)
                                .map_err(|e| e.to_string())
                                .and_then(|start| workers.scan(start))
                                .map_or_else(|e| format!("not scanned: {e}"), |v| describe(&v)),
                            None => "not scanned: no threat database could be opened".into(),
                        };
                        log(&format!("session {generation}: a download was quarantined"));
                        report(Event::Quarantined(format!(
                            "{} ({} bytes, from {}): {verdict}",
                            file.display_name, file.size, file.source
                        )));
                    }
                    Err(error) => {
                        report(Event::Status(format!("A download was not kept: {error}")))
                    }
                }
                downloads.fetch_sub(1, Ordering::SeqCst);
            });
        if started.is_err() {
            self.downloads.fetch_sub(1, Ordering::SeqCst);
            notify(Event::Status("A download could not be started.".into()));
        }
    }
}

/// A verdict in one line. Its texts come escaped from rift-core.
fn describe(verdict: &Verdict) -> String {
    let mut parts = vec![verdict.label.clone()];
    parts.extend(
        verdict
            .findings
            .iter()
            .map(|f| format!("{} {} ({})", f.check, f.id, f.description)),
    );
    parts.extend(verdict.gaps.iter().cloned());
    if verdict.demo {
        parts.push("the threat database is a demo and gives no real coverage".into());
    }
    parts.join("; ")
}

/// Hands one forwarded connection to the proxy. Only stream sockets are
/// served: the browser host could send any descriptor.
fn serve_connection(proxy: &ForwardedEgress, fd: OwnedFd) -> std::io::Result<()> {
    if rustix::net::sockopt::socket_type(&fd)? != SocketType::STREAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the descriptor is not a stream socket",
        ));
    }
    proxy.serve(TcpStream::from(fd))
}

/// The protocol's answer to rift-core's decision. A Confirm the user has
/// already confirmed for this URL proceeds; a Block stays a Block.
fn answer(navigation: Navigation, confirmed: bool) -> Decision {
    match navigation {
        Navigation::Proceed { .. } => Decision::Proceed,
        Navigation::Confirm { .. } if confirmed => Decision::Proceed,
        Navigation::Confirm { reasons, .. } => Decision::Confirm {
            reasons: reasons.into_iter().take(MAX_FACTS).map(fact).collect(),
        },
        Navigation::Block { reason, .. } => Decision::Block {
            reason: fact(reason),
        },
    }
}

fn fact(fact: rift_ffi::Fact) -> Fact {
    Fact {
        code: clip(fact.code, MAX_FACT_CODE_BYTES),
        text: clip(fact.text, MAX_FACT_TEXT_BYTES),
    }
}

fn clip(mut text: String, max: usize) -> String {
    let end = text.floor_char_boundary(max);
    text.truncate(end);
    text
}

fn utf8(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not UTF-8", path.display()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The controller's log, on stderr. It names sessions, never addresses.
pub fn log(line: &str) {
    eprintln!("rift: {line}");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn ffi_fact(code: &str, text: &str) -> rift_ffi::Fact {
        rift_ffi::Fact {
            code: code.into(),
            text: text.into(),
        }
    }

    #[test]
    fn a_confirmation_counts_only_for_confirm_and_never_unblocks() {
        let confirm = || Navigation::Confirm {
            reasons: vec![ffi_fact("lookalike", "Looks like paypal.com.")],
            notes: vec![],
        };
        assert!(
            matches!(answer(confirm(), false), Decision::Confirm { reasons } if reasons[0].code == "lookalike")
        );
        assert_eq!(answer(confirm(), true), Decision::Proceed);
        let block = || Navigation::Block {
            reason: ffi_fact("listed", "Listed as phishing."),
            inspect_anyway: true,
        };
        assert!(
            matches!(answer(block(), true), Decision::Block { reason } if reason.code == "listed")
        );
        assert_eq!(
            answer(Navigation::Proceed { notes: vec![] }, false),
            Decision::Proceed
        );
    }

    #[test]
    fn answers_fit_the_protocol_bounds() {
        let reasons = (0..40)
            .map(|_| ffi_fact(&"c".repeat(100), &"é".repeat(3000)))
            .collect();
        let Decision::Confirm { reasons } = answer(
            Navigation::Confirm {
                reasons,
                notes: vec![],
            },
            false,
        ) else {
            panic!("expected Confirm");
        };
        assert_eq!(reasons.len(), MAX_FACTS);
        assert!(reasons[0].code.len() <= MAX_FACT_CODE_BYTES);
        assert!(reasons[0].text.len() <= MAX_FACT_TEXT_BYTES);
        let message = ToBrowser::Answer {
            id: 1,
            decision: Decision::Confirm { reasons },
        };
        let bytes = rift_protocol::session::encode_message(&message).unwrap();
        assert_eq!(
            rift_protocol::session::decode_to_browser(&bytes).unwrap(),
            message
        );
    }

    #[test]
    fn the_navigator_blocks_everything_until_a_renderer_is_verified() {
        let navigator = Navigator::new(vec![], vec![]);
        let before = navigator.decide("https://example.com/".into(), false, None, now_unix());
        assert!(matches!(answer(before, true), Decision::Block { .. }));
        let after = navigator.decide("https://example.com/".into(), true, None, now_unix());
        assert!(!matches!(answer(after, false), Decision::Block { .. }));
    }
}
