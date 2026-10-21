//! Controller ⇄ Linux browser host (docs/architecture.md §9.2).
//!
//! The browser host runs Rift's code in the same process as Qt WebEngine's
//! browser process and network service, inside a sub-sandbox with no
//! network. It must be assumed compromised whenever the engine is, so the
//! controller treats every message from it as hostile input, as it does a
//! worker's: one message per `SOCK_SEQPACKET` datagram, size-checked before
//! decoding, then bounded field by field ([`decode_from_browser`]).
//!
//! The renderer rule ([`check_renderer`]) lives here, beside the facts it
//! reads, so that the browser host (which hides a page until its renderer
//! passes) and the controller (which ends the session when one fails) apply
//! the same code to the same facts. The browser host links this crate, never
//! rift-core: no vault or intelligence code is mapped next to the engine.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;

pub const SESSION_PROTOCOL_VERSION: u16 = 1;
/// Largest message in either direction (one datagram).
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Longest URL the browser host may ask about. A longer navigation is
/// blocked by the host without asking: it could not be checked (the core's
/// canonicalization takes 8 KiB).
pub const MAX_URL_BYTES: usize = 8 * 1024;
pub const MAX_ENGINE_BYTES: usize = 256;
pub const MAX_USER_AGENT_BYTES: usize = 512;
pub const MAX_FACTS: usize = 16;
pub const MAX_FACT_CODE_BYTES: usize = 64;
pub const MAX_FACT_TEXT_BYTES: usize = 2 * 1024;

/// The namespaces a renderer must not share with the browser host.
pub const OWN_NAMESPACES: [Namespace; 2] = [Namespace::Mount, Namespace::Pid];

/// Engine settings that turn its sandbox off or weaken it. Their presence in
/// the browser host's environment or arguments is refused at start.
pub const SANDBOX_SWITCH_VARIABLES: [&str; 2] =
    ["QTWEBENGINE_DISABLE_SANDBOX", "QTWEBENGINE_CHROMIUM_FLAGS"];
pub const SANDBOX_SWITCH_ARGUMENTS: [&str; 4] = [
    "--no-sandbox",
    "--single-process",
    "--disable-seccomp-filter-sandbox",
    "--disable-namespace-sandbox",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FromBrowser {
    /// First message: the protocol version and the engine's own description.
    Hello { version: u16, engine: String },
    /// May the page navigate to `url`? Answered by [`ToBrowser::Answer`]
    /// with the same `id`; the browser host waits for it. `confirmed`: the
    /// user saw this URL's reasons and chose to continue, which turns a
    /// `Confirm` into `Proceed` but never lifts a `Block`.
    Decide {
        id: u64,
        url: String,
        main_frame: bool,
        user_gesture: bool,
        redirect: bool,
        confirmed: bool,
    },
    /// What `/proc` says about a renderer and about the browser host itself,
    /// read before the renderer's page is shown.
    Renderer {
        pid: u32,
        renderer: ProcessFacts,
        host: ProcessFacts,
    },
    /// The engine wanted to download `url`. The engine's download was
    /// cancelled; the controller decides whether to fetch it itself, with
    /// the engine's `user_agent`. No cookies are passed (a session's are
    /// off the record and stay in the browser host).
    Download { url: String, user_agent: String },
    /// One TCP connection the engine opened to the forwarder, attached to
    /// this message (`SCM_RIGHTS`), for the controller's egress proxy.
    Connection,
    /// The user closed the window, or the host is ending for another reason.
    Closing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToBrowser {
    Answer {
        id: u64,
        decision: Decision,
    },
    /// Open `url` (checked by the controller already).
    Load {
        url: String,
    },
    /// End the session now.
    Close,
}

/// The controller's answer to a navigation, with its explanation already
/// escaped for display (the browser host shows the text as plain text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Proceed,
    /// Show the reasons; load only if the user confirms.
    Confirm {
        reasons: Vec<Fact>,
    },
    Block {
        reason: Fact,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub code: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Namespace {
    User,
    Mount,
    Pid,
    Network,
    Ipc,
}

impl Namespace {
    pub const ALL: [Self; 5] = [Self::User, Self::Mount, Self::Pid, Self::Network, Self::Ipc];

    /// The name of its link under `/proc/<pid>/ns/`.
    pub fn link_name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Mount => "mnt",
            Self::Pid => "pid",
            Self::Network => "net",
            Self::Ipc => "ipc",
        }
    }
}

/// What `/proc/<pid>/status` and `/proc/<pid>/ns/*` say about one process.
/// `None` means the field was absent or could not be read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessFacts {
    /// `Seccomp:` (2 is filter mode).
    pub seccomp_mode: Option<u8>,
    /// `Seccomp_filters:`, the number of stacked filters.
    pub seccomp_filters: Option<u32>,
    /// `NoNewPrivs:`.
    pub no_new_privs: Option<bool>,
    /// Namespace inodes, in the order of [`Namespace::ALL`].
    pub namespaces: [Option<u64>; 5],
}

impl ProcessFacts {
    /// Reads the fields Rift uses from the text of `/proc/<pid>/status`.
    /// Namespaces are left empty; see [`Self::set_namespace`].
    pub fn from_status(status: &str) -> Self {
        let mut facts = Self::default();
        for line in status.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "Seccomp" => facts.seccomp_mode = value.parse().ok(),
                "Seccomp_filters" => facts.seccomp_filters = value.parse().ok(),
                "NoNewPrivs" => {
                    facts.no_new_privs = match value {
                        "0" => Some(false),
                        "1" => Some(true),
                        _ => None,
                    };
                }
                _ => {}
            }
        }
        facts
    }

    /// Records a namespace from its link target, such as `mnt:[4026532274]`.
    /// A target of another kind or form leaves it unknown.
    pub fn set_namespace(&mut self, kind: Namespace, link: &str) {
        let inode = link
            .strip_prefix(kind.link_name())
            .and_then(|rest| rest.strip_prefix(":["))
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|digits| digits.parse().ok());
        if let Some(slot) = self.namespaces.get_mut(kind as usize) {
            *slot = inode;
        }
    }

    pub fn namespace(&self, kind: Namespace) -> Option<u64> {
        self.namespaces.get(kind as usize).copied().flatten()
    }
}

/// Why a renderer does not count as sandboxed by the engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxFailure {
    #[error("its seccomp state could not be read")]
    Unreadable,
    #[error("it runs without a seccomp filter")]
    NoSeccomp,
    #[error(
        "it has {renderer} seccomp filters and the browser host {host}: the engine's own filter is missing"
    )]
    NoEngineFilter { renderer: u32, host: u32 },
    #[error("it may gain privileges (NoNewPrivs is not set)")]
    NoNewPrivs,
    #[error("it shares the browser host's {0} namespace")]
    SharedNamespace(&'static str),
}

/// The rule from PoC Q1 (docs/reports/phase-5-qt-design.md). Every process
/// in a Flatpak already has one seccomp filter from bubblewrap, so a
/// renderer counts as sandboxed by the engine only with more filters than
/// the browser host, `NoNewPrivs`, and mount and pid namespaces of its own.
/// Unknown facts fail.
pub fn check_renderer(renderer: &ProcessFacts, host: &ProcessFacts) -> Result<(), SandboxFailure> {
    let (Some(mode), Some(filters), Some(host_filters)) = (
        renderer.seccomp_mode,
        renderer.seccomp_filters,
        host.seccomp_filters,
    ) else {
        return Err(SandboxFailure::Unreadable);
    };
    if mode != 2 || filters == 0 {
        return Err(SandboxFailure::NoSeccomp);
    }
    if filters <= host_filters {
        return Err(SandboxFailure::NoEngineFilter {
            renderer: filters,
            host: host_filters,
        });
    }
    if renderer.no_new_privs != Some(true) {
        return Err(SandboxFailure::NoNewPrivs);
    }
    for kind in OWN_NAMESPACES {
        match (renderer.namespace(kind), host.namespace(kind)) {
            (Some(theirs), Some(ours)) if theirs != ours => {}
            _ => return Err(SandboxFailure::SharedNamespace(kind.link_name())),
        }
    }
    Ok(())
}

/// The sandbox switches present in an environment and argument list, by
/// name (values are never echoed: they may be long or hostile).
pub fn sandbox_switches<'a>(
    variables: impl IntoIterator<Item = &'a str>,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let mut found: Vec<String> = variables
        .into_iter()
        .filter(|name| SANDBOX_SWITCH_VARIABLES.contains(name))
        .map(str::to_owned)
        .collect();
    for argument in arguments {
        let name = argument.split_once('=').map_or(argument, |(name, _)| name);
        if SANDBOX_SWITCH_ARGUMENTS.contains(&name) && !found.iter().any(|f| f == name) {
            found.push(name.to_owned());
        }
    }
    found
}

pub fn encode_message<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let bytes =
        postcard::to_allocvec(message).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// Decodes and bounds a message from the browser host.
pub fn decode_from_browser(bytes: &[u8]) -> Result<FromBrowser, ProtocolError> {
    let message: FromBrowser = decode(bytes)?;
    match &message {
        FromBrowser::Hello { engine, .. } => bounded(engine, MAX_ENGINE_BYTES, "engine")?,
        FromBrowser::Decide { url, .. } => bounded(url, MAX_URL_BYTES, "url")?,
        FromBrowser::Download { url, user_agent } => {
            bounded(url, MAX_URL_BYTES, "url")?;
            bounded(user_agent, MAX_USER_AGENT_BYTES, "user agent")?;
        }
        FromBrowser::Renderer { .. } | FromBrowser::Connection | FromBrowser::Closing => {}
    }
    Ok(message)
}

/// Decodes a message from the controller. The browser host trusts its
/// content (the controller is the more privileged side) but not its size.
pub fn decode_to_browser(bytes: &[u8]) -> Result<ToBrowser, ProtocolError> {
    let message: ToBrowser = decode(bytes)?;
    match &message {
        ToBrowser::Answer { decision, .. } => match decision {
            Decision::Proceed => {}
            Decision::Confirm { reasons } => {
                if reasons.len() > MAX_FACTS {
                    return Err(ProtocolError::OutOfBounds("facts"));
                }
                reasons.iter().try_for_each(fact)?;
            }
            Decision::Block { reason } => fact(reason)?,
        },
        ToBrowser::Load { url } => bounded(url, MAX_URL_BYTES, "url")?,
        ToBrowser::Close => {}
    }
    Ok(message)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    let (message, rest) =
        postcard::take_from_bytes(bytes).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    if !rest.is_empty() {
        return Err(ProtocolError::Malformed(
            "trailing bytes after message".into(),
        ));
    }
    Ok(message)
}

fn bounded(text: &str, limit: usize, field: &'static str) -> Result<(), ProtocolError> {
    if text.len() > limit {
        return Err(ProtocolError::OutOfBounds(field));
    }
    Ok(())
}

fn fact(fact: &Fact) -> Result<(), ProtocolError> {
    bounded(&fact.code, MAX_FACT_CODE_BYTES, "fact code")?;
    bounded(&fact.text, MAX_FACT_TEXT_BYTES, "fact text")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// From PoC Q1/Q2 (run 39511905939): the browser host, then the renderer
    /// it spawned through the portal.
    const HOST_STATUS: &str = "Name:\tqt-probe\nSeccomp:\t2\nSeccomp_filters:\t1\nNoNewPrivs:\t1\n";
    const RENDERER_STATUS: &str =
        "Name:\tQtWebEngineProc\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\n";

    fn facts(status: &str, mnt: u64, pid: u64) -> ProcessFacts {
        let mut facts = ProcessFacts::from_status(status);
        facts.set_namespace(Namespace::Mount, &format!("mnt:[{mnt}]"));
        facts.set_namespace(Namespace::Pid, &format!("pid:[{pid}]"));
        facts
    }

    #[test]
    fn the_renderer_rule_matches_what_q1_measured() {
        let host = facts(HOST_STATUS, 4026532274, 4026532333);
        let renderer = facts(RENDERER_STATUS, 4026532400, 4026532401);
        assert_eq!(check_renderer(&renderer, &host), Ok(()));
        // QTWEBENGINE_DISABLE_SANDBOX=1 (Q1's negative control): only
        // Flatpak's filter, and the host's namespaces.
        let disabled = facts(HOST_STATUS, 4026532274, 4026532333);
        assert_eq!(
            check_renderer(&disabled, &host),
            Err(SandboxFailure::NoEngineFilter {
                renderer: 1,
                host: 1
            })
        );
        let mut shared = renderer.clone();
        shared.set_namespace(Namespace::Pid, "pid:[4026532333]");
        assert_eq!(
            check_renderer(&shared, &host),
            Err(SandboxFailure::SharedNamespace("pid"))
        );
        let mut privs = renderer.clone();
        privs.no_new_privs = Some(false);
        assert_eq!(
            check_renderer(&privs, &host),
            Err(SandboxFailure::NoNewPrivs)
        );
        let mut off = renderer.clone();
        off.seccomp_mode = Some(0);
        assert_eq!(check_renderer(&off, &host), Err(SandboxFailure::NoSeccomp));
    }

    #[test]
    fn unknown_facts_fail() {
        let host = facts(HOST_STATUS, 1, 2);
        let renderer = facts(RENDERER_STATUS, 3, 4);
        assert_eq!(
            check_renderer(&ProcessFacts::default(), &host),
            Err(SandboxFailure::Unreadable)
        );
        assert_eq!(
            check_renderer(&renderer, &ProcessFacts::default()),
            Err(SandboxFailure::Unreadable)
        );
        let mut unread = renderer.clone();
        unread.set_namespace(Namespace::Mount, "unreadable");
        assert_eq!(
            check_renderer(&unread, &host),
            Err(SandboxFailure::SharedNamespace("mnt"))
        );
        // A link of the wrong kind is not taken for this one.
        let mut wrong = renderer;
        wrong.set_namespace(Namespace::Mount, "net:[5]");
        assert_eq!(wrong.namespace(Namespace::Mount), None);
        assert_eq!(
            ProcessFacts::from_status("NoNewPrivs:\tyes\nSeccomp:\tx\n"),
            ProcessFacts::default()
        );
    }

    #[test]
    fn sandbox_switches_are_found_by_name() {
        assert!(sandbox_switches(["PATH", "HOME"], ["rift-browser", "--url"]).is_empty());
        assert_eq!(
            sandbox_switches(
                ["QTWEBENGINE_CHROMIUM_FLAGS", "PATH"],
                [
                    "rift-browser",
                    "--no-sandbox",
                    "--single-process=1",
                    "--no-sandbox"
                ]
            ),
            vec![
                "QTWEBENGINE_CHROMIUM_FLAGS",
                "--no-sandbox",
                "--single-process"
            ]
        );
    }

    #[test]
    fn messages_round_trip_and_are_bounded() {
        let decide = FromBrowser::Decide {
            id: 7,
            url: "https://example.com/".into(),
            main_frame: true,
            user_gesture: false,
            redirect: false,
            confirmed: false,
        };
        let bytes = encode_message(&decide).unwrap();
        assert_eq!(decode_from_browser(&bytes).unwrap(), decide);
        let long = FromBrowser::Download {
            url: "a".repeat(MAX_URL_BYTES + 1),
            user_agent: "Mozilla/5.0".into(),
        };
        let bytes = encode_message(&long).unwrap();
        assert_eq!(
            decode_from_browser(&bytes),
            Err(ProtocolError::OutOfBounds("url"))
        );
        let mut trailing = encode_message(&FromBrowser::Closing).unwrap();
        trailing.push(0);
        assert!(decode_from_browser(&trailing).is_err());
        assert_eq!(
            decode_from_browser(&vec![0; MAX_MESSAGE_BYTES + 1]),
            Err(ProtocolError::FrameTooLarge(MAX_MESSAGE_BYTES + 1))
        );
        assert_eq!(decode_from_browser(&[]), Err(ProtocolError::EmptyFrame));
        let answer = ToBrowser::Answer {
            id: 7,
            decision: Decision::Confirm {
                reasons: vec![
                    Fact {
                        code: "new-domain".into(),
                        text: "x".into(),
                    };
                    MAX_FACTS + 1
                ],
            },
        };
        let bytes = encode_message(&answer).unwrap();
        assert_eq!(
            decode_to_browser(&bytes),
            Err(ProtocolError::OutOfBounds("facts"))
        );
        assert!(matches!(
            encode_message(&ToBrowser::Load {
                url: "a".repeat(MAX_MESSAGE_BYTES)
            }),
            Err(ProtocolError::FrameTooLarge(_))
        ));
    }
}
