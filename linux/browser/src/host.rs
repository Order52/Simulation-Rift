//! The browser host's side of the session (docs/architecture.md §9.2): the
//! channel to the controller, the forwarder, and the renderer check.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::Duration;

use rift_channel::Channel;
use rift_protocol::session::{
    Decision, FromBrowser, MAX_URL_BYTES, MAX_USER_AGENT_BYTES, Namespace, ProcessFacts, ToBrowser,
    check_renderer,
};

use crate::bridge::{NavigationAnswer, ffi};

/// How long a navigation waits for the controller before it is blocked.
const DECIDE_TIMEOUT: Duration = Duration::from_secs(10);

const PROCEED: u8 = 0;
const CONFIRM: u8 = 1;
const BLOCK: u8 = 2;

#[derive(Debug)]
struct Host {
    /// Sending is serialized: the GUI thread and the forwarder both send.
    channel: Mutex<Channel>,
    pending: Mutex<HashMap<u64, Sender<Decision>>>,
    next_id: AtomicU64,
}

static HOST: OnceLock<Host> = OnceLock::new();

/// Takes the channel from stdin, starts the forwarder and the reader, and
/// says hello. Returns the forwarder's port for Qt's application proxy.
pub fn start() -> io::Result<u16> {
    let channel = Channel::from_stdin()?;
    let reader = channel.try_clone()?;
    let forwarder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = forwarder.local_addr()?.port();
    HOST.set(Host {
        channel: Mutex::new(channel),
        pending: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
    })
    .map_err(|_| io::Error::other("the browser host was started twice"))?;
    send(
        &FromBrowser::Hello {
            version: rift_protocol::session::SESSION_PROTOCOL_VERSION,
            engine: ffi::engine_version(),
        },
        None,
    )?;
    thread::Builder::new()
        .name("rift-forwarder".into())
        .spawn(move || forward(&forwarder))?;
    thread::Builder::new()
        .name("rift-channel".into())
        .spawn(move || read(&reader))?;
    Ok(port)
}

/// Tells the controller the window is going away. Errors are ignored: the
/// controller also sees the channel close.
pub fn closing() {
    let _sent = send(&FromBrowser::Closing, None);
}

fn host() -> io::Result<&'static Host> {
    HOST.get()
        .ok_or_else(|| io::Error::other("the browser host has not started"))
}

fn send(message: &FromBrowser, attached: Option<std::os::fd::BorrowedFd<'_>>) -> io::Result<()> {
    let host = host()?;
    let channel = host.channel.lock().unwrap_or_else(PoisonError::into_inner);
    channel.send_from_browser(message, attached)
}

/// Every connection the engine opens to the proxy port goes to the
/// controller. Nothing is read or written here.
fn forward(listener: &TcpListener) {
    for incoming in listener.incoming() {
        let Ok(connection) = incoming else { continue };
        if send(&FromBrowser::Connection, Some(connection.as_fd())).is_err() {
            // The channel is gone: the session is over.
            ffi::post_close();
            return;
        }
    }
}

fn read(channel: &Channel) {
    loop {
        match channel.recv_to_browser() {
            Ok(Some(ToBrowser::Answer { id, decision })) => {
                let Ok(host) = host() else { return };
                let waiter = host
                    .pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&id);
                if let Some(waiter) = waiter {
                    // The navigation may have timed out already.
                    let _delivered = waiter.send(decision);
                }
            }
            Ok(Some(ToBrowser::Load { url })) => ffi::post_load(&url),
            Ok(Some(ToBrowser::Close) | None) | Err(_) => {
                ffi::post_close();
                return;
            }
        }
    }
}

pub fn decide(
    url: &str,
    main_frame: bool,
    user_gesture: bool,
    redirect: bool,
    confirmed: bool,
) -> NavigationAnswer {
    if url.len() > MAX_URL_BYTES {
        return answer(
            BLOCK,
            "This address is too long to check against Rift's threat database.",
        );
    }
    match ask(url, main_frame, user_gesture, redirect, confirmed) {
        Ok(Decision::Proceed) => answer(PROCEED, ""),
        Ok(Decision::Confirm { reasons }) => {
            let text = reasons
                .iter()
                .map(|fact| fact.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            answer(CONFIRM, &text)
        }
        Ok(Decision::Block { reason }) => answer(BLOCK, &reason.text),
        Err(error) => answer(
            BLOCK,
            &format!("Rift's controller did not decide this navigation ({error})."),
        ),
    }
}

fn ask(
    url: &str,
    main_frame: bool,
    user_gesture: bool,
    redirect: bool,
    confirmed: bool,
) -> io::Result<Decision> {
    let host = host()?;
    let id = host.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel();
    host.pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(id, tx);
    let sent = send(
        &FromBrowser::Decide {
            id,
            url: url.to_owned(),
            main_frame,
            user_gesture,
            redirect,
            confirmed,
        },
        None,
    );
    let result = sent.and_then(|()| {
        rx.recv_timeout(DECIDE_TIMEOUT)
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer"))
    });
    host.pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
    result
}

fn answer(kind: u8, text: &str) -> NavigationAnswer {
    NavigationAnswer {
        kind,
        text: text.to_owned(),
    }
}

/// Reads the renderer's and this process's facts, reports both to the
/// controller, and applies the same rule here. Empty means sandboxed.
pub fn renderer_started(pid: i64) -> String {
    let Ok(pid) = u32::try_from(pid) else {
        return "the engine reported no renderer process".into();
    };
    let renderer = facts(&pid.to_string());
    let own = facts("self");
    let verdict = check_renderer(&renderer, &own);
    let reported = send(
        &FromBrowser::Renderer {
            pid,
            renderer,
            host: own,
        },
        None,
    );
    match (verdict, reported) {
        (Ok(()), Ok(())) => String::new(),
        (Err(failure), _) => format!("The page's renderer is not sandboxed: {failure}."),
        (Ok(()), Err(error)) => format!("The renderer check could not be reported ({error})."),
    }
}

fn facts(pid: &str) -> ProcessFacts {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let mut facts = ProcessFacts::from_status(&status);
    for kind in Namespace::ALL {
        if let Ok(link) = fs::read_link(format!("/proc/{pid}/ns/{}", kind.link_name())) {
            facts.set_namespace(kind, &link.to_string_lossy());
        }
    }
    facts
}

pub fn download_requested(url: &str, user_agent: &str) {
    if url.len() <= MAX_URL_BYTES && user_agent.len() <= MAX_USER_AGENT_BYTES {
        let _sent = send(
            &FromBrowser::Download {
                url: url.to_owned(),
                user_agent: user_agent.to_owned(),
            },
            None,
        );
    }
}
