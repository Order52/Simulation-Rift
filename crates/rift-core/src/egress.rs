//! The browser's only way to the network (docs/architecture.md §8.8, INV-14).
//!
//! On Android the browser runs as its own app, and while a session is open
//! the controller's VPN routes every packet from that app's UID into a tun
//! device that forwards nothing. Loopback is not routed through a VPN, so
//! this proxy, listening on 127.0.0.1 in the controller, is what is left.
//! WebView is told to use it for everything (`ProxyController`, with
//! Chromium's implicit loopback and link-local bypass removed).
//!
//! What the proxy guarantees, for every connection:
//!
//! * The caller knows this session's token (Basic proxy authentication), so
//!   other apps on the device cannot use it.
//! * The destination is resolved once, here, and the connection goes to
//!   exactly the addresses that passed [`check_destination`]: no loopback,
//!   private, link-local, multicast or otherwise non-public address, unless
//!   the user allowed that host name for this session (INV-13's exception).
//! * Only two request forms exist: `CONNECT host:port` (HTTPS, WebSockets)
//!   and an absolute `http://` URL. Anything else is refused before any
//!   connection is made. The head is bounded and parsed strictly.
//! * With a [`Screen`], a destination the threat intelligence lists is
//!   refused before it is resolved: every subframe, script, image and
//!   connection of a page, not only its main-frame address (§10.3).
//!
//! It does not inspect TLS: for HTTPS it sees the host name and port only,
//! so for HTTPS only host-level indicators can match; for plain HTTP the
//! whole URL is checked. It is not a content filter and claims nothing about
//! what a public site serves.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::transfer::{DestinationError, check_destination};
use crate::urlcanon::{self, CanonError, CanonicalUrl};

/// The longest request head the proxy reads (request line and headers).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Denials kept for display, newest last.
const MAX_DENIALS: usize = 64;
const MAX_HOST_CHARS: usize = 253;
const MAX_HEADERS: usize = 100;
const THREAD_STACK: usize = 256 * 1024;
const COPY_BUFFER: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Host names the user allowed, for this session, to reach local or
    /// private addresses. Compared exactly, ASCII case-insensitively.
    pub local_hosts: Vec<String>,
    pub max_connections: usize,
    /// To receive the whole request head.
    pub head_timeout: Duration,
    pub connect_timeout: Duration,
    /// A tunnel with no traffic in either direction for this long is closed.
    pub idle_timeout: Duration,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            local_hosts: Vec::new(),
            max_connections: 256,
            head_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(10 * 60),
        }
    }
}

/// Threat intelligence for the proxy: which destinations are listed.
pub trait Screen: Send + Sync + fmt::Debug {
    /// The listed lookup expression that `url` matches, if any.
    fn listed(&self, url: &CanonicalUrl) -> Option<String>;
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("{0}")]
    Destination(DestinationError),
    /// The destination matched an indicator (the listed expression).
    #[error("listed as malicious in the threat database ({0})")]
    KnownMalicious(String),
    /// The address could not be checked against the threat database (it is
    /// longer than canonicalization takes), so it is not let through.
    #[error("the address could not be checked against the threat database: {0}")]
    NotChecked(CanonError),
    #[error("the name does not resolve")]
    DoesNotResolve,
    #[error("no connection could be made")]
    Unreachable,
    #[error("the request is malformed: {0}")]
    Malformed(&'static str),
    #[error("too many connections are open")]
    Busy,
}

impl Refusal {
    /// A stable code for the trusted UI.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Destination(_) => "local-address",
            Self::KnownMalicious(_) => "known-malicious",
            Self::NotChecked(_) => "not-checked",
            Self::DoesNotResolve => "does-not-resolve",
            Self::Unreachable => "unreachable",
            Self::Malformed(_) => "malformed",
            Self::Busy => "busy",
        }
    }
}

/// One refused destination, for the trusted UI. `host` is as the browser
/// sent it (a validated host name or address literal), never escaped here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// Numbers this proxy's refusals from 1, so a reader can tell which are new.
    pub seq: u64,
    pub host: String,
    pub port: u16,
    pub refusal: Refusal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EgressCounts {
    pub allowed: u64,
    pub denied: u64,
    /// Requests without the right token (the browser's first try, or another app).
    pub unauthenticated: u64,
}

/// A running proxy. Dropping it stops it.
#[derive(Debug)]
pub struct Egress {
    shared: Arc<Shared>,
    port: u16,
}

#[derive(Debug)]
struct Shared {
    /// SHA-256 of the expected `Proxy-Authorization` value: compared as
    /// digests, so the comparison time does not depend on how much of a
    /// guess was right.
    expected_auth: [u8; 32],
    token: String,
    realm: String,
    policy: RwLock<EgressPolicy>,
    screen: Option<Arc<dyn Screen>>,
    stopped: AtomicBool,
    live: Mutex<HashMap<u64, TcpStream>>,
    next_id: AtomicU64,
    denials: Mutex<VecDeque<Denial>>,
    /// Refusals recorded so far (the last [`Denial::seq`]); written under `denials`.
    recorded: AtomicU64,
    allowed: AtomicU64,
    denied: AtomicU64,
    unauthenticated: AtomicU64,
}

impl Egress {
    /// Listens on 127.0.0.1 with a fresh random port, token and realm.
    /// `screen`, if given, is asked about every destination before it is resolved.
    pub fn start(policy: EgressPolicy, screen: Option<Arc<dyn Screen>>) -> io::Result<Self> {
        let token = random_hex(32)?;
        let realm = format!("rift-{}", random_hex(8)?);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let expected = proxy_authorization(&token);
        let shared = Arc::new(Shared {
            expected_auth: Sha256::digest(expected.as_bytes()).into(),
            token,
            realm,
            policy: RwLock::new(policy),
            screen,
            stopped: AtomicBool::new(false),
            live: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            denials: Mutex::new(VecDeque::new()),
            recorded: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            unauthenticated: AtomicU64::new(0),
        });
        let accepting = Arc::clone(&shared);
        thread::Builder::new()
            .name("rift-egress".into())
            .stack_size(THREAD_STACK)
            .spawn(move || accept_loop(&accepting, &listener))?;
        Ok(Self { shared, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The secret the browser answers the proxy's challenge with (user "rift").
    pub fn token(&self) -> &str {
        &self.shared.token
    }

    /// The challenge's realm, which the browser checks before answering, so
    /// that it never sends the token to a site that asks for credentials.
    pub fn realm(&self) -> &str {
        &self.shared.realm
    }

    pub fn set_local_hosts(&self, hosts: Vec<String>) {
        let mut policy = self
            .shared
            .policy
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        policy.local_hosts = hosts;
    }

    /// The most recent refusals, oldest first.
    pub fn denials(&self) -> Vec<Denial> {
        lock(&self.shared.denials).iter().cloned().collect()
    }

    pub fn counts(&self) -> EgressCounts {
        EgressCounts {
            allowed: self.shared.allowed.load(Ordering::Relaxed),
            denied: self.shared.denied.load(Ordering::Relaxed),
            unauthenticated: self.shared.unauthenticated.load(Ordering::Relaxed),
        }
    }

    /// Stops accepting and closes every open connection and tunnel.
    /// Idempotent.
    pub fn stop(&self) {
        if self.shared.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        // Wakes the accept loop, which then sees the flag and exits.
        let _wake = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)),
            Duration::from_secs(1),
        );
        let live: Vec<TcpStream> = lock(&self.shared.live).drain().map(|(_, s)| s).collect();
        for stream in live {
            // Already closed is fine: the goal is that nothing stays open.
            let _closed = stream.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for Egress {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(shared: &Arc<Shared>, listener: &TcpListener) {
    for incoming in listener.incoming() {
        if shared.stopped.load(Ordering::SeqCst) {
            return;
        }
        let Ok(client) = incoming else { continue };
        let connection = Arc::clone(shared);
        let spawned = thread::Builder::new()
            .name("rift-egress-conn".into())
            .stack_size(THREAD_STACK)
            .spawn(move || serve(&connection, client));
        // Without a thread the connection is dropped, which closes it.
        drop(spawned);
    }
}

/// Registers a stream so [`Egress::stop`] can close it; unregisters on drop.
struct Tracked<'a> {
    shared: &'a Shared,
    ids: Vec<u64>,
}

impl<'a> Tracked<'a> {
    fn new(shared: &'a Shared) -> Self {
        Self {
            shared,
            ids: Vec::new(),
        }
    }

    /// False if the proxy is stopping or full (the stream is not registered).
    fn add(&mut self, stream: &TcpStream, limit: usize) -> bool {
        let Ok(clone) = stream.try_clone() else {
            return false;
        };
        let mut live = lock(&self.shared.live);
        if self.shared.stopped.load(Ordering::SeqCst) || live.len() >= limit {
            return false;
        }
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        live.insert(id, clone);
        self.ids.push(id);
        true
    }
}

impl Drop for Tracked<'_> {
    fn drop(&mut self) {
        let mut live = lock(&self.shared.live);
        for id in &self.ids {
            live.remove(id);
        }
    }
}

fn serve(shared: &Shared, mut client: TcpStream) {
    let policy = shared
        .policy
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let mut tracked = Tracked::new(shared);
    // Each client connection may hold two slots (itself and its upstream).
    if !tracked.add(&client, policy.max_connections.saturating_mul(2)) {
        if !shared.stopped.load(Ordering::SeqCst) {
            let _sent = respond(
                &mut client,
                503,
                "Service Unavailable",
                "Too many connections are open.",
            );
            shared.denied.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    if client.set_read_timeout(Some(policy.head_timeout)).is_err() {
        return;
    }
    let (head, leftover) = match read_head(&mut client) {
        Ok(read) => read,
        Err(HeadReadError::TooLarge) => {
            let _sent = respond(
                &mut client,
                431,
                "Request Header Fields Too Large",
                "The request head is too large.",
            );
            return;
        }
        Err(HeadReadError::Io) => return,
    };
    let request = match parse_head(&head) {
        Ok(request) => request,
        Err(reason) => {
            let _sent = respond(&mut client, 400, "Bad Request", reason);
            return;
        }
    };
    if !authorized(shared, &request) {
        shared.unauthenticated.fetch_add(1, Ordering::Relaxed);
        let challenge = format!(
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"{}\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            shared.realm
        );
        let _sent = client.write_all(challenge.as_bytes());
        return;
    }
    // Before resolving, so a listed name is not even looked up.
    if let Some(Err(refusal)) = shared.screen.as_deref().map(|s| screen(s, &request)) {
        record_denial(shared, &request.target, refusal.clone());
        let _sent = respond(&mut client, 403, "Forbidden", &refusal.to_string());
        return;
    }
    let upstream = match connect(&request.target, &policy) {
        Ok(upstream) => upstream,
        Err(refusal) => {
            record_denial(shared, &request.target, refusal.clone());
            let _sent = respond(&mut client, 403, "Forbidden", &refusal.to_string());
            return;
        }
    };
    if !tracked.add(&upstream, policy.max_connections.saturating_mul(2)) {
        return;
    }
    shared.allowed.fetch_add(1, Ordering::Relaxed);
    let opening = match &request.form {
        Form::Connect => {
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
            Vec::new()
        }
        Form::Absolute { origin_form } => forwarded_head(&request, origin_form),
    };
    tunnel(client, upstream, opening, leftover, policy.idle_timeout);
}

fn authorized(shared: &Shared, request: &Request) -> bool {
    let mut values = request
        .headers
        .iter()
        .filter(|(name, _)| name == "proxy-authorization");
    match (values.next(), values.next()) {
        (Some((_, value)), None) => {
            <[u8; 32]>::from(Sha256::digest(value.as_bytes())) == shared.expected_auth
        }
        _ => false,
    }
}

/// Checks `request` against the threat database: its whole URL for plain
/// HTTP, and its host (and parent domains) for either form. A plain-HTTP URL
/// that cannot be canonicalized (longer than [`urlcanon::MAX_URL_BYTES`]) is
/// refused as not checked: screening its host alone let a listed path
/// through behind a padded query.
fn screen(screen: &dyn Screen, request: &Request) -> Result<(), Refusal> {
    let host = &request.target.host;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let mut urls = Vec::new();
    if let Form::Absolute { origin_form } = &request.form {
        urls.push(format!("http://{host}{origin_form}"));
    }
    urls.push(format!("http://{host}/"));
    for url in urls {
        let url = urlcanon::canonicalize(url.as_bytes()).map_err(Refusal::NotChecked)?;
        if let Some(matched) = screen.listed(&url) {
            return Err(Refusal::KnownMalicious(matched));
        }
    }
    Ok(())
}

fn record_denial(shared: &Shared, target: &Target, refusal: Refusal) {
    shared.denied.fetch_add(1, Ordering::Relaxed);
    let mut denials = lock(&shared.denials);
    if denials.len() >= MAX_DENIALS {
        denials.pop_front();
    }
    let seq = shared
        .recorded
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    denials.push_back(Denial {
        seq,
        host: target.host.clone(),
        port: target.port,
        refusal,
    });
}

/// Resolves once and connects only to the addresses that passed the check.
fn connect(target: &Target, policy: &EgressPolicy) -> Result<TcpStream, Refusal> {
    let addresses: Vec<SocketAddr> = match target.host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, target.port)],
        Err(_) => (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|_| Refusal::DoesNotResolve)?
            .collect(),
    };
    if addresses.is_empty() {
        return Err(Refusal::DoesNotResolve);
    }
    let allowed_by_user = target.host.parse::<IpAddr>().is_err()
        && policy
            .local_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&target.host));
    if !allowed_by_user {
        // Any non-public answer refuses the name, as for downloads (DNS rebinding).
        for address in &addresses {
            check_destination(address.ip()).map_err(Refusal::Destination)?;
        }
    }
    for address in &addresses {
        if let Ok(stream) = TcpStream::connect_timeout(address, policy.connect_timeout) {
            return Ok(stream);
        }
    }
    Err(Refusal::Unreachable)
}

/// The head sent upstream for an absolute-form request: the origin-form
/// target, the browser's headers without proxy-only ones, and one request
/// per connection.
fn forwarded_head(request: &Request, origin_form: &str) -> Vec<u8> {
    let mut head = format!("{} {} {}\r\n", request.method, origin_form, request.version);
    for (name, value) in &request.headers {
        if matches!(
            name.as_str(),
            "proxy-authorization" | "proxy-connection" | "connection" | "keep-alive"
        ) {
            continue;
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    head.into_bytes()
}

fn tunnel(
    client: TcpStream,
    upstream: TcpStream,
    opening: Vec<u8>,
    leftover: Vec<u8>,
    idle: Duration,
) {
    let configured = [&client, &upstream]
        .iter()
        .all(|s| s.set_read_timeout(Some(idle)).is_ok() && s.set_write_timeout(Some(idle)).is_ok());
    if !configured {
        return;
    }
    let (Ok(mut client_read), Ok(mut upstream_write)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let started = thread::Builder::new()
        .name("rift-egress-up".into())
        .stack_size(THREAD_STACK)
        .spawn(move || {
            if upstream_write.write_all(&opening).is_ok()
                && upstream_write.write_all(&leftover).is_ok()
            {
                copy(&mut client_read, &mut upstream_write);
            }
            let _closed = upstream_write.shutdown(Shutdown::Write);
        });
    let mut upstream_read = upstream;
    let mut client_write = client;
    if started.is_ok() {
        copy(&mut upstream_read, &mut client_write);
    }
    let _closed = client_write.shutdown(Shutdown::Both);
    let _closed = upstream_read.shutdown(Shutdown::Both);
    if let Ok(handle) = started {
        let _joined = handle.join();
    }
}

/// Copies until end of stream, an error or the idle timeout.
fn copy(from: &mut TcpStream, to: &mut TcpStream) {
    let mut buf = vec![0u8; COPY_BUFFER];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else { return };
                if to.write_all(chunk).is_err() {
                    return;
                }
            }
        }
    }
}

fn respond(client: &mut TcpStream, status: u16, reason: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes())
}

enum HeadReadError {
    TooLarge,
    Io,
}

/// Reads up to the end of the head; returns the head (without the final
/// blank line) and any bytes read past it (the start of a body or tunnel).
fn read_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), HeadReadError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_head_end(&buf) {
            if end > MAX_HEAD_BYTES {
                return Err(HeadReadError::TooLarge);
            }
            let leftover = buf.split_off(end.saturating_add(4));
            buf.truncate(end);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(HeadReadError::TooLarge);
        }
        let n = stream.read(&mut chunk).map_err(|_| HeadReadError::Io)?;
        if n == 0 {
            return Err(HeadReadError::Io);
        }
        buf.extend_from_slice(chunk.get(..n).ok_or(HeadReadError::Io)?);
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Where a request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// A host name (letters, digits, '-', '.') or an IP literal, without brackets.
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Form {
    /// `CONNECT host:port`: a tunnel (HTTPS, WebSockets).
    Connect,
    /// `GET http://host/path`: forwarded as `GET /path`.
    Absolute { origin_form: String },
}

/// A parsed request head. Header names are lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: Target,
    pub form: Form,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

/// Parses a request head strictly. Public for the fuzz target.
pub fn parse_head(head: &[u8]) -> Result<Request, &'static str> {
    if head.len() > MAX_HEAD_BYTES {
        return Err("the head is too large");
    }
    let text = std::str::from_utf8(head).map_err(|_| "the head is not text")?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("no request line")?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the request line is not METHOD TARGET VERSION");
    };
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err("the method is not a token");
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("only HTTP/1.0 and HTTP/1.1 are accepted");
    }
    let (target, form) = if method == "CONNECT" {
        (parse_authority(target)?, Form::Connect)
    } else {
        parse_absolute(target)?
    };
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err("too many headers");
        }
        let (name, value) = line.split_once(':').ok_or("a header has no colon")?;
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err("a header name is not a token");
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if !value
            .bytes()
            .all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
        {
            return Err("a header value has a control or non-ASCII character");
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    Ok(Request {
        method: method.to_owned(),
        target,
        form,
        version: version.to_owned(),
        headers,
    })
}

/// `host:port`, `[v6]:port`. The port is required.
fn parse_authority(authority: &str) -> Result<Target, &'static str> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (v6, after) = rest
            .split_once(']')
            .ok_or("an IPv6 literal is not closed")?;
        let port = after.strip_prefix(':').ok_or("the port is missing")?;
        v6.parse::<std::net::Ipv6Addr>()
            .map_err(|_| "the IPv6 literal is not valid")?;
        (v6, port)
    } else {
        let (host, port) = authority.rsplit_once(':').ok_or("the port is missing")?;
        if !valid_host_name(host) {
            return Err("the host is not a valid name or address");
        }
        (host, port)
    };
    Ok(Target {
        host: host.to_ascii_lowercase(),
        port: parse_port(port)?,
    })
}

fn parse_absolute(target: &str) -> Result<(Target, Form), &'static str> {
    let url = url::Url::parse(target).map_err(|_| "the target is not an absolute URL")?;
    if url.scheme() != "http" {
        return Err("only http:// URLs are forwarded; other schemes use CONNECT");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials in the URL are refused");
    }
    let host = match url.host() {
        Some(url::Host::Domain(name)) if valid_host_name(name) => name.to_owned(),
        Some(url::Host::Ipv4(v4)) => v4.to_string(),
        Some(url::Host::Ipv6(v6)) => v6.to_string(),
        _ => return Err("the host is not a valid name or address"),
    };
    let port = url.port_or_known_default().ok_or("the port is missing")?;
    if port == 0 {
        return Err("port 0 is not valid");
    }
    let origin_form = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    Ok((Target { host, port }, Form::Absolute { origin_form }))
}

fn parse_port(port: &str) -> Result<u16, &'static str> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the port is not a number");
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err("the port is out of range"),
        Ok(p) => Ok(p),
    }
}

/// A DNS name in ASCII (IDNs arrive as punycode) or an IPv4 literal.
fn valid_host_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_CHARS
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && !host.starts_with('.')
        && !host.contains("..")
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The `Proxy-Authorization` value that answers this proxy's challenge.
pub fn proxy_authorization(token: &str) -> String {
    format!("Basic {}", base64(format!("rift:{token}").as_bytes()))
}

fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(hex::encode(buf))
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    for chunk in input.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let symbols = chunk.len().saturating_add(1);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            let index = (n >> shift) & 0x3f;
            if i < symbols {
                out.push(char::from(
                    ALPHABET.get(index as usize).copied().unwrap_or(b'A'),
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use std::io::BufRead;

    fn proxy(local_hosts: &[&str]) -> Egress {
        Egress::start(
            EgressPolicy {
                local_hosts: local_hosts.iter().map(|s| (*s).to_owned()).collect(),
                head_timeout: Duration::from_secs(5),
                connect_timeout: Duration::from_secs(5),
                ..EgressPolicy::default()
            },
            None,
        )
        .unwrap()
    }

    /// Lists the given lookup expressions, as a threat database would.
    #[derive(Debug)]
    struct Listed(Vec<&'static str>);

    impl Screen for Listed {
        fn listed(&self, url: &CanonicalUrl) -> Option<String> {
            url.expressions()
                .into_iter()
                .find(|e| self.0.contains(&e.as_str()))
        }
    }

    fn auth(p: &Egress) -> String {
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(format!("rift:{}", p.token()).as_bytes())
        )
    }

    /// Sends `request` to the proxy and returns the first line of the answer.
    fn ask(p: &Egress, request: &str) -> (String, TcpStream) {
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut reader = io::BufReader::new(s.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        (line.trim_end().to_owned(), s)
    }

    /// A one-shot server on loopback that records the head it receives and
    /// then echoes what follows.
    fn upstream() -> (u16, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).unwrap();
            tx.send(String::from_utf8_lossy(&buf[..n]).into_owned())
                .unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
            let mut rest = vec![0u8; 4096];
            while let Ok(n) = s.read(&mut rest) {
                if n == 0 || s.write_all(&rest[..n]).is_err() {
                    break;
                }
            }
        });
        (port, rx)
    }

    #[test]
    fn requests_without_the_token_are_challenged_and_not_forwarded() {
        let p = proxy(&["localhost"]);
        let (port, rx) = upstream();
        let mut s = TcpStream::connect(("127.0.0.1", p.port())).unwrap();
        s.write_all(
            format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        let mut answer = String::new();
        s.read_to_string(&mut answer).unwrap();
        assert!(
            answer.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"),
            "{answer}"
        );
        assert!(
            answer.contains(&format!("realm=\"{}\"", p.realm())),
            "{answer}"
        );
        let (line, _) = ask(
            &p,
            &format!(
                "CONNECT localhost:{port} HTTP/1.1\r\nProxy-Authorization: Basic cmlmdDp3cm9uZw==\r\n\r\n"
            ),
        );
        assert_eq!(line, "HTTP/1.1 407 Proxy Authentication Required");
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "nothing reached the server"
        );
        assert_eq!(p.counts().unauthenticated, 2);
        assert!(
            p.denials().is_empty(),
            "challenges are not destination refusals"
        );
    }

    #[test]
    fn connect_to_an_allowed_host_tunnels_bytes_both_ways() {
        let p = proxy(&["localhost"]);
        let (port, rx) = upstream();
        let (line, mut s) = ask(
            &p,
            &format!("CONNECT LocalHost:{port} HTTP/1.1\r\n{}\r\n", auth(&p)),
        );
        assert_eq!(line, "HTTP/1.1 200 Connection Established");
        s.write_all(b"hello through the tunnel").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "hello through the tunnel"
        );
        assert_eq!(p.counts().allowed, 1);
    }

    #[test]
    fn absolute_form_is_forwarded_as_origin_form_without_proxy_headers() {
        let p = proxy(&["localhost"]);
        let (port, rx) = upstream();
        let (line, _) = ask(
            &p,
            &format!(
                "GET http://localhost:{port}/path?q=1 HTTP/1.1\r\nHost: localhost:{port}\r\n{}Proxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n",
                auth(&p)
            ),
        );
        assert_eq!(line, "HTTP/1.1 200 OK");
        let head = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("GET /path?q=1 HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("accept: */*\r\n"), "{head}");
        assert!(head.contains("Connection: close\r\n"), "{head}");
        assert!(!head.to_ascii_lowercase().contains("proxy-"), "{head}");
    }

    #[test]
    fn non_public_destinations_are_refused_before_connecting() {
        let p = proxy(&["localhost"]);
        let (port, rx) = upstream();
        for target in [
            format!("127.0.0.1:{port}"),
            format!("[::1]:{port}"),
            "10.0.2.2:80".to_owned(),
            "192.168.1.1:80".to_owned(),
            "169.254.169.254:80".to_owned(),
            "[fe80::1]:443".to_owned(),
            "0.0.0.0:80".to_owned(),
        ] {
            let (line, _) = ask(
                &p,
                &format!("CONNECT {target} HTTP/1.1\r\n{}\r\n", auth(&p)),
            );
            assert_eq!(line, "HTTP/1.1 403 Forbidden", "{target}");
        }
        // An absolute-form request to a private address, too.
        let (line, _) = ask(
            &p,
            &format!("GET http://10.1.2.3/ HTTP/1.1\r\n{}\r\n", auth(&p)),
        );
        assert_eq!(line, "HTTP/1.1 403 Forbidden");
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "nothing reached the loopback server"
        );
        let denials = p.denials();
        assert_eq!(denials.len(), 8);
        assert_eq!(denials[0].host, "127.0.0.1");
        assert!(matches!(
            denials[0].refusal,
            Refusal::Destination(DestinationError::NonPublic(_))
        ));
        assert_eq!(p.counts().allowed, 0);
    }

    #[test]
    fn a_name_that_resolves_to_loopback_needs_the_users_allowance() {
        let p = proxy(&[]);
        let (line, _) = ask(
            &p,
            &format!("CONNECT localhost:9 HTTP/1.1\r\n{}\r\n", auth(&p)),
        );
        assert_eq!(line, "HTTP/1.1 403 Forbidden");
        // The allowance is per name: the address literal stays refused.
        let (port, rx) = upstream();
        p.set_local_hosts(vec!["localhost".into()]);
        let (line, _) = ask(
            &p,
            &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n{}\r\n", auth(&p)),
        );
        assert_eq!(line, "HTTP/1.1 403 Forbidden");
        let (line, mut s) = ask(
            &p,
            &format!("CONNECT localhost:{port} HTTP/1.1\r\n{}\r\n", auth(&p)),
        );
        assert_eq!(line, "HTTP/1.1 200 Connection Established");
        s.write_all(b"x").unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), "x");
    }

    #[test]
    fn malformed_requests_are_refused_without_connecting() {
        let p = proxy(&["localhost"]);
        let a = auth(&p);
        for (request, expected) in [
            (
                "GET /relative HTTP/1.1\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                "GET https://example.com/ HTTP/1.1\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                "GET ftp://example.com/ HTTP/1.1\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                format!("GET http://user:pw@example.com/ HTTP/1.1\r\n{a}\r\n"),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                "CONNECT example.com HTTP/1.1\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                "CONNECT example.com:http HTTP/1.1\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                "CONNECT example.com:0 HTTP/1.1\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                "CONNECT exa mple.com:443 HTTP/1.1\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                "CONNECT example.com:443 HTTP/2.0\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                "CONNECT example.com:443 HTTP/1.1\r\nX-A: a\u{1}b\r\n\r\n".to_owned(),
                "HTTP/1.1 400 Bad Request",
            ),
            (
                format!("CONNECT example.com:443 HTTP/1.1\r\n{a}{a}\r\n"),
                "HTTP/1.1 407 Proxy Authentication Required",
            ),
            (
                format!(
                    "CONNECT example.com:443 HTTP/1.1\r\nX: {}\r\n\r\n",
                    "a".repeat(MAX_HEAD_BYTES)
                ),
                "HTTP/1.1 431 Request Header Fields Too Large",
            ),
        ] {
            let (line, _) = ask(&p, &request);
            assert_eq!(line, expected, "{request:.80}");
        }
        assert_eq!(p.counts().allowed, 0);
    }

    #[test]
    fn stop_closes_open_tunnels_and_refuses_new_connections() {
        let p = proxy(&["localhost"]);
        let (port, _rx) = upstream();
        let (line, mut s) = ask(
            &p,
            &format!("CONNECT localhost:{port} HTTP/1.1\r\n{}\r\n", auth(&p)),
        );
        assert_eq!(line, "HTTP/1.1 200 Connection Established");
        p.stop();
        let mut buf = [0u8; 16];
        // The tunnel ends: EOF or a reset, never data.
        assert!(matches!(s.read(&mut buf), Ok(0) | Err(_)));
        let after = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, p.port())),
            Duration::from_secs(1),
        );
        if let Ok(mut late) = after {
            late.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let _ = late.write_all(b"CONNECT localhost:1 HTTP/1.1\r\n\r\n");
            assert!(
                matches!(late.read(&mut buf), Ok(0) | Err(_)),
                "a stopped proxy answers nothing"
            );
        }
    }

    #[test]
    fn listed_destinations_are_refused_before_resolving_or_connecting() {
        let (port, rx) = upstream();
        let p = Egress::start(
            EgressPolicy {
                local_hosts: vec!["localhost".into()],
                ..EgressPolicy::default()
            },
            Some(Arc::new(Listed(vec![
                "bad.invalid/",
                "localhost/known-bad",
            ]))),
        )
        .unwrap();
        // A host-level indicator covers the host and its subdomains, for
        // tunnels too; a path indicator, the plain-HTTP URL only. The
        // .invalid names never resolve, so a refusal for them can only come
        // from the screen.
        let listed = |e: &str| Refusal::KnownMalicious(e.into());
        for (request, refusal) in [
            (
                "CONNECT bad.invalid:443 HTTP/1.1".to_owned(),
                listed("bad.invalid/"),
            ),
            (
                "CONNECT cdn.bad.invalid:443 HTTP/1.1".to_owned(),
                listed("bad.invalid/"),
            ),
            (
                "GET http://ads.bad.invalid/x.js HTTP/1.1".to_owned(),
                listed("bad.invalid/"),
            ),
            (
                format!("GET http://localhost:{port}/known-bad HTTP/1.1"),
                listed("localhost/known-bad"),
            ),
            // Padded past what canonicalization takes (8 KiB) but inside the
            // proxy's head limit (16 KiB): it cannot be checked, so it is
            // refused, not screened by its host alone.
            (
                format!(
                    "GET http://localhost:{port}/known-bad?{} HTTP/1.1",
                    "a".repeat(urlcanon::MAX_URL_BYTES)
                ),
                Refusal::NotChecked(urlcanon::CanonError::TooLong),
            ),
        ] {
            let (line, _) = ask(&p, &format!("{request}\r\n{}\r\n", auth(&p)));
            assert_eq!(line, "HTTP/1.1 403 Forbidden", "{request}");
            let denial = p.denials().pop().unwrap();
            assert_eq!(denial.refusal, refusal, "{request}");
        }
        assert_eq!(listed("x").code(), "known-malicious");
        assert_eq!(
            Refusal::NotChecked(urlcanon::CanonError::TooLong).code(),
            "not-checked"
        );
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "nothing reached the server"
        );
        let seqs: Vec<u64> = p.denials().iter().map(|d| d.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
        // A path indicator says nothing about the rest of the host.
        let (line, _) = ask(
            &p,
            &format!(
                "GET http://localhost:{port}/fine HTTP/1.1\r\n{}\r\n",
                auth(&p)
            ),
        );
        assert_eq!(line, "HTTP/1.1 200 OK");
        assert_eq!(p.counts().allowed, 1);
    }

    #[test]
    fn the_connection_limit_is_enforced() {
        let p = Egress::start(
            EgressPolicy {
                max_connections: 1,
                local_hosts: vec!["localhost".into()],
                ..EgressPolicy::default()
            },
            None,
        )
        .unwrap();
        let (port, _rx) = upstream();
        let (line, _held) = ask(
            &p,
            &format!("CONNECT localhost:{port} HTTP/1.1\r\n{}\r\n", auth(&p)),
        );
        assert_eq!(line, "HTTP/1.1 200 Connection Established");
        let (line, _) = ask(
            &p,
            &format!("CONNECT localhost:{port} HTTP/1.1\r\n{}\r\n", auth(&p)),
        );
        assert_eq!(line, "HTTP/1.1 503 Service Unavailable");
    }

    #[test]
    fn tokens_and_realms_differ_per_proxy() {
        let (a, b) = (proxy(&[]), proxy(&[]));
        assert_eq!(a.token().len(), 64);
        assert_ne!(a.token(), b.token());
        assert_ne!(a.realm(), b.realm());
        assert_ne!(a.port(), b.port());
    }

    #[test]
    fn base64_matches_known_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("rift:x", "cmlmdDp4"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
    }

    #[test]
    fn parse_head_accepts_the_two_forms() {
        let r = parse_head(b"CONNECT Example.COM:443 HTTP/1.1\r\nHost: example.com:443").unwrap();
        assert_eq!(
            r.target,
            Target {
                host: "example.com".into(),
                port: 443
            }
        );
        assert_eq!(r.form, Form::Connect);
        assert_eq!(r.headers, vec![("host".into(), "example.com:443".into())]);
        let r = parse_head(b"CONNECT [2001:db8::1]:8443 HTTP/1.1").unwrap();
        assert_eq!(r.target.host, "2001:db8::1");
        let r = parse_head(b"POST http://example.com/a/b?c HTTP/1.0").unwrap();
        assert_eq!(
            r.form,
            Form::Absolute {
                origin_form: "/a/b?c".into()
            }
        );
        assert_eq!(r.target.port, 80);
    }
}
