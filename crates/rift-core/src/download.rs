//! Controller-owned downloads into session quarantine (docs/architecture.md
//! §8.5, §11.1, INV-13).
//!
//! The browser engine only reports that a download was requested. The core
//! fetches it again itself, so every byte that enters quarantine passed
//! through these rules:
//!
//! * Redirects are followed here, one hop at a time, and each hop is checked
//!   again (scheme, host, destination).
//! * DNS is resolved once per hop, inside the resolver, and the connection
//!   uses exactly the addresses that passed [`check_destination`]. There is no
//!   second lookup that a rebinding server could answer differently.
//! * Non-public addresses are refused unless the user allowed that host name
//!   for this session. The exception is per name, so a redirect or another
//!   site cannot use it.
//! * The byte limit applies to the stream (`Content-Length` is never trusted),
//!   and nothing is visible until the whole object is committed.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use percent_encoding::percent_decode_str;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};
use url::Url;

use crate::store::{ObjectStore, StoredObject};
use crate::transfer::{DestinationError, check_destination, display_name};
use crate::vault::VaultError;

const CHUNK: usize = 64 * 1024;
const MAX_CONTENT_TYPE_CHARS: usize = 100;

/// What the browser reported about a download it saw (§8.5).
#[derive(Debug, Clone, Copy)]
pub struct DownloadRequest<'a> {
    pub url: &'a str,
    /// The engine's cookie header for `url`. Sent only to that URL's origin,
    /// never to a host a redirect leads to.
    pub cookie: Option<&'a str>,
    pub user_agent: &'a str,
    pub referer: Option<&'a str>,
    /// The engine's Content-Disposition, used only if the response has none.
    pub engine_disposition: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadPolicy {
    /// Host names the user allowed, for this session, to resolve to local or
    /// private addresses (INV-13's explicit exception). Compared exactly,
    /// ASCII case-insensitively.
    pub local_hosts: Vec<String>,
    pub max_bytes: u64,
    pub max_redirects: usize,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub total_timeout: Duration,
}

impl Default for DownloadPolicy {
    fn default() -> Self {
        Self {
            local_hosts: Vec::new(),
            max_bytes: 100 * 1024 * 1024, // 100 MiB per object (§11.1)
            max_redirects: 10,
            connect_timeout: Duration::from_secs(20),
            response_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(15 * 60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    pub object: StoredObject,
    pub final_url: String,
    pub redirects: usize,
    /// Display metadata only: normalized by [`display_name`].
    pub display_name: String,
    /// As the server labelled it; not trusted for anything but display.
    pub content_type: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("only http and https downloads can be captured, not {0}:")]
    Scheme(String),
    #[error("the download address is not valid")]
    InvalidUrl,
    #[error("{host} resolves to {source}")]
    Destination {
        host: String,
        #[source]
        source: DestinationError,
    },
    #[error("more than {0} redirects")]
    TooManyRedirects(usize),
    #[error("a redirect had no valid destination")]
    BadRedirect,
    /// For example 405 when a POST-generated download is fetched again with
    /// GET (PoC A3): such downloads cannot be captured safely.
    #[error("the server answered HTTP {0} when Rift fetched the file")]
    Status(u16),
    #[error("the file is larger than the {0}-byte limit")]
    TooLarge(u64),
    #[error("the download was cancelled")]
    Cancelled,
    #[error("network error: {0}")]
    Network(String),
    #[error("storage error: {0}")]
    Storage(#[from] VaultError),
}

/// Fetches `request` into `store`, encrypted to `recipient`. On any error
/// nothing is committed. `cancel` is checked between chunks; a session reset
/// sets it.
pub fn download(
    request: &DownloadRequest<'_>,
    policy: &DownloadPolicy,
    store: &ObjectStore,
    recipient: &age::x25519::Recipient,
    cancel: &AtomicBool,
) -> Result<Downloaded, DownloadError> {
    let agent = agent(policy);
    let first = hop_url(request.url)?;
    let cookie_origin = first.origin();
    let mut url = first;
    for redirects in 0..=policy.max_redirects {
        if cancel.load(Ordering::SeqCst) {
            return Err(DownloadError::Cancelled);
        }
        let mut call = agent
            .get(url.as_str())
            .header("User-Agent", request.user_agent);
        if let Some(cookie) = request.cookie
            && url.origin() == cookie_origin
        {
            call = call.header("Cookie", cookie);
        }
        if let Some(referer) = request.referer {
            call = call.header("Referer", referer);
        }
        let response = call.call().map_err(network_error)?;
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or(DownloadError::BadRedirect)?;
            let next = url.join(location).map_err(|_| DownloadError::BadRedirect)?;
            url = hop_url(next.as_str())?;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(DownloadError::Status(status));
        }

        // Servers put raw UTF-8 (not only visible ASCII) in filenames, so
        // header values are decoded lossily rather than dropped.
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        };
        let supplied_name = header("content-disposition")
            .as_deref()
            .or(request.engine_disposition)
            .and_then(filename_from_disposition)
            .or_else(|| filename_from_url(&url))
            .unwrap_or_default();
        let content_type = header("content-type")
            .map(|t| t.chars().take(MAX_CONTENT_TYPE_CHARS).collect::<String>());

        let mut pending = store.begin(recipient, policy.max_bytes)?;
        let mut body = response.into_body().into_reader();
        let mut buffer = vec![0u8; CHUNK];
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(DownloadError::Cancelled); // dropping `pending` discards it
            }
            let n = body.read(&mut buffer).map_err(|e| network_error_io(&e))?;
            let Some(chunk) = buffer.get(..n) else {
                return Err(DownloadError::Network("reader overran its buffer".into()));
            };
            if chunk.is_empty() {
                break;
            }
            pending.write_all(chunk).map_err(|e| {
                if e.kind() == io::ErrorKind::FileTooLarge {
                    DownloadError::TooLarge(policy.max_bytes)
                } else {
                    DownloadError::Storage(VaultError::Io(e))
                }
            })?;
        }
        let object = pending.commit()?;
        return Ok(Downloaded {
            object,
            final_url: url.to_string(),
            redirects,
            display_name: display_name(&supplied_name),
            content_type,
        });
    }
    Err(DownloadError::TooManyRedirects(policy.max_redirects))
}

/// One hop's URL: http or https with a host; the fragment is never sent.
fn hop_url(raw: &str) -> Result<Url, DownloadError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| DownloadError::InvalidUrl)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(DownloadError::Scheme(url.scheme().to_owned()));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(DownloadError::InvalidUrl);
    }
    url.set_fragment(None);
    Ok(url)
}

fn agent(policy: &DownloadPolicy) -> ureq::Agent {
    let config = Config::builder()
        .max_redirects(0) // every hop is checked by `download`
        .http_status_as_error(false)
        .proxy(None) // no environment proxy can redirect the core's traffic
        .timeout_connect(Some(policy.connect_timeout))
        .timeout_recv_response(Some(policy.response_timeout))
        .timeout_global(Some(policy.total_timeout))
        .build();
    let resolver = CheckedResolver {
        inner: DefaultResolver::default(),
        local_hosts: policy
            .local_hosts
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect(),
    };
    ureq::Agent::with_parts(config, DefaultConnector::default(), resolver)
}

/// Resolves once and refuses the hop if any address is not public (unless
/// the user allowed this host name). ureq connects only to what it returns.
struct CheckedResolver {
    inner: DefaultResolver,
    local_hosts: Vec<String>,
}

impl fmt::Debug for CheckedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedResolver")
            .field("local_hosts", &self.local_hosts)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{host} resolves to {source}")]
struct Refused {
    host: String,
    source: DestinationError,
}

impl Resolver for CheckedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let addrs = self.inner.resolve(uri, config, timeout)?;
        let host = uri
            .host()
            .unwrap_or_default()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if self.local_hosts.contains(&host) {
            return Ok(addrs);
        }
        for addr in addrs.iter() {
            if let Err(source) = check_destination(addr.ip()) {
                return Err(ureq::Error::Other(Box::new(Refused { host, source })));
            }
        }
        Ok(addrs)
    }
}

fn network_error(error: ureq::Error) -> DownloadError {
    match error {
        ureq::Error::Other(inner) => match inner.downcast::<Refused>() {
            Ok(refused) => DownloadError::Destination {
                host: refused.host,
                source: refused.source,
            },
            Err(other) => DownloadError::Network(other.to_string()),
        },
        ureq::Error::Io(e) => network_error_io(&e),
        other => DownloadError::Network(other.to_string()),
    }
}

fn network_error_io(error: &io::Error) -> DownloadError {
    DownloadError::Network(error.to_string())
}

/// The filename from a Content-Disposition value: RFC 6266 `filename*`
/// (UTF-8, percent-encoded) wins over `filename`. Display metadata only.
pub fn filename_from_disposition(value: &str) -> Option<String> {
    let mut plain = None;
    for part in value.split(';').map(str::trim) {
        let Some((key, raw)) = part.split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "filename*" => {
                let encoded = raw.trim().trim_matches('"');
                let (charset, rest) = encoded.split_once('\'')?;
                let (_language, text) = rest.split_once('\'')?;
                if charset.eq_ignore_ascii_case("utf-8") {
                    return percent_decode_str(text)
                        .decode_utf8()
                        .ok()
                        .map(|s| s.into_owned());
                }
            }
            "filename" => plain = Some(raw.trim().trim_matches('"').to_owned()),
            _ => {}
        }
    }
    plain
}

fn filename_from_url(url: &Url) -> Option<String> {
    let last = url.path_segments()?.next_back()?;
    let decoded = percent_decode_str(last).decode_utf8_lossy().into_owned();
    (!decoded.is_empty()).then_some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultKey;
    use sha2::Digest as _;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// (path, Cookie header) of each request the server received.
    type RequestLog = Arc<Mutex<Vec<(String, Option<String>)>>>;

    /// A tiny HTTP/1.1 server on 127.0.0.1. `respond(path, headers)` returns
    /// the raw response bytes. Records each request's path and Cookie header.
    struct Server {
        port: u16,
        log: RequestLog,
    }

    impl Server {
        fn start(respond: fn(&str, u16) -> Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let log = RequestLog::default();
            let seen = log.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let path = request_line.split(' ').nth(1).unwrap_or("/").to_owned();
                    let mut cookie = None;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("cookie")
                        {
                            cookie = Some(value.trim().to_owned());
                        }
                    }
                    seen.lock().unwrap().push((path.clone(), cookie));
                    let _ = stream.write_all(&respond(&path, port));
                }
            });
            Self { port, log }
        }

        fn url(&self, host: &str, path: &str) -> String {
            format!("http://{host}:{}{path}", self.port)
        }
    }

    fn ok(body: &[u8], extra: &str) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn redirect(location: &str) -> Vec<u8> {
        format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .into_bytes()
    }

    fn routes(path: &str, port: u16) -> Vec<u8> {
        match path {
            "/file" => ok(b"hello quarantine", "Content-Type: text/plain\r\n"),
            "/hostile-name" => ok(
                b"%PDF-1.4",
                "Content-Disposition: attachment; filename=\"../../evil\u{202e}gpj.pdf\"\r\n",
            ),
            "/to-file" => redirect("/file"),
            "/to-loopback-literal" => redirect(&format!("http://127.0.0.1:{port}/file")),
            "/to-metadata" => redirect("http://169.254.169.254/latest/meta-data/"),
            "/to-scheme" => redirect("file:///etc/passwd"),
            "/loop" => redirect("/loop"),
            "/post-only" => {
                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec()
            }
            // Claims 10 bytes, sends far more: the limit must hold anyway.
            "/lying-length" => {
                let mut out =
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 10\r\n\r\n".to_vec();
                out.extend(std::iter::repeat_n(b'x', 10));
                out
            }
            "/no-length" => {
                let mut out = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
                out.extend(std::iter::repeat_n(b'y', 5000));
                out
            }
            _ => {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            }
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        store: ObjectStore,
        key: VaultKey,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::open(dir.path().join("q")).unwrap();
        Fixture {
            _dir: dir,
            store,
            key: VaultKey::generate(),
        }
    }

    fn policy(local: &[&str]) -> DownloadPolicy {
        DownloadPolicy {
            local_hosts: local.iter().map(|s| (*s).to_owned()).collect(),
            ..DownloadPolicy::default()
        }
    }

    fn get(
        f: &Fixture,
        url: &str,
        policy: &DownloadPolicy,
        cookie: Option<&str>,
    ) -> Result<Downloaded, DownloadError> {
        let request = DownloadRequest {
            url,
            cookie,
            user_agent: "rift-test",
            referer: None,
            engine_disposition: None,
        };
        download(
            &request,
            policy,
            &f.store,
            &f.key.recipient(),
            &AtomicBool::new(false),
        )
    }

    fn plaintext(f: &Fixture, d: &Downloaded) -> Vec<u8> {
        let mut out = Vec::new();
        f.store
            .read(d.object.id, &f.key, &d.object.sealed, &mut out)
            .unwrap();
        out
    }

    #[test]
    fn downloads_are_stored_encrypted_and_hashed() {
        let server = Server::start(routes);
        let f = fixture();
        let d = get(
            &f,
            &server.url("localhost", "/to-file"),
            &policy(&["localhost"]),
            None,
        )
        .unwrap();
        assert_eq!(plaintext(&f, &d), b"hello quarantine");
        assert_eq!(d.redirects, 1);
        assert_eq!(d.display_name, "file");
        assert_eq!(d.content_type.as_deref(), Some("text/plain"));
        assert_eq!(
            d.object.sealed.sha256,
            <[u8; 32]>::from(sha2::Sha256::digest(b"hello quarantine"))
        );
    }

    #[test]
    fn s9_local_destinations_need_an_explicit_per_host_allowance() {
        let server = Server::start(routes);
        let f = fixture();
        // Not allowed at all.
        assert!(matches!(
            get(&f, &server.url("localhost", "/file"), &policy(&[]), None),
            Err(DownloadError::Destination { .. })
        ));
        // Allowed for "localhost" only: a redirect to another name for the
        // same machine, or to cloud metadata, is still refused.
        let allowed = policy(&["localhost"]);
        for path in ["/to-loopback-literal", "/to-metadata"] {
            assert!(
                matches!(
                    get(&f, &server.url("localhost", path), &allowed, None),
                    Err(DownloadError::Destination { .. })
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn s8_byte_limit_holds_whatever_the_headers_say() {
        let server = Server::start(routes);
        let f = fixture();
        let small = DownloadPolicy {
            max_bytes: 1000,
            ..policy(&["localhost"])
        };
        assert!(matches!(
            get(&f, &server.url("localhost", "/no-length"), &small, None),
            Err(DownloadError::TooLarge(1000))
        ));
        // A body longer than its Content-Length is cut at the declared length
        // by the HTTP layer; what is stored is never more than was declared.
        let d = get(&f, &server.url("localhost", "/lying-length"), &small, None).unwrap();
        assert_eq!(d.object.sealed.size, 10);
        assert_eq!(
            std::fs::read_dir(f._dir.path().join("q/pending"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn s10_hostile_filenames_are_display_only() {
        let server = Server::start(routes);
        let f = fixture();
        let d = get(
            &f,
            &server.url("localhost", "/hostile-name"),
            &policy(&["localhost"]),
            None,
        )
        .unwrap();
        assert_eq!(d.display_name, "evilgpj.pdf");
        // Storage uses the random object id, never the supplied name.
        assert!(f.store.contains(d.object.id));
    }

    #[test]
    fn hops_that_leave_the_web_or_loop_are_refused() {
        let server = Server::start(routes);
        let f = fixture();
        let allowed = policy(&["localhost"]);
        assert!(matches!(
            get(&f, &server.url("localhost", "/to-scheme"), &allowed, None),
            Err(DownloadError::Scheme(s)) if s == "file"
        ));
        assert!(matches!(
            get(&f, &server.url("localhost", "/loop"), &allowed, None),
            Err(DownloadError::TooManyRedirects(10))
        ));
        assert!(matches!(
            get(&f, &server.url("localhost", "/post-only"), &allowed, None),
            Err(DownloadError::Status(405))
        ));
        assert!(matches!(
            get(&f, "data:text/plain,hi", &allowed, None),
            Err(DownloadError::Scheme(s)) if s == "data"
        ));
    }

    #[test]
    fn cookies_go_only_to_their_own_origin() {
        let server = Server::start(routes);
        let f = fixture();
        let both = policy(&["localhost", "127.0.0.1"]);
        get(
            &f,
            &server.url("localhost", "/to-loopback-literal"),
            &both,
            Some("session=secret"),
        )
        .unwrap();
        let log = server.log.lock().unwrap().clone();
        assert_eq!(
            log,
            vec![
                (
                    "/to-loopback-literal".to_owned(),
                    Some("session=secret".to_owned())
                ),
                ("/file".to_owned(), None),
            ]
        );
    }

    #[test]
    fn cancelled_downloads_leave_nothing() {
        let server = Server::start(routes);
        let f = fixture();
        let request = DownloadRequest {
            url: &server.url("localhost", "/file"),
            cookie: None,
            user_agent: "rift-test",
            referer: None,
            engine_disposition: None,
        };
        let result = download(
            &request,
            &policy(&["localhost"]),
            &f.store,
            &f.key.recipient(),
            &AtomicBool::new(true),
        );
        assert!(matches!(result, Err(DownloadError::Cancelled)));
        assert_eq!(
            std::fs::read_dir(f._dir.path().join("q/objects"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn disposition_parsing_prefers_the_utf8_form() {
        assert_eq!(
            filename_from_disposition(
                "attachment; filename=\"a.txt\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf"
            )
            .as_deref(),
            Some("résumé.pdf")
        );
        assert_eq!(
            filename_from_disposition("attachment; filename=plain.bin").as_deref(),
            Some("plain.bin")
        );
        assert_eq!(filename_from_disposition("inline"), None);
    }
}

/// Needs the internet: `cargo test -p rift-core -- --ignored https`.
#[cfg(test)]
mod network_tests {
    use super::*;

    #[test]
    #[ignore = "contacts example.com"]
    fn https_verifies_with_the_bundled_roots() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::open(dir.path()).unwrap();
        let key = crate::vault::VaultKey::generate();
        let request = DownloadRequest {
            url: "https://example.com/",
            cookie: None,
            user_agent: "rift-test",
            referer: None,
            engine_disposition: None,
        };
        let done = download(
            &request,
            &DownloadPolicy::default(),
            &store,
            &key.recipient(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(done.object.sealed.size > 0);
        // A certificate for another name must fail.
        let wrong = DownloadRequest {
            url: "https://wrong.host.badssl.com/",
            ..request
        };
        assert!(matches!(
            download(
                &wrong,
                &DownloadPolicy::default(),
                &store,
                &key.recipient(),
                &AtomicBool::new(false)
            ),
            Err(DownloadError::Network(_))
        ));
    }
}
