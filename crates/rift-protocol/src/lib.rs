//! Controller ⇄ worker contract (docs/architecture.md §7.2, INV-3), and in
//! [`session`] the controller ⇄ Linux browser host contract (§9.2).
//!
//! Workers parse untrusted content and must be assumed compromised, so every
//! response is treated as hostile input: frames are size-checked before any
//! allocation, decoded with postcard, matched to the outstanding request
//! (version, job, session generation) and bounded field by field against what
//! that request allowed. Only a [`Validated`] response may be acted upon.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

pub mod session;

pub const PROTOCOL_VERSION: u16 = 1;
/// Largest control frame in either direction. Pixels never travel in frames.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_RULE_NAME_BYTES: usize = 128;
pub const MAX_PDF_PAGES: u32 = 100_000;
pub const MAX_RULES: u32 = 1_000_000;
/// Output ceiling for any rendered bitmap (16 MiB = 4 Mpx RGBA).
pub const MAX_BITMAP_BYTES: u64 = 16 * 1024 * 1024;
/// The worker's scan engine, part of every verdict's cache key (§12.1).
/// rift-worker's tests check it against the locked yara-x version.
pub const SCAN_ENGINE: &str = "yara-x 1.21.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u16,
    pub job_id: u64,
    pub generation: u64,
    pub body: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Ask a freshly locked-down worker to report its confinement.
    Hello,
    /// Compile the rule source in the passed descriptor; `digest` is its
    /// SHA-256, which later `Scan` requests must reference.
    LoadRules { digest: [u8; 32] },
    /// Scan the passed descriptor with the rules identified by `rules_digest`.
    Scan {
        rules_digest: [u8; 32],
        max_matches: u16,
        deadline_ms: u32,
    },
    /// Report the page count of the passed PDF.
    PdfInfo { deadline_ms: u32 },
    /// Render one page into the passed output region, fitting within the box.
    RenderPdfPage {
        page: u32,
        max_width: u32,
        max_height: u32,
        deadline_ms: u32,
    },
    /// Decode the passed image into the output region, fitting within the box.
    DecodeImage {
        max_width: u32,
        max_height: u32,
        deadline_ms: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Ready(Confinement),
    RulesLoaded {
        rule_count: u32,
    },
    /// `truncated`: more rules matched than the request's `max_matches`.
    ScanResult {
        matches: Vec<RuleMatch>,
        truncated: bool,
    },
    PdfInfo {
        pages: u32,
    },
    Bitmap(BitmapHeader),
    Error(WorkerError),
}

/// The worker's own account of its lockdown. Advisory only: the controller
/// verifies confinement independently (e.g. /proc status) before sending input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confinement {
    pub seccomp: bool,
    pub no_new_privs: bool,
    pub landlock: LandlockStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LandlockStatus {
    FullyEnforced,
    PartiallyEnforced,
    /// Platform without Landlock where another mechanism confines the worker
    /// (Android: isolatedProcess / isolated_app).
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitmapHeader {
    pub width: u32,
    pub height: u32,
    /// Bytes per row; must equal `width * 4` for RGBA8.
    pub stride: u32,
    pub format: PixelFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PixelFormat {
    /// 8 bits per channel in R, G, B, A byte order, straight (not premultiplied) alpha.
    Rgba8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerError {
    Unsupported,
    Malformed,
    TooLarge,
    Timeout,
    Encrypted,
    EngineFailure,
    /// `Scan` named rules that are not the ones loaded in this worker.
    RulesNotLoaded,
}

/// Why a frame or response was rejected. Any of these ends the job as failed
/// ("not fully scanned" / "preview unavailable") and retires the worker.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("frame of {0} bytes exceeds the limit")]
    FrameTooLarge(usize),
    #[error("frame is empty")]
    EmptyFrame,
    #[error("frame is not a valid message: {0}")]
    Malformed(String),
    #[error("protocol version {0} is not supported")]
    VersionMismatch(u16),
    #[error("response belongs to job {found}, expected {expected}")]
    WrongJob { expected: u64, found: u64 },
    #[error("response belongs to session generation {found}, expected {expected}")]
    StaleGeneration { expected: u64, found: u64 },
    #[error("response type does not answer the request")]
    UnexpectedResponse,
    #[error("response field out of bounds: {0}")]
    OutOfBounds(&'static str),
}

/// A response that passed every check against its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated(Response);

impl Validated {
    pub fn into_inner(self) -> Response {
        self.0
    }

    pub fn get(&self) -> &Response {
        &self.0
    }
}

/// Serializes a message into a length-prefixed frame.
pub fn encode<T: Serialize>(message: &Envelope<T>) -> Result<Vec<u8>, ProtocolError> {
    let body =
        postcard::to_allocvec(message).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| ProtocolError::FrameTooLarge(body.len()))?;
    let mut frame = Vec::with_capacity(body.len().saturating_add(4));
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn write_frame<T: Serialize>(out: &mut impl Write, message: &Envelope<T>) -> io::Result<()> {
    let frame = encode(message).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    out.write_all(&frame)
}

/// Reads one frame body. The declared length is checked against
/// [`MAX_FRAME_BYTES`] before any buffer is allocated.
pub fn read_frame(input: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    input.read_exact(&mut prefix)?;
    let len = usize::try_from(u32::from_le_bytes(prefix)).unwrap_or(usize::MAX);
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            ProtocolError::FrameTooLarge(len),
        ));
    }
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    Ok(body)
}

/// Decodes a request on the worker side (only version is checked here).
pub fn decode_request(body: &[u8]) -> Result<Envelope<Request>, ProtocolError> {
    let envelope: Envelope<Request> = decode(body)?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch(envelope.version));
    }
    Ok(envelope)
}

/// Decodes and validates a worker response against the request it answers.
pub fn decode_response(
    body: &[u8],
    request: &Envelope<Request>,
) -> Result<Validated, ProtocolError> {
    let envelope: Envelope<Response> = decode(body)?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch(envelope.version));
    }
    if envelope.job_id != request.job_id {
        return Err(ProtocolError::WrongJob {
            expected: request.job_id,
            found: envelope.job_id,
        });
    }
    if envelope.generation != request.generation {
        return Err(ProtocolError::StaleGeneration {
            expected: request.generation,
            found: envelope.generation,
        });
    }
    validate(&envelope.body, &request.body)?;
    Ok(Validated(envelope.body))
}

fn decode<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, ProtocolError> {
    if body.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if body.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(body.len()));
    }
    let (value, rest) =
        postcard::take_from_bytes(body).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    if !rest.is_empty() {
        return Err(ProtocolError::Malformed(
            "trailing bytes after message".into(),
        ));
    }
    Ok(value)
}

fn validate(response: &Response, request: &Request) -> Result<(), ProtocolError> {
    match (request, response) {
        // An error report is a valid answer to any request.
        (_, Response::Error(_)) => Ok(()),
        (Request::Hello, Response::Ready(_)) => Ok(()),
        (Request::LoadRules { .. }, Response::RulesLoaded { rule_count }) => {
            if *rule_count > MAX_RULES {
                return Err(ProtocolError::OutOfBounds("rule count"));
            }
            Ok(())
        }
        (Request::Scan { max_matches, .. }, Response::ScanResult { matches, .. }) => {
            if matches.len() > usize::from(*max_matches) {
                return Err(ProtocolError::OutOfBounds("match count"));
            }
            if !matches.iter().all(|m| is_rule_identifier(&m.rule)) {
                return Err(ProtocolError::OutOfBounds("rule identifier"));
            }
            Ok(())
        }
        (Request::PdfInfo { .. }, Response::PdfInfo { pages }) => {
            if *pages == 0 || *pages > MAX_PDF_PAGES {
                return Err(ProtocolError::OutOfBounds("page count"));
            }
            Ok(())
        }
        (
            Request::RenderPdfPage {
                max_width,
                max_height,
                ..
            }
            | Request::DecodeImage {
                max_width,
                max_height,
                ..
            },
            Response::Bitmap(header),
        ) => validate_bitmap(header, *max_width, *max_height),
        _ => Err(ProtocolError::UnexpectedResponse),
    }
}

fn validate_bitmap(
    header: &BitmapHeader,
    max_width: u32,
    max_height: u32,
) -> Result<(), ProtocolError> {
    let BitmapHeader {
        width,
        height,
        stride,
        format: PixelFormat::Rgba8,
    } = *header;
    if width == 0 || height == 0 || width > max_width || height > max_height {
        return Err(ProtocolError::OutOfBounds("bitmap dimensions"));
    }
    let row = u64::from(width)
        .checked_mul(4)
        .ok_or(ProtocolError::OutOfBounds("bitmap stride"))?;
    if u64::from(stride) != row {
        return Err(ProtocolError::OutOfBounds("bitmap stride"));
    }
    let total = row
        .checked_mul(u64::from(height))
        .ok_or(ProtocolError::OutOfBounds("bitmap size"))?;
    if total > MAX_BITMAP_BYTES {
        return Err(ProtocolError::OutOfBounds("bitmap size"));
    }
    Ok(())
}

/// YARA identifiers: ASCII letter or underscore, then letters, digits, underscores.
fn is_rule_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    valid_first
        && name.len() <= MAX_RULE_NAME_BYTES
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: Request) -> Envelope<Request> {
        Envelope {
            version: PROTOCOL_VERSION,
            job_id: 42,
            generation: 7,
            body,
        }
    }

    fn reply(body: Response) -> Envelope<Response> {
        Envelope {
            version: PROTOCOL_VERSION,
            job_id: 42,
            generation: 7,
            body,
        }
    }

    fn frame_body(message: &Envelope<Response>) -> Vec<u8> {
        encode(message).unwrap()[4..].to_vec()
    }

    fn render(max: u32) -> Envelope<Request> {
        request(Request::RenderPdfPage {
            page: 0,
            max_width: max,
            max_height: max,
            deadline_ms: 5000,
        })
    }

    fn bitmap(width: u32, height: u32, stride: u32) -> Envelope<Response> {
        reply(Response::Bitmap(BitmapHeader {
            width,
            height,
            stride,
            format: PixelFormat::Rgba8,
        }))
    }

    #[test]
    fn valid_bitmap_is_accepted() {
        let validated = decode_response(&frame_body(&bitmap(1000, 800, 4000)), &render(1024));
        assert!(validated.is_ok(), "{validated:?}");
    }

    #[test]
    fn bitmap_bounds_are_enforced() {
        let req = render(1024);
        for (w, h, stride, why) in [
            (0, 10, 0, "zero width"),
            (1025, 10, 4100, "wider than requested"),
            (10, 1025, 40, "taller than requested"),
            (100, 100, 404, "stride padding"),
            (100, 100, 396, "stride too small"),
        ] {
            let result = decode_response(&frame_body(&bitmap(w, h, stride)), &req);
            assert!(
                matches!(result, Err(ProtocolError::OutOfBounds(_))),
                "{why}: {result:?}"
            );
        }
        // Huge request box: the absolute 16 MiB ceiling still applies.
        let huge = render(u32::MAX);
        let result = decode_response(&frame_body(&bitmap(4096, 4097, 16384)), &huge);
        assert!(matches!(
            result,
            Err(ProtocolError::OutOfBounds("bitmap size"))
        ));
        let result = decode_response(&frame_body(&bitmap(u32::MAX, u32::MAX, u32::MAX)), &huge);
        assert!(matches!(result, Err(ProtocolError::OutOfBounds(_))));
    }

    #[test]
    fn responses_must_match_job_generation_version_and_type() {
        let req = render(1024);
        let mut wrong_job = bitmap(10, 10, 40);
        wrong_job.job_id = 43;
        assert!(matches!(
            decode_response(&frame_body(&wrong_job), &req),
            Err(ProtocolError::WrongJob { .. })
        ));
        let mut stale = bitmap(10, 10, 40);
        stale.generation = 6;
        assert!(matches!(
            decode_response(&frame_body(&stale), &req),
            Err(ProtocolError::StaleGeneration { .. })
        ));
        let mut future = bitmap(10, 10, 40);
        future.version = 2;
        assert!(matches!(
            decode_response(&frame_body(&future), &req),
            Err(ProtocolError::VersionMismatch(2))
        ));
        let pages = reply(Response::PdfInfo { pages: 3 });
        assert!(matches!(
            decode_response(&frame_body(&pages), &req),
            Err(ProtocolError::UnexpectedResponse)
        ));
    }

    #[test]
    fn scan_results_are_bounded() {
        let req = request(Request::Scan {
            rules_digest: [0; 32],
            max_matches: 2,
            deadline_ms: 1000,
        });
        let matches = |names: &[&str]| {
            reply(Response::ScanResult {
                matches: names
                    .iter()
                    .map(|n| RuleMatch { rule: (*n).into() })
                    .collect(),
                truncated: false,
            })
        };
        assert!(decode_response(&frame_body(&matches(&["rift_demo", "_x2"])), &req).is_ok());
        assert!(decode_response(&frame_body(&matches(&["a", "b", "c"])), &req).is_err());
        for bad in [
            "",
            "9starts_with_digit",
            "has space",
            "dash-ed",
            "\u{202e}rtl",
            &"a".repeat(129),
        ] {
            assert!(
                decode_response(&frame_body(&matches(&[bad])), &req).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn rule_counts_are_bounded() {
        let req = request(Request::LoadRules { digest: [1; 32] });
        let ok = reply(Response::RulesLoaded { rule_count: 12 });
        assert!(decode_response(&frame_body(&ok), &req).is_ok());
        let huge = reply(Response::RulesLoaded {
            rule_count: MAX_RULES + 1,
        });
        assert!(decode_response(&frame_body(&huge), &req).is_err());
    }

    #[test]
    fn error_reports_answer_any_request() {
        let req = request(Request::PdfInfo { deadline_ms: 1000 });
        let error = reply(Response::Error(WorkerError::Encrypted));
        assert!(decode_response(&frame_body(&error), &req).is_ok());
    }

    #[test]
    fn page_counts_are_bounded() {
        let req = request(Request::PdfInfo { deadline_ms: 1000 });
        assert!(
            decode_response(&frame_body(&reply(Response::PdfInfo { pages: 0 })), &req).is_err()
        );
        let too_many = reply(Response::PdfInfo {
            pages: MAX_PDF_PAGES + 1,
        });
        assert!(decode_response(&frame_body(&too_many), &req).is_err());
    }

    #[test]
    fn trailing_bytes_and_empty_frames_are_rejected() {
        let req = request(Request::Hello);
        let ready = reply(Response::Ready(Confinement {
            seccomp: true,
            no_new_privs: true,
            landlock: LandlockStatus::FullyEnforced,
        }));
        let mut body = frame_body(&ready);
        assert!(decode_response(&body, &req).is_ok());
        body.push(0);
        assert!(matches!(
            decode_response(&body, &req),
            Err(ProtocolError::Malformed(_))
        ));
        assert!(matches!(
            decode_response(&[], &req),
            Err(ProtocolError::EmptyFrame)
        ));
    }

    #[test]
    fn oversized_declared_frame_is_refused_before_allocation() {
        let mut input = io::Cursor::new(u32::MAX.to_le_bytes().to_vec());
        let error = read_frame(&mut input).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let mut zero = io::Cursor::new(0u32.to_le_bytes().to_vec());
        assert!(read_frame(&mut zero).is_err());
    }

    #[test]
    fn frames_round_trip_through_a_stream() {
        let req = request(Request::DecodeImage {
            max_width: 64,
            max_height: 64,
            deadline_ms: 100,
        });
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &req).unwrap();
        let body = read_frame(&mut io::Cursor::new(buffer)).unwrap();
        assert_eq!(decode_request(&body).unwrap(), req);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(20_000))]

            /// Arbitrary worker output never panics and never validates by accident
            /// against a request it does not answer.
            #[test]
            fn arbitrary_bytes_never_panic(body in proptest::collection::vec(any::<u8>(), 0..512)) {
                for req in [request(Request::Hello), render(256), request(Request::PdfInfo { deadline_ms: 1 })] {
                    if let Ok(valid) = decode_response(&body, &req) {
                        // Anything accepted must satisfy the bounds independently.
                        if let Response::Bitmap(h) = valid.get() {
                            prop_assert!(h.width <= 256 && h.height <= 256 && Some(h.stride) == h.width.checked_mul(4));
                        }
                    }
                }
                let _ = decode_request(&body);
            }
        }
    }
}
