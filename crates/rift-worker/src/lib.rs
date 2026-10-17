//! Simulation-Rift worker job logic (docs/architecture.md §7.3).
//!
//! The same code runs inside the Android isolated service and the confined
//! Linux worker process. It assumes nothing about its input: every read is
//! bounded, decoders run with explicit limits, and failures become typed
//! [`WorkerError`]s — never a "clean" result. The platform shim is
//! responsible for confinement and for moving pixels out of the process.

use std::io::Read;

use rift_protocol::{
    BitmapHeader, Confinement, Envelope, PROTOCOL_VERSION, PixelFormat, Request, Response,
    RuleMatch, WorkerError,
};
use sha2::{Digest, Sha256};

/// Largest rule source accepted (a curated consumer pack is far smaller).
pub const MAX_RULES_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
/// Largest file scanned (matches the default managed-download limit).
pub const MAX_SCAN_BYTES: u64 = 100 * 1024 * 1024;
/// Largest encoded image accepted for preview.
pub const MAX_IMAGE_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Decoder limits: a hostile header cannot make the decoder allocate more.
pub const MAX_IMAGE_DIMENSION: u32 = 16_384;
pub const MAX_IMAGE_DECODE_ALLOC: u64 = 256 * 1024 * 1024;

/// A job's answer plus, for bitmaps, the pixels the shim must deliver out of
/// band (sealed memfd on Linux, SharedMemory on Android).
#[derive(Debug)]
pub struct Outcome {
    pub response: Envelope<Response>,
    pub pixels: Option<Vec<u8>>,
}

/// One worker's state. Rules persist across jobs of the same worker; the
/// worker itself is retired after a document closes or after any error.
#[derive(Debug)]
pub struct Worker {
    confinement: Confinement,
    rules: Option<LoadedRules>,
}

#[derive(Debug)]
struct LoadedRules {
    digest: [u8; 32],
    rules: yara_x::Rules,
}

impl Worker {
    /// `confinement` is what the platform shim established before any input.
    pub fn new(confinement: Confinement) -> Self {
        Self {
            confinement,
            rules: None,
        }
    }

    pub fn handle(&mut self, request: &Envelope<Request>, input: Option<&mut dyn Read>) -> Outcome {
        let (body, pixels) = match self.run(&request.body, input) {
            Ok(done) => done,
            Err(error) => (Response::Error(error), None),
        };
        let response = Envelope {
            version: PROTOCOL_VERSION,
            job_id: request.job_id,
            generation: request.generation,
            body,
        };
        Outcome { response, pixels }
    }

    fn run(
        &mut self,
        request: &Request,
        input: Option<&mut dyn Read>,
    ) -> Result<(Response, Option<Vec<u8>>), WorkerError> {
        match request {
            Request::Hello => Ok((Response::Ready(self.confinement), None)),
            Request::LoadRules { digest } => {
                let source = read_bounded(input, MAX_RULES_SOURCE_BYTES)?;
                if Sha256::digest(&source).as_slice() != digest {
                    return Err(WorkerError::Malformed);
                }
                let text = std::str::from_utf8(&source).map_err(|_| WorkerError::Malformed)?;
                let rules = yara_x::compile(text).map_err(|_| WorkerError::Malformed)?;
                let rule_count =
                    u32::try_from(rules.iter().count()).map_err(|_| WorkerError::TooLarge)?;
                self.rules = Some(LoadedRules {
                    digest: *digest,
                    rules,
                });
                Ok((Response::RulesLoaded { rule_count }, None))
            }
            Request::Scan {
                rules_digest,
                max_matches,
                deadline_ms,
            } => {
                let loaded = self
                    .rules
                    .as_ref()
                    .filter(|r| &r.digest == rules_digest)
                    .ok_or(WorkerError::RulesNotLoaded)?;
                let data = read_bounded(input, MAX_SCAN_BYTES)?;
                let mut scanner = yara_x::Scanner::new(&loaded.rules);
                scanner.set_timeout(std::time::Duration::from_millis(u64::from(*deadline_ms)));
                let results = scanner.scan(&data).map_err(|e| match e {
                    yara_x::ScanError::Timeout => WorkerError::Timeout,
                    _ => WorkerError::EngineFailure,
                })?;
                let limit = usize::from(*max_matches);
                let mut matches: Vec<RuleMatch> = results
                    .matching_rules()
                    .map(|r| RuleMatch {
                        rule: r.identifier().to_owned(),
                    })
                    .collect();
                let truncated = matches.len() > limit;
                matches.truncate(limit);
                Ok((Response::ScanResult { matches, truncated }, None))
            }
            Request::DecodeImage {
                max_width,
                max_height,
                ..
            } => {
                let encoded = read_bounded(input, MAX_IMAGE_INPUT_BYTES)?;
                let (header, pixels) = decode_image(&encoded, *max_width, *max_height)?;
                Ok((Response::Bitmap(header), Some(pixels)))
            }
            // PDF rendering is provided by the platform engine (Android
            // PdfRenderer) or PDFium; see PoC A4. Not available in this build.
            Request::PdfInfo { .. } | Request::RenderPdfPage { .. } => {
                Err(WorkerError::Unsupported)
            }
        }
    }
}

fn read_bounded(input: Option<&mut dyn Read>, max: u64) -> Result<Vec<u8>, WorkerError> {
    let input = input.ok_or(WorkerError::Malformed)?;
    let mut data = Vec::new();
    input
        .take(max.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|_| WorkerError::Malformed)?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > max {
        return Err(WorkerError::TooLarge);
    }
    Ok(data)
}

fn decode_image(
    encoded: &[u8],
    max_width: u32,
    max_height: u32,
) -> Result<(BitmapHeader, Vec<u8>), WorkerError> {
    if max_width == 0 || max_height == 0 {
        return Err(WorkerError::Malformed);
    }
    let mut reader = image::ImageReader::new(std::io::Cursor::new(encoded))
        .with_guessed_format()
        .map_err(|_| WorkerError::Malformed)?;
    if reader.format().is_none() {
        return Err(WorkerError::Unsupported);
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_IMAGE_DECODE_ALLOC);
    reader.limits(limits);
    let decoded = reader.decode().map_err(|e| match e {
        image::ImageError::Limits(_) => WorkerError::TooLarge,
        image::ImageError::Unsupported(_) => WorkerError::Unsupported,
        _ => WorkerError::Malformed,
    })?;
    let fitted = if decoded.width() > max_width || decoded.height() > max_height {
        decoded.thumbnail(max_width, max_height)
    } else {
        decoded
    };
    let rgba = fitted.into_rgba8();
    let (width, height) = rgba.dimensions();
    let stride = width.checked_mul(4).ok_or(WorkerError::TooLarge)?;
    Ok((
        BitmapHeader {
            width,
            height,
            stride,
            format: PixelFormat::Rgba8,
        },
        rgba.into_raw(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rift_protocol::{LandlockStatus, decode_response, encode};

    const CONFINED: Confinement = Confinement {
        seccomp: true,
        no_new_privs: true,
        landlock: LandlockStatus::FullyEnforced,
    };
    const RULES: &str = r#"
        rule rift_a { strings: $a = "RIFT-DEMO-MALWARE-MARKER" condition: $a }
        rule rift_b { strings: $a = "MARKER" condition: $a }
        rule rift_c { condition: filesize > 10 }
    "#;

    fn request(body: Request) -> Envelope<Request> {
        Envelope {
            version: PROTOCOL_VERSION,
            job_id: 9,
            generation: 3,
            body,
        }
    }

    /// Runs a job and checks the controller would accept the answer.
    fn run(worker: &mut Worker, body: Request, input: Option<&[u8]>) -> Outcome {
        let req = request(body);
        let mut reader = input.map(std::io::Cursor::new);
        let outcome = worker.handle(&req, reader.as_mut().map(|r| r as &mut dyn Read));
        let frame = encode(&outcome.response).unwrap();
        let validated = decode_response(&frame[4..], &req);
        assert!(
            validated.is_ok(),
            "controller rejected worker output: {validated:?}"
        );
        outcome
    }

    fn digest(text: &str) -> [u8; 32] {
        Sha256::digest(text.as_bytes()).into()
    }

    fn loaded() -> Worker {
        let mut worker = Worker::new(CONFINED);
        let outcome = run(
            &mut worker,
            Request::LoadRules {
                digest: digest(RULES),
            },
            Some(RULES.as_bytes()),
        );
        assert_eq!(
            outcome.response.body,
            Response::RulesLoaded { rule_count: 3 }
        );
        worker
    }

    fn scan(max_matches: u16) -> Request {
        Request::Scan {
            rules_digest: digest(RULES),
            max_matches,
            deadline_ms: 5000,
        }
    }

    #[test]
    fn hello_reports_confinement() {
        let outcome = run(&mut Worker::new(CONFINED), Request::Hello, None);
        assert_eq!(outcome.response.body, Response::Ready(CONFINED));
        assert_eq!(
            (outcome.response.job_id, outcome.response.generation),
            (9, 3)
        );
    }

    #[test]
    fn rules_must_match_their_digest() {
        let mut worker = Worker::new(CONFINED);
        let outcome = run(
            &mut worker,
            Request::LoadRules { digest: [0; 32] },
            Some(RULES.as_bytes()),
        );
        assert_eq!(
            outcome.response.body,
            Response::Error(WorkerError::Malformed)
        );
        let broken = "rule broken {";
        let outcome = run(
            &mut worker,
            Request::LoadRules {
                digest: digest(broken),
            },
            Some(broken.as_bytes()),
        );
        assert_eq!(
            outcome.response.body,
            Response::Error(WorkerError::Malformed)
        );
    }

    #[test]
    fn scanning_requires_the_named_rules() {
        let outcome = run(&mut Worker::new(CONFINED), scan(10), Some(b"x"));
        assert_eq!(
            outcome.response.body,
            Response::Error(WorkerError::RulesNotLoaded)
        );
    }

    #[test]
    fn scan_reports_matches_and_truncation() {
        let mut worker = loaded();
        let input = b"padding RIFT-DEMO-MALWARE-MARKER padding";
        let all = run(&mut worker, scan(10), Some(input));
        assert_eq!(
            all.response.body,
            Response::ScanResult {
                matches: ["rift_a", "rift_b", "rift_c"]
                    .map(|r| RuleMatch { rule: r.into() })
                    .to_vec(),
                truncated: false
            }
        );
        let capped = run(&mut worker, scan(2), Some(input));
        assert!(
            matches!(capped.response.body, Response::ScanResult { ref matches, truncated: true } if matches.len() == 2)
        );
        let clean = run(&mut worker, scan(10), Some(b"tiny"));
        assert_eq!(
            clean.response.body,
            Response::ScanResult {
                matches: vec![],
                truncated: false
            }
        );
    }

    fn png(width: u32, height: u32) -> Vec<u8> {
        let image = image::RgbaImage::from_pixel(width, height, image::Rgba([10, 20, 30, 255]));
        let mut out = std::io::Cursor::new(Vec::new());
        image.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    fn decode(max: u32) -> Request {
        Request::DecodeImage {
            max_width: max,
            max_height: max,
            deadline_ms: 5000,
        }
    }

    #[test]
    fn image_is_decoded_within_the_requested_box() {
        let mut worker = Worker::new(CONFINED);
        let small = run(&mut worker, decode(256), Some(&png(40, 30)));
        let Response::Bitmap(header) = small.response.body else {
            panic!("{:?}", small.response.body)
        };
        assert_eq!((header.width, header.height, header.stride), (40, 30, 160));
        assert_eq!(small.pixels.as_ref().map(Vec::len), Some(40 * 30 * 4));

        let large = run(&mut worker, decode(100), Some(&png(400, 200)));
        let Response::Bitmap(header) = large.response.body else {
            panic!("{:?}", large.response.body)
        };
        assert!(header.width <= 100 && header.height <= 100, "{header:?}");
        assert_eq!(
            large.pixels.map(|p| p.len() as u64),
            Some(u64::from(header.stride) * u64::from(header.height))
        );
    }

    #[test]
    fn oversized_and_malformed_images_fail_safely() {
        let mut worker = Worker::new(CONFINED);
        // Declared width beyond the decoder limit: refused before allocation.
        let wide = run(
            &mut worker,
            decode(256),
            Some(&png(MAX_IMAGE_DIMENSION + 1, 1)),
        );
        assert_eq!(wide.response.body, Response::Error(WorkerError::TooLarge));
        let mut truncated = png(64, 64);
        truncated.truncate(truncated.len() / 2);
        let broken = run(&mut worker, decode(256), Some(&truncated));
        assert_eq!(
            broken.response.body,
            Response::Error(WorkerError::Malformed)
        );
        let text = run(&mut worker, decode(256), Some(b"not an image at all"));
        assert_eq!(
            text.response.body,
            Response::Error(WorkerError::Unsupported)
        );
        assert!(text.pixels.is_none());
    }

    #[test]
    fn pdf_jobs_are_explicitly_unsupported_in_this_build() {
        let outcome = run(
            &mut Worker::new(CONFINED),
            Request::PdfInfo { deadline_ms: 1000 },
            Some(b"%PDF-1.4"),
        );
        assert_eq!(
            outcome.response.body,
            Response::Error(WorkerError::Unsupported)
        );
    }

    #[test]
    fn missing_input_descriptor_is_an_error() {
        let outcome = run(&mut loaded(), scan(1), None);
        assert_eq!(
            outcome.response.body,
            Response::Error(WorkerError::Malformed)
        );
    }
}
