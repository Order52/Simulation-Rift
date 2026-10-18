//! UniFFI bindings for the Android isolated worker (docs/architecture.md
//! §7.3, §8.6). The Kotlin service passes in what it was handed (a request
//! frame and the input bytes it read from its read-only descriptor) and
//! returns the response frame to the controller, which validates it.
//!
//! Everything here runs inside the isolated process and is assumed to be
//! compromisable by its input; nothing it says is trusted by the controller.

use std::sync::{Arc, Mutex};

use rift_protocol::{
    BitmapHeader, Confinement, Envelope, LandlockStatus, PROTOCOL_VERSION, PixelFormat, Request,
    Response, WorkerError,
};
use rift_worker::{Deadline, Worker};

#[cfg(any(target_os = "android", target_os = "linux"))]
mod thread_filter;

uniffi::setup_scaffolding!();

/// Installs the parser-thread seccomp filter (§8.6) on the calling thread.
/// The Android service calls it before it touches untrusted input, and
/// fails the job if it cannot be installed.
#[uniffi::export]
pub fn confine_current_thread() -> Result<(), ConfineError> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    return thread_filter::confine_current_thread()
        .map_err(|reason| ConfineError::Failed { reason });
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    Err(ConfineError::Failed {
        reason: "seccomp is not available on this platform".into(),
    })
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ConfineError {
    #[error("{reason}")]
    Failed { reason: String },
}

/// What the Kotlin service has to do with a request it received.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Job {
    /// Handled by rift-worker: call [`WorkerEngine::handle`] with the input.
    Native,
    /// Rendered by the platform's PdfRenderer, then framed with
    /// [`WorkerEngine::platform_reply`].
    PdfPage {
        page: u32,
        max_width: u32,
        max_height: u32,
    },
    /// Not a request this worker understands; answer with `reject`.
    Invalid,
}

/// A response frame and, for bitmaps, the RGBA pixels to put in the output region.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Reply {
    pub frame: Vec<u8>,
    pub pixels: Option<Vec<u8>>,
}

/// The outcome of platform rendering, reported in protocol terms.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PlatformResult {
    Bitmap { width: u32, height: u32 },
    Unsupported,
    Malformed,
    Encrypted,
    TooLarge,
    EngineFailure,
}

#[derive(Debug, uniffi::Object)]
pub struct WorkerEngine {
    worker: Mutex<Worker>,
}

#[uniffi::export]
impl WorkerEngine {
    /// `seccomp` and `no_new_privs` are what this process reads from its own
    /// /proc status; the controller decides whether that is enough.
    #[uniffi::constructor]
    pub fn new(seccomp: bool, no_new_privs: bool) -> Arc<Self> {
        let confinement = Confinement {
            seccomp,
            no_new_privs,
            landlock: LandlockStatus::NotApplicable,
        };
        // Android cannot kill the isolated process, so YARA-X's own timeout
        // applies; unbinding is the controller's backstop (§8.6).
        Arc::new(Self {
            worker: Mutex::new(Worker::new(confinement, Deadline::InProcess)),
        })
    }

    pub fn job(&self, frame: Vec<u8>) -> Job {
        match parse(&frame) {
            Some(Envelope {
                body:
                    Request::RenderPdfPage {
                        page,
                        max_width,
                        max_height,
                        ..
                    },
                ..
            }) => Job::PdfPage {
                page,
                max_width,
                max_height,
            },
            Some(_) => Job::Native,
            None => Job::Invalid,
        }
    }

    /// Runs a request with rift-worker. `input` is what the service read
    /// from the descriptor it was given (empty for requests without one).
    pub fn handle(&self, frame: Vec<u8>, input: Option<Vec<u8>>) -> Reply {
        let Some(request) = parse(&frame) else {
            return reject();
        };
        let Ok(mut worker) = self.worker.lock() else {
            return error_reply(&request, WorkerError::EngineFailure);
        };
        let mut reader = input.as_deref();
        let outcome = worker.handle(
            &request,
            reader.as_mut().map(|r| r as &mut dyn std::io::Read),
        );
        match rift_protocol::encode(&outcome.response) {
            Ok(frame) => Reply {
                frame,
                pixels: outcome.pixels,
            },
            Err(_) => error_reply(&request, WorkerError::TooLarge),
        }
    }

    /// Frames the result of platform rendering for `frame`'s request.
    pub fn platform_reply(&self, frame: Vec<u8>, result: PlatformResult) -> Reply {
        let Some(request) = parse(&frame) else {
            return reject();
        };
        let body = match result {
            PlatformResult::Bitmap { width, height } => match width.checked_mul(4) {
                Some(stride) => Response::Bitmap(BitmapHeader {
                    width,
                    height,
                    stride,
                    format: PixelFormat::Rgba8,
                }),
                None => Response::Error(WorkerError::TooLarge),
            },
            PlatformResult::Unsupported => Response::Error(WorkerError::Unsupported),
            PlatformResult::Malformed => Response::Error(WorkerError::Malformed),
            PlatformResult::Encrypted => Response::Error(WorkerError::Encrypted),
            PlatformResult::TooLarge => Response::Error(WorkerError::TooLarge),
            PlatformResult::EngineFailure => Response::Error(WorkerError::EngineFailure),
        };
        reply(&request, body)
    }
}

/// A frame that names no request: the controller rejects it as malformed.
#[uniffi::export]
pub fn reject() -> Reply {
    Reply {
        frame: Vec::new(),
        pixels: None,
    }
}

fn parse(frame: &[u8]) -> Option<Envelope<Request>> {
    let mut reader = frame;
    let body = rift_protocol::read_frame(&mut reader).ok()?;
    if !reader.is_empty() {
        return None;
    }
    rift_protocol::decode_request(&body).ok()
}

fn reply(request: &Envelope<Request>, body: Response) -> Reply {
    let envelope = Envelope {
        version: PROTOCOL_VERSION,
        job_id: request.job_id,
        generation: request.generation,
        body,
    };
    Reply {
        frame: rift_protocol::encode(&envelope).unwrap_or_default(),
        pixels: None,
    }
}

fn error_reply(request: &Envelope<Request>, error: WorkerError) -> Reply {
    reply(request, Response::Error(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(body: Request) -> Vec<u8> {
        rift_protocol::encode(&Envelope {
            version: PROTOCOL_VERSION,
            job_id: 7,
            generation: 3,
            body,
        })
        .unwrap()
    }

    fn response(reply: &Reply, request: &[u8]) -> Response {
        let mut reader = request;
        let request =
            rift_protocol::decode_request(&rift_protocol::read_frame(&mut reader).unwrap())
                .unwrap();
        let mut reader = &reply.frame[..];
        let body = rift_protocol::read_frame(&mut reader).unwrap();
        rift_protocol::decode_response(&body, &request)
            .unwrap()
            .into_inner()
    }

    #[test]
    fn hello_reports_what_the_process_measured() {
        let engine = WorkerEngine::new(true, false);
        let hello = frame(Request::Hello);
        assert_eq!(engine.job(hello.clone()), Job::Native);
        assert_eq!(
            response(&engine.handle(hello.clone(), None), &hello),
            Response::Ready(Confinement {
                seccomp: true,
                no_new_privs: false,
                landlock: LandlockStatus::NotApplicable
            })
        );
    }

    #[test]
    fn images_decode_within_the_requested_box() {
        let engine = WorkerEngine::new(true, false);
        // 1x1 PNG.
        let png = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52,
            0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0x0d, 0x49,
            0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0, 0x05, 0x00, 0x01,
            0xff, 0x89, 0x99, 0x3d, 0x1d, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60,
            0x82,
        ];
        let request = frame(Request::DecodeImage {
            max_width: 64,
            max_height: 64,
            deadline_ms: 1000,
        });
        let reply = engine.handle(request.clone(), Some(png.to_vec()));
        assert!(matches!(
            response(&reply, &request),
            Response::Bitmap(BitmapHeader {
                width: 1,
                height: 1,
                stride: 4,
                ..
            })
        ));
        assert_eq!(reply.pixels.map(|p| p.len()), Some(4));
        let garbage = engine.handle(request.clone(), Some(b"not an image".to_vec()));
        assert!(matches!(response(&garbage, &request), Response::Error(_)));
    }

    #[test]
    fn pdf_requests_go_to_the_platform_and_come_back_framed() {
        let engine = WorkerEngine::new(true, false);
        let request = frame(Request::RenderPdfPage {
            page: 0,
            max_width: 800,
            max_height: 600,
            deadline_ms: 1000,
        });
        assert_eq!(
            engine.job(request.clone()),
            Job::PdfPage {
                page: 0,
                max_width: 800,
                max_height: 600
            }
        );
        let reply = engine.platform_reply(
            request.clone(),
            PlatformResult::Bitmap {
                width: 464,
                height: 600,
            },
        );
        assert!(matches!(
            response(&reply, &request),
            Response::Bitmap(BitmapHeader {
                width: 464,
                height: 600,
                stride: 1856,
                ..
            })
        ));
    }

    #[test]
    fn garbage_requests_get_an_empty_frame() {
        let engine = WorkerEngine::new(true, false);
        assert_eq!(engine.job(b"junk".to_vec()), Job::Invalid);
        assert!(engine.handle(b"junk".to_vec(), None).frame.is_empty());
    }
}
