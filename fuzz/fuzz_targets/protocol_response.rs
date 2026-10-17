//! Worker responses are hostile input (INV-3). Decoding must never panic, and
//! a response that passes validation must respect the bounds of the request
//! it answers.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_protocol::{
    Envelope, MAX_BITMAP_BYTES, PROTOCOL_VERSION, Request, Response, decode_request,
    decode_response,
};

const REQUESTS: [Request; 6] = [
    Request::Hello,
    Request::LoadRules { digest: [7; 32] },
    Request::Scan {
        rules_digest: [7; 32],
        max_matches: 4,
        deadline_ms: 1000,
    },
    Request::PdfInfo { deadline_ms: 1000 },
    Request::RenderPdfPage {
        page: 0,
        max_width: 640,
        max_height: 480,
        deadline_ms: 1000,
    },
    Request::DecodeImage {
        max_width: 64,
        max_height: 4096,
        deadline_ms: 1000,
    },
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let _ = decode_request(body);
    let request = Envelope {
        version: PROTOCOL_VERSION,
        job_id: 7,
        generation: 3,
        body: REQUESTS[usize::from(selector) % REQUESTS.len()].clone(),
    };
    let Ok(validated) = decode_response(body, &request) else {
        return;
    };
    match (validated.get(), &request.body) {
        (
            Response::Bitmap(header),
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
        ) => {
            assert!(header.width >= 1 && header.width <= *max_width);
            assert!(header.height >= 1 && header.height <= *max_height);
            assert_eq!(u64::from(header.stride), u64::from(header.width) * 4);
            assert!(u64::from(header.stride) * u64::from(header.height) <= MAX_BITMAP_BYTES);
        }
        (Response::ScanResult { matches, .. }, Request::Scan { max_matches, .. }) => {
            assert!(matches.len() <= usize::from(*max_matches));
        }
        (Response::Error(_), _)
        | (Response::Ready(_), Request::Hello)
        | (Response::RulesLoaded { .. }, Request::LoadRules { .. })
        | (Response::PdfInfo { .. }, Request::PdfInfo { .. }) => {}
        (response, request) => panic!("{response:?} accepted as an answer to {request:?}"),
    }
});
