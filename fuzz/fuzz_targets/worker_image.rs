//! The worker decodes images from untrusted downloads (§8.6). Whatever the
//! bytes, it must answer with a bitmap inside the requested bounds whose
//! pixels match its header, or with an error, and the controller must accept
//! that answer: a worker that sends what the controller refuses breaks the
//! preview instead of failing it cleanly.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rift_protocol::{
    Confinement, Envelope, LandlockStatus, PROTOCOL_VERSION, Request, Response, decode_response,
    encode,
};
use rift_worker::{Deadline, Worker};

fuzz_target!(|data: &[u8]| {
    let Some((bounds, mut image)) = data.split_first_chunk::<2>() else {
        return;
    };
    let request = Envelope {
        version: PROTOCOL_VERSION,
        job_id: 1,
        generation: 1,
        body: Request::DecodeImage {
            max_width: u32::from(bounds[0]) + 1,
            max_height: u32::from(bounds[1]) + 1,
            deadline_ms: 1000,
        },
    };
    let mut worker = Worker::new(
        Confinement {
            seccomp: false,
            no_new_privs: false,
            landlock: LandlockStatus::NotApplicable,
        },
        Deadline::Supervisor,
    );
    let outcome = worker.handle(&request, Some(&mut image));
    let encoded = encode(&outcome.response).expect("the worker's answer encodes");
    let accepted = decode_response(&encoded, &request)
        .unwrap_or_else(|e| panic!("the controller refused {:?}: {e:?}", outcome.response.body));
    match (accepted.get(), outcome.pixels) {
        (Response::Bitmap(header), Some(pixels)) => assert_eq!(
            u64::try_from(pixels.len()).unwrap(),
            u64::from(header.stride) * u64::from(header.height)
        ),
        (Response::Error(_), None) => {}
        (response, pixels) => panic!("{response:?} with pixels: {}", pixels.is_some()),
    }
});
