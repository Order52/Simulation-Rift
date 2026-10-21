//! The worker binary as the controller runs it: a fresh process per job, a
//! channel on stdin, input and pixels as sealed memfds. Its confinement is
//! read from the outside, in /proc, while it waits for a request.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::Cursor;
use std::os::fd::AsFd;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rift_channel::{Channel, job};
use rift_protocol::{
    Envelope, LandlockStatus, PROTOCOL_VERSION, Request, Response, decode_response, encode,
    read_frame,
};
use sha2::{Digest, Sha256};

const RULES: &str = r#"rule rift_demo { strings: $a = "rift-demo-marker" condition: $a }"#;

struct Worker {
    child: Child,
    channel: Channel,
    next: u64,
}

impl Worker {
    fn start() -> Self {
        let (channel, theirs) = Channel::pair().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_rift-worker"))
            .stdin(Stdio::from(theirs))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            channel,
            next: 1,
        }
    }

    /// Sends one request and returns the validated response and attachment.
    fn ask(
        &mut self,
        body: Request,
        input: Option<&[u8]>,
    ) -> (Response, Option<std::os::fd::OwnedFd>) {
        let request = Envelope {
            version: PROTOCOL_VERSION,
            job_id: self.next,
            generation: 7,
            body,
        };
        self.next = self.next.checked_add(1).unwrap();
        let frame = encode(&request).unwrap();
        let input = input.map(|bytes| job::sealed("input", bytes).unwrap());
        self.channel
            .send(&frame, input.as_ref().map(AsFd::as_fd))
            .unwrap();
        assert!(
            self.channel.readable(Duration::from_secs(30)).unwrap(),
            "no reply in time"
        );
        let received = self
            .channel
            .recv()
            .unwrap()
            .expect("a reply, not a hang-up");
        let mut reader = received.bytes.as_slice();
        let body = read_frame(&mut reader).unwrap();
        assert!(reader.is_empty());
        let response = decode_response(&body, &request).unwrap().into_inner();
        (response, received.attached)
    }

    fn status(&self) -> String {
        std::fs::read_to_string(format!("/proc/{}/status", self.child.id())).unwrap()
    }

    fn open_fds(&self) -> Vec<u32> {
        let mut fds: Vec<u32> = std::fs::read_dir(format!("/proc/{}/fd", self.child.id()))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
            .collect();
        fds.sort_unstable();
        fds
    }

    /// Ends it by closing the channel; its exit status.
    fn finish(mut self) -> std::process::ExitStatus {
        drop(self.channel);
        self.child.wait().unwrap()
    }
}

fn field<'a>(status: &'a str, name: &str) -> &'a str {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .unwrap_or("")
        .trim()
}

#[test]
fn a_confined_worker_loads_rules_and_scans() {
    let mut worker = Worker::start();
    let (hello, _) = worker.ask(Request::Hello, None);
    let Response::Ready(confinement) = hello else {
        panic!("expected Ready, got {hello:?}");
    };
    assert!(confinement.seccomp && confinement.no_new_privs);
    assert_ne!(confinement.landlock, LandlockStatus::NotApplicable);

    // Seen from outside: seccomp in filter mode, no new privileges, and no
    // descriptor but stdin (/dev/null), stdout, stderr and the channel.
    let status = worker.status();
    assert_eq!(field(&status, "Seccomp"), "2", "{status}");
    assert_eq!(field(&status, "NoNewPrivs"), "1", "{status}");
    assert_eq!(worker.open_fds(), vec![0, 1, 2, 3]);

    let digest: [u8; 32] = Sha256::digest(RULES.as_bytes()).into();
    let (loaded, _) = worker.ask(Request::LoadRules { digest }, Some(RULES.as_bytes()));
    assert_eq!(loaded, Response::RulesLoaded { rule_count: 1 });

    let scan = |worker: &mut Worker, data: &[u8]| {
        worker.ask(
            Request::Scan {
                rules_digest: digest,
                max_matches: 8,
                deadline_ms: 10_000,
            },
            Some(data),
        )
    };
    let (hit, _) = scan(&mut worker, b"prefix rift-demo-marker suffix");
    let Response::ScanResult { matches, truncated } = hit else {
        panic!("expected a scan result, got {hit:?}");
    };
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule, "rift_demo");
    assert!(!truncated);
    let (miss, _) = scan(&mut worker, b"nothing here");
    assert_eq!(
        miss,
        Response::ScanResult {
            matches: vec![],
            truncated: false
        }
    );
    assert!(worker.finish().success());
}

#[test]
fn an_image_comes_back_as_sealed_pixels() {
    let mut png = Vec::new();
    image::RgbaImage::from_pixel(3, 2, image::Rgba([10, 20, 30, 255]))
        .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let mut worker = Worker::start();
    let _ = worker.ask(Request::Hello, None);
    let (response, pixels) = worker.ask(
        Request::DecodeImage {
            max_width: 100,
            max_height: 100,
            deadline_ms: 10_000,
        },
        Some(&png),
    );
    let Response::Bitmap(header) = response else {
        panic!("expected a bitmap, got {response:?}");
    };
    assert_eq!((header.width, header.height, header.stride), (3, 2, 12));
    let bytes = job::read_sealed(pixels.expect("pixels attached"), 1 << 20).unwrap();
    assert_eq!(bytes.len(), 24);
    assert_eq!(&bytes[..4], &[10, 20, 30, 255]);
    assert!(worker.finish().success());
}

#[test]
fn a_request_that_is_not_one_ends_the_worker_without_a_reply() {
    let worker = Worker::start();
    worker.channel.send(b"\x04\0\0\0junk", None).unwrap();
    assert!(worker.channel.readable(Duration::from_secs(30)).unwrap());
    assert!(
        worker.channel.recv().unwrap().is_none(),
        "a reply came back"
    );
    assert_eq!(worker.finish().code(), Some(4));
}
