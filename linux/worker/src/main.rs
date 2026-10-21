//! Simulation-Rift's Linux worker (docs/architecture.md §7.3, §8.6).
//!
//! Started by the controller with a `SOCK_SEQPACKET` channel as stdin, one
//! per job. It confines itself before it reads any request, then answers
//! one datagram at a time: a request frame, with the job's input as an
//! attached read-only descriptor where the request has one; a response
//! frame, with the pixels of a bitmap as an attached sealed memfd. Nothing
//! it says is trusted: the controller validates every reply, and kills the
//! worker at each job's deadline.

mod lockdown;

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::process::ExitCode;

use rift_channel::{Channel, job};
use rift_protocol::{Confinement, Envelope, Request};
use rift_worker::{Deadline, Worker};

/// No channel, or confinement failed: no input was read.
const EXIT_NOT_CONFINED: u8 = 3;
/// A request that is not one: the controller gets no reply and retires it.
const EXIT_BAD_REQUEST: u8 = 4;
const EXIT_CHANNEL: u8 = 5;

fn main() -> ExitCode {
    let channel = match Channel::from_stdin() {
        Ok(channel) => channel,
        Err(error) => {
            eprintln!("rift-worker: no channel: {error}");
            return ExitCode::from(EXIT_NOT_CONFINED);
        }
    };
    let landlock = match lockdown::apply(channel.as_fd()) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("rift-worker: not confined, refusing to work: {error}");
            return ExitCode::from(EXIT_NOT_CONFINED);
        }
    };
    // What lockdown::apply established; the controller checks it.
    let confinement = Confinement {
        seccomp: true,
        no_new_privs: true,
        landlock,
    };
    let mut worker = Worker::new(confinement, Deadline::Supervisor);
    loop {
        let received = match channel.recv() {
            Ok(Some(received)) => received,
            // The controller is done with this worker.
            Ok(None) => return ExitCode::SUCCESS,
            Err(_) => return ExitCode::from(EXIT_CHANNEL),
        };
        let Some(request) = parse(&received.bytes) else {
            return ExitCode::from(EXIT_BAD_REQUEST);
        };
        let mut input = received.attached.map(|fd| Input(File::from(fd)));
        let outcome = worker.handle(&request, input.as_mut().map(|i| i as &mut dyn Read));
        drop(input);
        let Ok(frame) = rift_protocol::encode(&outcome.response) else {
            return ExitCode::from(EXIT_BAD_REQUEST);
        };
        let sent = match outcome.pixels {
            Some(pixels) => job::sealed("rift-pixels", &pixels)
                .and_then(|fd| channel.send(&frame, Some(fd.as_fd()))),
            None => channel.send(&frame, None),
        };
        if sent.is_err() {
            return ExitCode::from(EXIT_CHANNEL);
        }
    }
}

/// One whole frame naming one request, as the controller frames them.
fn parse(frame: &[u8]) -> Option<Envelope<Request>> {
    let mut reader = frame;
    let body = rift_protocol::read_frame(&mut reader).ok()?;
    if !reader.is_empty() {
        return None;
    }
    rift_protocol::decode_request(&body).ok()
}

/// The input descriptor, read with plain read(2) only: `File`'s own
/// `read_to_end` would first ask for its size with statx, which the seccomp
/// filter does not allow.
struct Input(File);

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
