//! Workers (docs/architecture.md §7.3, §8.6): one fresh `rift-worker`
//! process per job, confined by itself before it reads anything (Landlock,
//! seccomp, rlimits), inside the Flatpak sandbox. The controller frames
//! every request with rift-core, passes input as a sealed memfd, enforces
//! each step's deadline by killing the process, and validates every reply
//! with rift-core. Nothing a worker says is trusted.

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rift_channel::{Channel, job};
use rift_ffi::{IntelStatus, PendingIntel, PreviewBitmap, PreviewJob, ScanJob, ScanStart, Verdict};
use rift_protocol::{LandlockStatus, Response};

/// Starting and confining itself takes milliseconds; compiling a pack's
/// rules and scanning a large file take longer.
const HELLO_DEADLINE: Duration = Duration::from_secs(5);
const RULES_DEADLINE: Duration = Duration::from_secs(60);
/// The core's scan deadline (15 s) plus reading the input.
const SCAN_DEADLINE: Duration = Duration::from_secs(20);
/// The worker's own preview deadline (10 s) plus reading the input.
const PREVIEW_DEADLINE: Duration = Duration::from_secs(15);
/// The largest bitmap accepted, as RGBA: rift-protocol's own bound.
const MAX_BITMAP_BYTES: u64 = rift_protocol::MAX_BITMAP_BYTES;

#[derive(Debug, Clone)]
pub struct Workers {
    program: PathBuf,
}

impl Workers {
    pub fn new(program: &Path) -> Self {
        Self {
            program: program.to_owned(),
        }
    }

    fn start(&self) -> Result<WorkerProcess, String> {
        let (channel, theirs) =
            Channel::pair().map_err(|e| format!("no channel for the worker: {e}"))?;
        let child = Command::new(&self.program)
            .env_clear()
            .stdin(Stdio::from(theirs))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("the worker could not be started: {e}"))?;
        Ok(WorkerProcess { child, channel })
    }

    /// Runs a scan the core asked for, in a fresh worker. A worker that
    /// fails, is not confined or answers wrongly gives a verdict that names
    /// the missing coverage, never a clean one.
    pub fn scan(&self, start: ScanStart) -> Result<Verdict, String> {
        match start {
            ScanStart::Done { verdict } => Ok(verdict),
            ScanStart::Run { job } => match self.run_scan(&job) {
                Ok(verdict) => Ok(verdict),
                Err(detail) => job.failed(detail).map_err(|e| e.to_string()),
            },
        }
    }

    fn run_scan(&self, job: &ScanJob) -> Result<Verdict, String> {
        let mut worker = self.start()?;
        let hello = job.hello_frame();
        let reply = worker.ask(&hello, None, HELLO_DEADLINE)?;
        require_landlock(&hello, &reply)?;
        job.accept_hello(reply).map_err(|e| e.to_string())?;
        let reply = worker.ask(&job.load_frame(), Some(&job.rules()), RULES_DEADLINE)?;
        job.accept_load(reply).map_err(|e| e.to_string())?;
        let reply = worker.ask(&job.scan_frame(), Some(&job.input()), SCAN_DEADLINE)?;
        job.finish(reply).map_err(|e| e.to_string())
    }

    /// Renders an image preview in a fresh worker: its RGBA pixels, in rows
    /// of `stride` bytes, read from the sealed memfd it returned.
    pub fn preview(&self, job: &PreviewJob) -> Result<(PreviewBitmap, Vec<u8>), String> {
        let mut worker = self.start()?;
        let hello = job.hello_frame();
        let reply = worker.ask(&hello, None, HELLO_DEADLINE)?;
        require_landlock(&hello, &reply)?;
        job.accept_hello(reply).map_err(|e| e.to_string())?;
        let (reply, pixels) =
            worker.exchange(&job.request_frame(), Some(&job.input()), PREVIEW_DEADLINE)?;
        let bitmap = job
            .accept(reply, MAX_BITMAP_BYTES)
            .map_err(|e| e.to_string())?;
        let pixels = pixels.ok_or("the worker sent no pixels")?;
        let size = u64::from(bitmap.stride).saturating_mul(u64::from(bitmap.height));
        let bytes = job::read_sealed(pixels, size)
            .map_err(|e| format!("the worker's pixels were refused: {e}"))?;
        if u64::try_from(bytes.len()).ok() != Some(size) {
            return Err("the worker's pixels do not match its bitmap".into());
        }
        Ok((bitmap, bytes))
    }

    /// The install check for a verified threat database (§13.2): a fresh
    /// worker must compile exactly its rules before it becomes current.
    pub fn install(&self, pending: &PendingIntel, now_unix: u64) -> Result<IntelStatus, String> {
        let mut worker = self.start()?;
        let hello = pending.hello_frame();
        let reply = worker.ask(&hello, None, HELLO_DEADLINE)?;
        require_landlock(&hello, &reply)?;
        pending.accept_hello(reply).map_err(|e| e.to_string())?;
        let reply = worker.ask(
            &pending.load_frame(),
            Some(&pending.rules()),
            RULES_DEADLINE,
        )?;
        pending.accept_load(reply).map_err(|e| e.to_string())?;
        pending.install(now_unix).map_err(|e| e.to_string())
    }
}

/// rift-core checks for seccomp, which every Android app process has. On
/// Linux the worker must also report Landlock: the filesystem and network
/// rules are its own, not the platform's.
fn require_landlock(hello: &[u8], reply: &[u8]) -> Result<(), String> {
    let request = {
        let mut reader = hello;
        let body = rift_protocol::read_frame(&mut reader).map_err(|e| e.to_string())?;
        rift_protocol::decode_request(&body).map_err(|e| e.to_string())?
    };
    let mut reader = reply;
    let body = rift_protocol::read_frame(&mut reader).map_err(|e| e.to_string())?;
    match rift_protocol::decode_response(&body, &request).map(rift_protocol::Validated::into_inner)
    {
        Ok(Response::Ready(confinement))
            if confinement.seccomp
                && confinement.no_new_privs
                && confinement.landlock != LandlockStatus::NotApplicable =>
        {
            Ok(())
        }
        Ok(Response::Ready(confinement)) => {
            Err(format!("the worker is not fully confined: {confinement:?}"))
        }
        Ok(other) => Err(format!("unexpected answer to hello: {other:?}")),
        Err(error) => Err(format!("invalid answer to hello: {error}")),
    }
}

/// One worker process; killed when dropped.
#[derive(Debug)]
struct WorkerProcess {
    child: Child,
    channel: Channel,
}

impl WorkerProcess {
    /// Sends `frame`, with `input` in a sealed memfd, and returns the reply
    /// frame. A reply with a descriptor is refused here: only bitmaps carry
    /// one, which [`Workers::preview`] takes with `exchange`.
    fn ask(
        &mut self,
        frame: &[u8],
        input: Option<&[u8]>,
        deadline: Duration,
    ) -> Result<Vec<u8>, String> {
        let (reply, attached) = self.exchange(frame, input, deadline)?;
        if attached.is_some() {
            return Err("the worker attached a descriptor to its reply".into());
        }
        Ok(reply)
    }

    fn exchange(
        &mut self,
        frame: &[u8],
        input: Option<&[u8]>,
        deadline: Duration,
    ) -> Result<(Vec<u8>, Option<OwnedFd>), String> {
        let sealed = input
            .map(|bytes| job::sealed("rift-input", bytes))
            .transpose()
            .map_err(|e| format!("could not prepare the worker's input: {e}"))?;
        self.channel
            .send(frame, sealed.as_ref().map(AsFd::as_fd))
            .map_err(|e| format!("the worker could not be reached: {e}"))?;
        drop(sealed);
        match self.channel.readable(deadline) {
            Ok(true) => {}
            Ok(false) => return Err(format!("the worker did not answer within {deadline:?}")),
            Err(error) => return Err(format!("could not wait for the worker: {error}")),
        }
        match self.channel.recv() {
            Ok(Some(received)) => Ok((received.bytes, received.attached)),
            Ok(None) => Err(match self.child.wait() {
                Ok(status) => format!("the worker ended without answering ({status})"),
                Err(error) => format!("the worker ended without answering ({error})"),
            }),
            Err(error) => Err(format!("the worker's answer was refused: {error}")),
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        // Already gone, or killed now: a worker never outlives its job.
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}
