//! The browser host's process (docs/architecture.md §9.2): how it is
//! started in a no-network sub-sandbox, and how a session's disposal ends
//! it and deletes what it wrote (§15).

use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use rift_channel::Channel;
use rift_ffi::{BrowserDisposal, DisposalError};
use rift_protocol::session::ToBrowser;
use rustix::process::{Pid, Signal, kill_process};

/// Each generation's writable directory is `<sandbox>/rift-browser-<n>`:
/// `flatpak-spawn --sandbox-expose` takes only names in the app's sandbox
/// directory.
const STATE_PREFIX: &str = "rift-browser-";
/// Inside it, what the engine may write: its home, XDG directories and
/// temporary files, all pointed here so that disposal finds them.
const STATE_PARTS: [(&str, &str); 6] = [
    ("HOME", "home"),
    ("XDG_CONFIG_HOME", "config"),
    ("XDG_CACHE_HOME", "cache"),
    ("XDG_DATA_HOME", "data"),
    ("XDG_STATE_HOME", "state"),
    ("TMPDIR", "tmp"),
];
/// Passed to the browser host when set, so that it can open its window.
const DISPLAY_VARIABLES: [&str; 4] = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "QT_QPA_PLATFORM",
];

/// How long the browser host has to leave after being asked to close, and
/// then after SIGTERM, before flatpak-spawn is killed.
const CLOSE_GRACE: Duration = Duration::from_secs(3);
const TERM_GRACE: Duration = Duration::from_secs(5);
/// How long the channel may stay open after flatpak-spawn has gone: the
/// portal ends the sub-sandbox when flatpak-spawn leaves the bus.
const HANG_UP_WAIT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct Launcher {
    /// The app's sandbox directory, `~/.var/app/<id>/sandbox`.
    sandbox_dir: PathBuf,
    /// The browser host as seen inside the sub-sandbox.
    program: PathBuf,
}

impl Launcher {
    pub fn new(sandbox_dir: PathBuf, program: PathBuf) -> Self {
        Self {
            sandbox_dir,
            program,
        }
    }

    pub fn state_dir(&self, generation: u64) -> PathBuf {
        self.sandbox_dir.join(format!("{STATE_PREFIX}{generation}"))
    }

    /// flatpak-spawn's arguments: no network, no GPU and no files but the
    /// generation's state directory. The display, and the app's filtered
    /// session bus, which the engine needs to start its renderers in their
    /// own sandboxes through the Flatpak portal (Q1, Q2).
    pub fn arguments(
        &self,
        generation: u64,
        display: impl Fn(&str) -> Option<OsString>,
    ) -> Vec<OsString> {
        let state = self.state_dir(generation);
        let mut arguments: Vec<OsString> = [
            "--sandbox",
            "--no-network",
            "--watch-bus",
            "--sandbox-flag=share-display",
            "--sandbox-flag=allow-dbus",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        arguments.push(format!("--sandbox-expose={STATE_PREFIX}{generation}").into());
        arguments.push("--env=QTWEBENGINEPROCESS_PATH=/app/bin/QtWebEngineProcess".into());
        for (variable, part) in STATE_PARTS {
            arguments.push(assignment(variable, state.join(part).as_os_str()));
        }
        for variable in DISPLAY_VARIABLES {
            if let Some(value) = display(variable) {
                arguments.push(assignment(variable, &value));
            }
        }
        arguments.push(self.program.clone().into_os_string());
        arguments
    }

    /// Starts the browser host for `generation` with `channel_end` as its
    /// stdin. Its output goes to the controller's stderr; it logs no
    /// addresses.
    pub fn spawn(&self, generation: u64, channel_end: OwnedFd) -> io::Result<Child> {
        let state = self.state_dir(generation);
        let mut builder = DirBuilder::new();
        builder.recursive(true).mode(0o700);
        for (_, part) in STATE_PARTS {
            builder.create(state.join(part))?;
        }
        Command::new("flatpak-spawn")
            .args(self.arguments(generation, |name| std::env::var_os(name)))
            .stdin(Stdio::from(channel_end))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
    }
}

fn assignment(variable: &str, value: &std::ffi::OsStr) -> OsString {
    let mut argument = OsString::from(format!("--env={variable}="));
    argument.push(value);
    argument
}

/// The running browser host of one generation.
#[derive(Debug)]
pub struct Running {
    pub generation: u64,
    /// flatpak-spawn, which exits when the browser host does.
    pub child: Child,
    /// The controller's end, for Close and for the hang-up check.
    pub channel: Channel,
}

/// The engine-side half of disposal (§15 steps 3–5) for rift-core.
#[derive(Debug)]
pub struct Disposal {
    launcher: Launcher,
    running: Mutex<Option<Running>>,
}

impl Disposal {
    pub fn new(launcher: Launcher) -> Self {
        Self {
            launcher,
            running: Mutex::new(None),
        }
    }

    /// Records the browser host of a session that has just started.
    pub fn attach(&self, running: Running) {
        let previous = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(running);
        // Disposal of the previous generation took it out already.
        debug_assert!(previous.is_none());
    }
}

impl BrowserDisposal for Disposal {
    fn destroy_browser_state(&self, generation: u64) -> Result<(), DisposalError> {
        let mut slot = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.as_ref().is_some_and(|r| r.generation == generation)
            && let Some(mut running) = slot.take()
            && let Err(reason) = end(&mut running)
        {
            // Kept, so that the retry repeats every step.
            *slot = Some(running);
            return Err(DisposalError::Failed { reason });
        }
        drop(slot);
        remove_state(&self.launcher.state_dir(generation))
            .map_err(|reason| DisposalError::Failed { reason })
    }
}

/// Ends the browser host and verifies it: flatpak-spawn has exited and no
/// process holds the browser host's end of the channel any more.
fn end(running: &mut Running) -> Result<(), String> {
    // It may be gone already.
    let _asked = running.channel.send_to_browser(&ToBrowser::Close);
    let mut exited = exited_within(&mut running.child, CLOSE_GRACE)?;
    if !exited {
        // flatpak-spawn forwards SIGTERM to the browser host.
        if let Some(pid) = i32::try_from(running.child.id())
            .ok()
            .and_then(Pid::from_raw)
        {
            let _signalled = kill_process(pid, Signal::TERM);
        }
        exited = exited_within(&mut running.child, TERM_GRACE)?;
    }
    if !exited {
        // Once flatpak-spawn leaves the bus, --watch-bus has the portal end
        // the sub-sandbox.
        running
            .child
            .kill()
            .and_then(|()| running.child.wait())
            .map_err(|e| format!("could not end flatpak-spawn: {e}"))?;
    }
    match running.channel.peer_closed(HANG_UP_WAIT) {
        Ok(true) => Ok(()),
        Ok(false) => Err("the browser host still holds its end of the session channel".into()),
        Err(error) => Err(format!("could not check the session channel: {error}")),
    }
}

fn exited_within(child: &mut Child, limit: Duration) -> Result<bool, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(true),
            Ok(None) if start.elapsed() >= limit => return Ok(false),
            Ok(None) => thread::sleep(POLL),
            Err(error) => return Err(format!("could not wait for flatpak-spawn: {error}")),
        }
    }
}

/// Deletes a generation's state directory and verifies that it is gone.
/// Idempotent: recovery repeats it after a crash.
fn remove_state(dir: &Path) -> Result<(), String> {
    match fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("could not delete the browser's files: {error}")),
    }
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("the browser's files are still there after deletion".into()),
        Err(error) => Err(format!(
            "could not verify the browser's files are gone: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rift-linux-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_browser_host_gets_no_network_and_only_its_own_directory() {
        let launcher = Launcher::new(
            "/home/u/.var/app/x/sandbox".into(),
            "/app/bin/rift-browser".into(),
        );
        let display = |name: &str| (name == "WAYLAND_DISPLAY").then(|| OsString::from("wayland-0"));
        let arguments: Vec<String> = launcher
            .arguments(7, display)
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        for expected in [
            "--sandbox",
            "--no-network",
            "--watch-bus",
            "--sandbox-expose=rift-browser-7",
            "--env=HOME=/home/u/.var/app/x/sandbox/rift-browser-7/home",
            "--env=TMPDIR=/home/u/.var/app/x/sandbox/rift-browser-7/tmp",
            "--env=WAYLAND_DISPLAY=wayland-0",
        ] {
            assert!(
                arguments.iter().any(|a| a == expected),
                "{expected} missing"
            );
        }
        assert_eq!(arguments.last().unwrap(), "/app/bin/rift-browser");
        assert!(!arguments.iter().any(|a| a.contains("share-gpu")));
        assert!(!arguments.iter().any(|a| a.starts_with("--env=DISPLAY=")));
    }

    #[test]
    fn disposal_ends_the_host_and_deletes_its_files_and_can_repeat() {
        let sandbox = scratch("disposal");
        let launcher = Launcher::new(sandbox.clone(), "/unused".into());
        let state = launcher.state_dir(3);
        fs::create_dir_all(state.join("cache/deep")).unwrap();
        fs::write(state.join("cache/deep/page"), b"engine data").unwrap();
        // A host that ignores Close: SIGTERM ends it.
        let (ours, theirs) = Channel::pair().unwrap();
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::from(theirs))
            .spawn()
            .unwrap();
        let disposal = Disposal::new(launcher);
        disposal.attach(Running {
            generation: 3,
            child,
            channel: ours,
        });
        let started = Instant::now();
        disposal.destroy_browser_state(3).unwrap();
        assert!(started.elapsed() >= CLOSE_GRACE);
        assert!(!state.exists());
        assert!(disposal.running.lock().unwrap().is_none());
        // Recovery after a crash repeats it with nothing running.
        disposal.destroy_browser_state(3).unwrap();
        fs::remove_dir_all(sandbox).unwrap();
    }

    #[test]
    fn disposal_fails_while_another_process_holds_the_channel() {
        let sandbox = scratch("held");
        let (ours, theirs) = Channel::pair().unwrap();
        let held = theirs.try_clone().unwrap();
        let child = Command::new("true")
            .stdin(Stdio::from(theirs))
            .spawn()
            .unwrap();
        let disposal = Disposal::new(Launcher::new(sandbox.clone(), "/unused".into()));
        disposal.attach(Running {
            generation: 1,
            child,
            channel: ours,
        });
        let error = disposal.destroy_browser_state(1).unwrap_err();
        assert!(error.to_string().contains("still holds"), "{error}");
        // Kept for the retry, which succeeds once the holder is gone.
        drop(held);
        disposal.destroy_browser_state(1).unwrap();
        fs::remove_dir_all(sandbox).unwrap();
    }
}
