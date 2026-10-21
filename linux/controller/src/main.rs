//! Simulation-Rift's Linux controller (docs/architecture.md §9).
//!
//! Runs as the Flatpak's main process and keeps the app's network for the
//! checking proxy. Each session's page runs in a separate browser host that
//! it starts with `flatpak-spawn --sandbox --no-network`; outside Flatpak
//! there is no such sub-sandbox, so it refuses to start.
//!
//! Usage: `rift [ADDRESS]`. SIGTERM or closing the window destroys the
//! session before the controller exits.

// The bridge declares a C++ type in an `unsafe extern "C++"` block, which
// cxx checks at build time. This module holds nothing else that is unsafe.
#[allow(unsafe_code)]
mod bridge;
mod browser;
mod session;
mod vault;
mod worker;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;

use cxx_qt_lib::{QGuiApplication, QQmlApplicationEngine, QUrl};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::bridge::{STARTUP, Startup};
use crate::session::{Controller, Paths, log};

const EXIT_USAGE: u8 = 2;
const EXIT_NOT_FLATPAK: u8 = 3;
/// The session could not be destroyed on the way out.
const EXIT_CLEANUP: u8 = 5;

const BROWSER: &str = "/app/bin/rift-browser";
const WORKER: &str = "/app/bin/rift-worker";
/// The demo threat database a test build carries; a release carries none.
const DEMO_INTEL: &str = "/app/share/rift/intel-demo";
/// A release build's trusted root and update address.
const INTEL_ROOT: &str = "/app/share/rift/intel-root";
const MAIN_QML: &str = "qrc:/qt/qml/org/simulationrift/app/qml/Main.qml";

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let address = arguments.next();
    if arguments.next().is_some() {
        eprintln!("usage: rift [ADDRESS]");
        return ExitCode::from(EXIT_USAGE);
    }
    let Some(app_id) = flatpak_app() else {
        eprintln!(
            "rift: refusing to start outside Flatpak: each session's browser needs the \
             Flatpak portal's no-network sub-sandbox (docs/architecture.md §9.2)"
        );
        return ExitCode::from(EXIT_NOT_FLATPAK);
    };
    let startup = match locations(&app_id) {
        Ok((data, sandbox)) => start(&data, &sandbox, address),
        Err(error) => Startup {
            controller: Err(error.clone()),
            address: None,
            status: format!("Rift could not start: {error}"),
        },
    };
    let controller = startup.controller.clone().ok();
    if let Err(error) = &startup.controller {
        log(&format!("could not start: {error}"));
    }
    let _set = STARTUP.set(startup);
    if let Some(controller) = &controller {
        watch_signals(controller);
        let installer = std::sync::Arc::clone(controller);
        let spawned = thread::Builder::new()
            .name("rift-intel".into())
            .spawn(move || installer.install_demo_intel());
        if let Err(error) = spawned {
            log(&format!(
                "could not start the threat database install: {error}"
            ));
        }
    }

    let mut app = QGuiApplication::new();
    let mut engine = QQmlApplicationEngine::new();
    if let Some(engine) = engine.as_mut() {
        engine.load(&QUrl::from(MAIN_QML));
    }
    if let Some(app) = app.as_mut() {
        app.exec();
    }
    match controller.map(|c| c.end_session(None)) {
        Some(Err(error)) => {
            log(&format!("the session could not be destroyed: {error}"));
            ExitCode::from(EXIT_CLEANUP)
        }
        _ => ExitCode::SUCCESS,
    }
}

fn start(data: &Path, sandbox: &Path, address: Option<String>) -> Startup {
    let demo = Path::new(DEMO_INTEL);
    let paths = Paths {
        data,
        sandbox,
        browser: Path::new(BROWSER),
        worker: Path::new(WORKER),
        demo_intel: demo.is_dir().then_some(demo),
        intel_root: Path::new(INTEL_ROOT)
            .is_dir()
            .then_some(Path::new(INTEL_ROOT)),
    };
    match Controller::open(&paths) {
        Ok((controller, recovery)) => {
            let status = match recovery.interrupted_generation {
                Some(generation) => {
                    log(&format!(
                        "session {generation} from an earlier run destroyed"
                    ));
                    "A session left open by an earlier run was destroyed.".to_owned()
                }
                None => "No session is open.".to_owned(),
            };
            Startup {
                controller: Ok(controller),
                address,
                status,
            }
        }
        Err(error) => Startup {
            status: format!("Rift could not open its session area: {error}"),
            controller: Err(error),
            address: None,
        },
    }
}

/// The Flatpak app id, only when running inside Flatpak.
fn flatpak_app() -> Option<String> {
    if !Path::new("/.flatpak-info").is_file() {
        return None;
    }
    std::env::var("FLATPAK_ID").ok().filter(|id| !id.is_empty())
}

/// `$XDG_DATA_HOME/rift` and `~/.var/app/<id>/sandbox`, created private.
fn locations(app_id: &str) -> Result<(PathBuf, PathBuf), String> {
    use std::os::unix::fs::DirBuilderExt;
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let app_dir = Path::new(&home).join(".var/app").join(app_id);
    let data = std::env::var_os("XDG_DATA_HOME")
        .map_or_else(|| app_dir.join("data"), PathBuf::from)
        .join("rift");
    let sandbox = app_dir.join("sandbox");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    for dir in [&data, &sandbox] {
        builder
            .create(dir)
            .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    }
    Ok((data, sandbox))
}

/// At SIGTERM (logout, shutdown) or SIGINT, destroys the session, then exits.
fn watch_signals(controller: &std::sync::Arc<Controller>) {
    let controller = std::sync::Arc::clone(controller);
    let signals = match Signals::new([SIGTERM, SIGINT]) {
        Ok(signals) => signals,
        Err(error) => {
            log(&format!("cannot watch for SIGTERM: {error}"));
            return;
        }
    };
    let watcher = thread::Builder::new()
        .name("rift-signals".into())
        .spawn(move || {
            let mut signals = signals;
            if let Some(signal) = signals.forever().next() {
                log(&format!("signal {signal}: destroying the session"));
                let code = match controller.end_session(None) {
                    Ok(_) => 0,
                    Err(error) => {
                        log(&format!("the session could not be destroyed: {error}"));
                        i32::from(EXIT_CLEANUP)
                    }
                };
                std::process::exit(code);
            }
        });
    if let Err(error) = watcher {
        log(&format!("cannot watch for SIGTERM: {error}"));
    }
}
