//! The controller as a QML object. QML calls Rust in the same process; the
//! session threads report back through Qt's event loop. Every string shown
//! is plain text, and anything from the web in it has been escaped.

#[cxx_qt::bridge]
pub mod qobject {
    // cxx's declaration of a C++ type that Rust uses; cxx generates and
    // checks the binding.
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, status)]
        #[qproperty(QString, intel)]
        #[qproperty(QString, traffic)]
        #[qproperty(QString, denials)]
        #[qproperty(QString, quarantine)]
        #[qproperty(QString, address)]
        #[qproperty(bool, active)]
        type RiftController = super::RiftControllerRust;

        /// Opens a new session at the typed address, ending any current one.
        #[qinvokable]
        fn open(self: Pin<&mut Self>, address: &QString);
        /// Destroys the current session.
        #[qinvokable]
        fn reset(self: Pin<&mut Self>);
        /// Reads the session's proxy counters and recent refusals.
        #[qinvokable]
        fn refresh(self: Pin<&mut Self>);
    }

    impl cxx_qt::Threading for RiftController {}
}

use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::thread;

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::QString;

use crate::session::{Controller, Event, Notify};

/// Set once by `main` before QML is loaded.
#[derive(Debug)]
pub struct Startup {
    pub controller: Result<Arc<Controller>, String>,
    /// The address given on the command line, opened at once.
    pub address: Option<String>,
    pub status: String,
}

pub static STARTUP: OnceLock<Startup> = OnceLock::new();

/// The most recent refusals shown.
const SHOWN_DENIALS: usize = 20;

#[derive(Debug)]
pub struct RiftControllerRust {
    status: QString,
    intel: QString,
    traffic: QString,
    denials: QString,
    quarantine: QString,
    address: QString,
    active: bool,
    files: Vec<String>,
}

impl Default for RiftControllerRust {
    fn default() -> Self {
        let startup = STARTUP.get();
        let intel = match startup.map(|s| &s.controller) {
            Some(Ok(controller)) => controller.intel_summary(),
            _ => String::new(),
        };
        Self {
            status: QString::from(startup.map_or("", |s| s.status.as_str())),
            intel: QString::from(intel.as_str()),
            traffic: QString::default(),
            denials: QString::default(),
            quarantine: QString::default(),
            address: QString::from(startup.and_then(|s| s.address.as_deref()).unwrap_or("")),
            active: false,
            files: Vec::new(),
        }
    }
}

fn controller() -> Result<Arc<Controller>, String> {
    match STARTUP.get().map(|s| &s.controller) {
        Some(Ok(controller)) => Ok(Arc::clone(controller)),
        Some(Err(error)) => Err(error.clone()),
        None => Err("the controller was not started".into()),
    }
}

impl qobject::RiftController {
    pub fn open(self: Pin<&mut Self>, address: &QString) {
        let address = String::from(address);
        if address.trim().is_empty() {
            return;
        }
        self.run(move |controller, notify| {
            notify(Event::Status("Starting a new session…".into()));
            match controller.open_session(&address, Arc::clone(&notify)) {
                Ok(generation) => notify(Event::Started(generation)),
                Err(error) => notify(Event::Status(format!("The session did not start: {error}"))),
            }
        });
    }

    pub fn reset(self: Pin<&mut Self>) {
        self.run(|controller, notify| match controller.end_session(None) {
            Ok(Some(generation)) => {
                notify(Event::Status("The session was destroyed.".into()));
                notify(Event::Ended(generation));
            }
            Ok(None) => {}
            Err(error) => notify(Event::Status(format!(
                "The session could not be destroyed: {error}. Rift will retry when it next starts."
            ))),
        });
    }

    pub fn refresh(mut self: Pin<&mut Self>) {
        let Ok(controller) = controller() else { return };
        let Some(stats) = controller.stats() else {
            return;
        };
        let traffic = format!(
            "Proxy: {} connections allowed, {} refused.",
            stats.allowed, stats.denied
        );
        let denials: Vec<String> = stats
            .recent
            .iter()
            .rev()
            .take(SHOWN_DENIALS)
            .map(|d| format!("{} — {}", d.destination, d.reason))
            .collect();
        self.as_mut().set_traffic(QString::from(traffic.as_str()));
        self.as_mut()
            .set_denials(QString::from(denials.join("\n").as_str()));
    }

    /// Runs `work` off the GUI thread, with a way to report back to it.
    fn run(self: Pin<&mut Self>, work: impl FnOnce(Arc<Controller>, Notify) + Send + 'static) {
        let controller = match controller() {
            Ok(controller) => controller,
            Err(error) => {
                self.set_status(QString::from(
                    format!("Rift could not start: {error}").as_str(),
                ));
                return;
            }
        };
        let qt = self.qt_thread();
        let notify: Notify = Arc::new(move |event| {
            // Fails only once the window is gone, when there is no one to tell.
            let _queued = qt.queue(move |object| object.apply(event));
        });
        let spawned = thread::Builder::new()
            .name("rift-control".into())
            .spawn(move || work(controller, notify));
        if spawned.is_err() {
            crate::session::log("could not start a worker thread");
        }
    }

    fn apply(mut self: Pin<&mut Self>, event: Event) {
        match event {
            Event::Status(text) => self.set_status(QString::from(text.as_str())),
            Event::Started(_) => self.set_active(true),
            Event::Ended(_) => {
                self.as_mut().set_active(false);
                self.as_mut().set_traffic(QString::default());
                self.as_mut().set_denials(QString::default());
                self.as_mut().rust_mut().files.clear();
                self.set_quarantine(QString::default());
            }
            Event::Quarantined(file) => {
                let files = {
                    let mut rust = self.as_mut().rust_mut();
                    rust.files.push(file);
                    rust.files.join("\n")
                };
                self.set_quarantine(QString::from(files.as_str()));
            }
        }
    }
}
