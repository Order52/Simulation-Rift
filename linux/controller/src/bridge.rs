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
        include!("cxx-qt-lib/qstringlist.h");
        type QStringList = cxx_qt_lib::QStringList;
        include!("cxx-qt-lib/qurl.h");
        type QUrl = cxx_qt_lib::QUrl;
    }

    // QML sees camelCase names: local_hosts as localHosts.
    #[auto_cxx_name]
    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, status)]
        #[qproperty(QString, intel)]
        #[qproperty(QString, traffic)]
        #[qproperty(QString, denials)]
        #[qproperty(QStringList, quarantine)]
        #[qproperty(QString, address)]
        #[qproperty(bool, active)]
        /// This build has an address to check for database updates.
        #[qproperty(bool, can_update)]
        /// Host names the user allowed to reach local addresses this session.
        #[qproperty(QString, local_hosts)]
        /// Changes with every preview shown.
        #[qproperty(i32, preview_serial)]
        #[qproperty(QString, preview_title)]
        /// Escaped plain text, or empty.
        #[qproperty(QString, preview_text)]
        /// A `data:` URL of a PNG this process encoded, or empty.
        #[qproperty(QString, preview_image)]
        /// What was cut or replaced, or why there is no preview.
        #[qproperty(QString, preview_note)]
        type RiftController = super::RiftControllerRust;

        /// Opens a new session at the typed address, ending any current one.
        #[qinvokable]
        fn open(self: Pin<&mut Self>, address: &QString);
        /// Destroys the current session.
        #[qinvokable]
        fn reset(self: Pin<&mut Self>);
        /// Reads the threat database's state, and the session's proxy
        /// counters and recent refusals.
        #[qinvokable]
        fn refresh(self: Pin<&mut Self>);

        /// Installs the threat database update in `folder`, chosen by the user.
        #[qinvokable]
        fn import_intel(self: Pin<&mut Self>, folder: &QUrl);
        /// Downloads and installs an update from this build's address.
        #[qinvokable]
        fn check_for_update(self: Pin<&mut Self>);
        /// Lets `host` reach local or private addresses in this session.
        #[qinvokable]
        fn allow_local_host(self: Pin<&mut Self>, host: &QString);
        /// Previews quarantined file `index` (as listed).
        #[qinvokable]
        fn preview(self: Pin<&mut Self>, index: i32);
    }

    impl cxx_qt::Threading for RiftController {}
}

use std::pin::Pin;

use base64::Engine as _;
use std::sync::{Arc, OnceLock};
use std::thread;

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::{QList, QString, QStringList, QUrl};

use crate::session::{Controller, Event, Notify, Shown};

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
    quarantine: QStringList,
    address: QString,
    active: bool,
    can_update: bool,
    local_hosts: QString,
    preview_serial: i32,
    preview_title: QString,
    preview_text: QString,
    preview_image: QString,
    preview_note: QString,
    /// The quarantined files listed, as (generation, id, text).
    files: Vec<(u64, String, String)>,
}

impl Default for RiftControllerRust {
    fn default() -> Self {
        let startup = STARTUP.get();
        let (intel, can_update) = match startup.map(|s| &s.controller) {
            Some(Ok(controller)) => (
                controller.intel_summary(),
                controller.update_source().is_some(),
            ),
            _ => (String::new(), false),
        };
        Self {
            status: QString::from(startup.map_or("", |s| s.status.as_str())),
            intel: QString::from(intel.as_str()),
            traffic: QString::default(),
            denials: QString::default(),
            quarantine: QStringList::default(),
            address: QString::from(startup.and_then(|s| s.address.as_deref()).unwrap_or("")),
            active: false,
            can_update,
            local_hosts: QString::default(),
            preview_serial: 0,
            preview_title: QString::default(),
            preview_text: QString::default(),
            preview_image: QString::default(),
            preview_note: QString::default(),
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
        let intel = controller.intel_summary();
        if self.intel().to_string() != intel {
            self.as_mut().set_intel(QString::from(intel.as_str()));
        }
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

    pub fn import_intel(self: Pin<&mut Self>, folder: &QUrl) {
        let Some(dir) = folder
            .to_local_file()
            .map(|p| std::path::PathBuf::from(String::from(&p)))
        else {
            self.set_status(QString::from("Choose a local folder."));
            return;
        };
        self.run(move |controller, notify| {
            notify(Event::Status("Checking the update…".into()));
            let message = controller
                .import_intel(&dir)
                .unwrap_or_else(|error| format!("The update was not installed: {error}"));
            notify(Event::Status(message));
        });
    }

    pub fn check_for_update(self: Pin<&mut Self>) {
        self.run(|controller, notify| {
            notify(Event::Status("Downloading the update…".into()));
            let message = controller
                .check_for_update()
                .unwrap_or_else(|error| format!("The update was not installed: {error}"));
            notify(Event::Status(message));
        });
    }

    pub fn allow_local_host(mut self: Pin<&mut Self>, host: &QString) {
        let Ok(controller) = controller() else { return };
        // Quick: no file or network work.
        match controller.allow_local_host(&String::from(host)) {
            Ok(hosts) => self
                .as_mut()
                .set_local_hosts(QString::from(hosts.join(", ").as_str())),
            Err(error) => self.set_status(QString::from(error.as_str())),
        }
    }

    pub fn preview(self: Pin<&mut Self>, index: i32) {
        let Some((generation, id, title)) = usize::try_from(index)
            .ok()
            .and_then(|i| self.rust().files.get(i).cloned())
        else {
            return;
        };
        self.run(move |controller, notify| {
            notify(Event::Status("Previewing in an isolated worker…".into()));
            let shown = controller.preview(generation, &id);
            notify(Event::Previewed { title, shown });
        });
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
            .spawn(move || {
                // A bug here must not leave the window waiting for an answer.
                // The panic's message is on stderr; state it left behind is
                // refused by rift-ffi as poisoned.
                let report = Arc::clone(&notify);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    work(controller, notify);
                }));
                if outcome.is_err() {
                    report(Event::Status(
                        "Rift hit an internal error and did not finish this action.".into(),
                    ));
                }
            });
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
                self.as_mut().set_local_hosts(QString::default());
                self.as_mut().rust_mut().files.clear();
                self.set_quarantine(QStringList::default());
            }
            Event::Quarantined {
                generation,
                id,
                text,
            } => {
                let files = {
                    let mut rust = self.as_mut().rust_mut();
                    rust.files.push((generation, id, text));
                    list(rust.files.iter().map(|(_, _, text)| text.as_str()))
                };
                self.set_quarantine(files);
            }
            Event::Previewed { title, shown } => {
                let (text, image, note) = match shown {
                    Ok(Shown::Text { text, note }) => (text, String::new(), note),
                    Ok(Shown::Image { png, width, height }) => (
                        String::new(),
                        format!(
                            "data:image/png;base64,{}",
                            base64::engine::general_purpose::STANDARD.encode(png)
                        ),
                        format!("{width} × {height} pixels, decoded by an isolated worker"),
                    ),
                    Err(error) => (String::new(), String::new(), format!("No preview: {error}")),
                };
                self.as_mut().set_status(QString::default());
                self.as_mut()
                    .set_preview_title(QString::from(title.as_str()));
                self.as_mut().set_preview_text(QString::from(text.as_str()));
                self.as_mut()
                    .set_preview_image(QString::from(image.as_str()));
                self.as_mut().set_preview_note(QString::from(note.as_str()));
                let serial = self.preview_serial().wrapping_add(1);
                self.set_preview_serial(serial);
            }
        }
    }
}

fn list<'a>(texts: impl Iterator<Item = &'a str>) -> QStringList {
    QStringList::from(&texts.map(QString::from).collect::<QList<QString>>())
}
