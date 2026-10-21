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
        /// "missing", "locked", "unlocked" or "unusable".
        #[qproperty(QString, vault)]
        #[qproperty(QStringList, kept)]
        #[qproperty(QString, vault_status)]
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

        /// Creates the vault, protected by `passphrase`.
        #[qinvokable]
        fn create_vault(self: Pin<&mut Self>, passphrase: &QString);
        #[qinvokable]
        fn unlock_vault(self: Pin<&mut Self>, passphrase: &QString);
        #[qinvokable]
        fn lock_vault(self: Pin<&mut Self>);
        /// Copies quarantined file `index` (as listed) into the vault.
        #[qinvokable]
        fn keep(self: Pin<&mut Self>, index: i32);
        /// Deletes kept file `index` (as listed) from the vault.
        #[qinvokable]
        fn remove_kept(self: Pin<&mut Self>, index: i32);
        /// Writes kept file `index` (as listed) to `target`, chosen by the
        /// user after the export warning.
        #[qinvokable]
        fn export_kept(self: Pin<&mut Self>, index: i32, target: &QUrl);
    }

    impl cxx_qt::Threading for RiftController {}
}

use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::thread;

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::{QList, QString, QStringList, QUrl};

use crate::session::{Controller, Event, Notify};
use crate::vault::State;

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
    vault: QString,
    kept: QStringList,
    vault_status: QString,
    /// The quarantined files listed, as (generation, id, text).
    files: Vec<(u64, String, String)>,
    /// The kept files' ids, in the order listed.
    kept_ids: Vec<String>,
}

impl Default for RiftControllerRust {
    fn default() -> Self {
        let startup = STARTUP.get();
        let (intel, vault) = match startup.map(|s| &s.controller) {
            Some(Ok(controller)) => (
                controller.intel_summary(),
                state_name(controller.locker().state()),
            ),
            _ => (String::new(), state_name(State::Unusable)),
        };
        Self {
            status: QString::from(startup.map_or("", |s| s.status.as_str())),
            intel: QString::from(intel.as_str()),
            traffic: QString::default(),
            denials: QString::default(),
            quarantine: QStringList::default(),
            address: QString::from(startup.and_then(|s| s.address.as_deref()).unwrap_or("")),
            active: false,
            vault: QString::from(vault),
            kept: QStringList::default(),
            vault_status: QString::default(),
            files: Vec::new(),
            kept_ids: Vec::new(),
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

    pub fn create_vault(self: Pin<&mut Self>, passphrase: &QString) {
        let passphrase = String::from(passphrase);
        self.run(move |controller, notify| {
            let message = match controller.locker().create(passphrase) {
                Ok(()) => {
                    "The vault was created. Kept files are encrypted; they are still untrusted."
                        .into()
                }
                Err(error) => format!("The vault was not created: {error}"),
            };
            notify(controller.vault_event(Some(message)));
        });
    }

    pub fn unlock_vault(self: Pin<&mut Self>, passphrase: &QString) {
        let passphrase = String::from(passphrase);
        self.run(move |controller, notify| {
            let message = match controller.locker().unlock(passphrase) {
                Ok(()) => None,
                Err(error) => Some(format!("The vault was not unlocked: {error}")),
            };
            notify(controller.vault_event(message));
        });
    }

    pub fn lock_vault(self: Pin<&mut Self>) {
        let Ok(controller) = controller() else { return };
        // On the GUI thread: a lock never waits for other work.
        if controller.locker().lock() {
            crate::session::log("vault locked");
        }
        let event = controller.vault_event(Some("The vault is locked.".into()));
        self.apply(event);
    }

    pub fn keep(self: Pin<&mut Self>, index: i32) {
        let Some((generation, id, _)) = usize::try_from(index)
            .ok()
            .and_then(|i| self.rust().files.get(i).cloned())
        else {
            return;
        };
        self.run(move |controller, notify| {
            let message = controller
                .keep(generation, &id)
                .unwrap_or_else(|error| format!("The file was not kept: {error}"));
            notify(controller.vault_event(Some(message)));
        });
    }

    pub fn remove_kept(self: Pin<&mut Self>, index: i32) {
        let Some(id) = self.kept_id(index) else {
            return;
        };
        self.run(move |controller, notify| {
            let message = match controller.locker().remove(&id) {
                Ok(()) => "The file was deleted from the vault.".into(),
                Err(error) => format!("The file was not deleted: {error}"),
            };
            notify(controller.vault_event(Some(message)));
        });
    }

    pub fn export_kept(self: Pin<&mut Self>, index: i32, target: &QUrl) {
        let Some(id) = self.kept_id(index) else {
            return;
        };
        let Some(path) = target
            .to_local_file()
            .map(|p| std::path::PathBuf::from(String::from(&p)))
        else {
            self.set_vault_status(QString::from(
                "The file was not exported: choose a local file.",
            ));
            return;
        };
        self.run(move |controller, notify| {
            let message = match controller.locker().export(&id, &path) {
                Ok(size) => {
                    crate::session::log(&format!("vault: exported a {size}-byte file"));
                    "Exported. The copy is outside Rift's protection now, and was not made safe."
                        .into()
                }
                Err(error) => format!("The file was not exported: {error}"),
            };
            notify(controller.vault_event(Some(message)));
        });
    }

    fn kept_id(&self, index: i32) -> Option<String> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.rust().kept_ids.get(i).cloned())
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
            Event::Vault {
                state,
                kept,
                message,
            } => {
                self.as_mut().set_vault(QString::from(state_name(state)));
                self.as_mut()
                    .set_kept(list(kept.iter().map(|(_, text)| text.as_str())));
                self.as_mut().rust_mut().kept_ids = kept.into_iter().map(|(id, _)| id).collect();
                self.set_vault_status(QString::from(message.as_deref().unwrap_or("")));
            }
        }
    }
}

fn list<'a>(texts: impl Iterator<Item = &'a str>) -> QStringList {
    QStringList::from(&texts.map(QString::from).collect::<QList<QString>>())
}

fn state_name(state: State) -> &'static str {
    match state {
        State::Missing => "missing",
        State::Locked => "locked",
        State::Unlocked => "unlocked",
        State::Unusable => "unusable",
    }
}
