//! PoC Q3: a Cargo-only cxx-qt QML application that calls rift-core.
//! Run with `QT_QPA_PLATFORM=offscreen` for the self-test: the QML file calls
//! the core, prints the answers, and quits.

pub mod core_object;

use cxx_qt_lib::{QGuiApplication, QQmlApplicationEngine, QUrl};

fn main() {
    let mut app = QGuiApplication::new();
    let mut engine = QQmlApplicationEngine::new();
    if let Some(engine) = engine.as_mut() {
        engine.load(&QUrl::from(
            "qrc:/qt/qml/org/simulationrift/probe/qml/main.qml",
        ));
    }
    if let Some(app) = app.as_mut() {
        std::process::exit(app.exec());
    }
}
