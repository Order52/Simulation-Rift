use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    CxxQtBuilder::new_qml_module(QmlModule::new("org.simulationrift.app").qml_file("qml/Main.qml"))
        // Qt Qml needs Qt Network linked on some platforms.
        .qt_module("Network")
        .files(["src/bridge.rs"])
        .build();
}
