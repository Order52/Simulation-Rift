use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    CxxQtBuilder::new_qml_module(
        QmlModule::new("org.simulationrift.probe").qml_file("qml/main.qml"),
    )
    // Qt Qml needs Qt Network linked on some platforms.
    .qt_module("Network")
    .files(["src/core_object.rs"])
    .build();
}
