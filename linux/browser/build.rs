use cxx_qt_build::CxxQtBuilder;

fn main() {
    CxxQtBuilder::new()
        .qt_module("Gui")
        .qt_module("Network")
        .qt_module("Widgets")
        .qt_module("WebEngineCore")
        .qt_module("WebEngineWidgets")
        .file("src/bridge.rs")
        .cpp_file("cpp/browser.cpp")
        .build();
}
