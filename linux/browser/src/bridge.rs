//! The C++ ⇄ Rust boundary of the browser host. C++ owns the Qt WebEngine
//! window; it asks Rust (and through it the controller) before every
//! main-frame navigation, before showing a renderer's page, and when the
//! engine wants a download.

#[cxx_qt::bridge]
pub mod ffi {
    /// The controller's answer, flattened for C++. `kind`: 0 proceed,
    /// 1 confirm (show `text`, load only if the user continues), 2 block.
    struct NavigationAnswer {
        kind: u8,
        text: String,
    }

    extern "Rust" {
        /// Blocks until the controller answers (bounded by a timeout,
        /// after which the navigation is blocked).
        fn decide(
            url: &str,
            main_frame: bool,
            user_gesture: bool,
            redirect: bool,
            confirmed: bool,
        ) -> NavigationAnswer;
        /// Checks renderer `pid` and reports it to the controller. Empty if
        /// the renderer is sandboxed, otherwise why not.
        fn renderer_started(pid: i64) -> String;
        /// The engine's download was cancelled; tell the controller.
        fn download_requested(url: &str, user_agent: &str);
    }

    unsafe extern "C++" {
        include!("rift-browser/cpp/browser.h");

        /// Runs the window until the session ends; returns the exit code.
        fn run_browser(proxy_port: u16) -> i32;
        /// Thread-safe: queued to the GUI thread.
        fn post_load(url: &str);
        /// Thread-safe: closes the window and ends the event loop.
        fn post_close();
        /// "Qt WebEngine x.y.z (Chromium a.b.c.d)".
        fn engine_version() -> String;
    }
}

pub use ffi::NavigationAnswer;

use crate::host;

fn decide(
    url: &str,
    main_frame: bool,
    user_gesture: bool,
    redirect: bool,
    confirmed: bool,
) -> NavigationAnswer {
    host::decide(url, main_frame, user_gesture, redirect, confirmed)
}

fn renderer_started(pid: i64) -> String {
    host::renderer_started(pid)
}

fn download_requested(url: &str, user_agent: &str) {
    host::download_requested(url, user_agent);
}
