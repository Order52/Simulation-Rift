//! Simulation-Rift's Linux browser host (docs/architecture.md §9.2).
//!
//! Started by the controller with `flatpak-spawn --sandbox --no-network`,
//! with the session channel as stdin. It refuses to run with the engine's
//! sandbox switched off, then shows one Qt WebEngine window whose every
//! main-frame navigation, renderer and download goes past the controller,
//! and whose every connection reaches the network only through the
//! controller's egress proxy.

// The bridge declares its C++ functions in an `unsafe extern "C++"` block,
// which cxx checks against cpp/browser.h at build time. This module holds
// nothing else that is unsafe.
#[allow(unsafe_code)]
mod bridge;
mod host;

use std::process::ExitCode;

use rift_protocol::session::sandbox_switches;

use crate::bridge::ffi;

/// The engine's sandbox would be off or weakened.
const EXIT_SANDBOX_SWITCH: u8 = 3;
/// There is no session channel, or it failed at start.
const EXIT_NO_CHANNEL: u8 = 4;

fn main() -> ExitCode {
    let variables: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    let arguments: Vec<String> = std::env::args_os()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let switches = sandbox_switches(
        variables.iter().map(String::as_str),
        arguments.iter().map(String::as_str),
    );
    if !switches.is_empty() {
        eprintln!(
            "rift-browser: refusing to start, because these turn the engine's sandbox off or weaken it: {}",
            switches.join(", ")
        );
        return ExitCode::from(EXIT_SANDBOX_SWITCH);
    }
    let port = match host::start() {
        Ok(port) => port,
        Err(error) => {
            eprintln!("rift-browser: no session channel: {error}");
            return ExitCode::from(EXIT_NO_CHANNEL);
        }
    };
    let code = ffi::run_browser(port);
    host::closing();
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
