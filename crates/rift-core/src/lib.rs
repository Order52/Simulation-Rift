//! Simulation-Rift trusted core. See docs/architecture.md §7.1.
//!
//! Everything here runs in the trusted controller process and treats all
//! inputs from web content, files, workers and intelligence packs as untrusted.

pub mod urlcanon;

pub mod intel;
pub mod vault;
