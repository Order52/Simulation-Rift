//! Simulation-Rift trusted core. See docs/architecture.md §7.1.
//!
//! Everything here runs in the trusted controller process and treats all
//! inputs from web content, files, workers and intelligence packs as untrusted.

pub mod download;
pub mod egress;
pub mod heuristics;
pub mod intel;
pub mod locker;
pub mod pack;
pub mod policy;
pub mod scan;
pub mod session;
pub mod snapshot;
pub mod store;
pub mod text;
pub mod transfer;
pub mod urlcanon;
pub mod vault;
