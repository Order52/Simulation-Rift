//! Rift trusted core. See docs/architecture.md §7.1.
//!
//! Everything here runs in the trusted controller process and treats all
//! inputs from web content, files, workers and intelligence packs as untrusted.

pub mod clean;
pub mod download;
pub mod egress;
pub mod filters;
pub mod heuristics;
pub mod hostlists;
pub mod intel;
pub mod pack;
pub mod page;
pub mod policy;
pub mod scan;
pub mod seal;
pub mod session;
pub mod snapshot;
pub mod store;
pub mod text;
pub mod transfer;
pub mod urlcanon;
pub mod urlmodel;
