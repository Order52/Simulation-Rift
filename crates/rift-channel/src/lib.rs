//! The controller ⇄ browser host channel on Linux (docs/architecture.md §9.2).
//!
//! One `SOCK_SEQPACKET` socketpair per session. Each datagram is one
//! [`rift_protocol::session`] message, with at most one file descriptor
//! attached: a connection the browser host's forwarder accepted, which only
//! a [`FromBrowser::Connection`] may carry. The controller gives its child
//! end to `flatpak-spawn` as stdin, and the browser host takes it from there
//! with a duplicate ([`Channel::from_stdin`]), so neither side adopts a raw
//! descriptor number and no unsafe code is needed.
//!
//! Workers use the same channel, one per job: request and response frames
//! as datagrams, with the job's input and a bitmap's pixels as sealed
//! memfds ([`job`]).
//!
//! Linux only: elsewhere the crate is empty.

#[cfg(target_os = "linux")]
pub mod job;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;
