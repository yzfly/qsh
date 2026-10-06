//! qsh-core: the library behind `qsh` and `qsh-server`, a remote shell over QUIC whose
//! sessions survive network changes, sleep and roaming.
//!
//! - [`client::Session`] runs one terminal session from a client: the bootstrap over the
//!   user's ssh, then a connection over QUIC, TLS or an ssh pipe that is replaced whenever it
//!   breaks, with nothing lost.
//! - [`server::Daemon`] is the per-user daemon that owns sessions; [`server::bootstrap`] and
//!   [`server::pipe`] are what the client runs over ssh.
//! - [`hub`] (feature `hub`) keeps one connection per server for many terminals, for embedders.
//! - [`config`] reads qsh_config(5); [`netwatch`] reports network changes so connections can
//!   migrate at once.
//!
//! The wire protocol is specified in `docs/protocol.md` (qsh/1); [`proto`] implements it.
//! Paths follow FHS and XDG ([`paths::Paths`]), and embedders can override every one.

// Unsafe code is denied everywhere; `sys` alone allows it, with every block justified.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod config;
pub mod crypto;
#[cfg(feature = "hub")]
pub mod hub;
pub mod log;
pub mod mux;
pub mod netwatch;
pub mod paths;
pub mod proto;
pub mod server;
pub mod session;
pub mod sys;
pub mod transport;

#[cfg(test)]
mod testutil;

pub use paths::Paths;
