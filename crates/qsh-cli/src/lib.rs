//! The command line programs `qsh` and `qsh-server`. Everything that is not command line
//! handling lives in the `qsh-core` library.

#![forbid(unsafe_code)]

pub mod cli;
pub mod escape;
#[cfg(feature = "self-install")]
pub mod install;
pub mod screen;
pub mod sessions;
pub mod terminal;
