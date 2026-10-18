//! Core OS abstractions for CommAnalyser.
//!
//! This crate deliberately stays small: memory maps, modules, process and
//! thread identity.  Android-specific probing lives in `ca-art` / `ca-inject`.

pub mod error;
pub mod maps;
pub mod module;
pub mod process;
pub mod range;
pub mod thread;

pub use error::{Error, Result};
pub use range::Range;
