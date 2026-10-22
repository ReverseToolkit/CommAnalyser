//! Core OS abstractions for CommAnalyser.
//!
//! This crate deliberately stays small: memory maps, modules, process and
//! thread identity.  Android-specific probing lives in `art` / `inject`.

pub mod dlsym;
pub mod error;
pub mod ffi;
pub mod handles;
pub mod maps;
pub mod module;
pub mod patch;
pub mod process;
pub mod range;
pub mod thread;

pub use error::{Error, Result};
pub use range::Range;
