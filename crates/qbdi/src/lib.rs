//! QBDI integration.
//!
//! M0 exposes the intended native API surface and a compile-time feature for
//! linking the static QBDI library.  The real FFI declarations are added when
//! the QBDI build is wired into the workspace (M4).

use runtime::{Error, Result};

/// QBDI version this crate is designed against.
pub const QBDI_VERSION: &str = "0.12";

/// Whether the QBDI static library is linked into this build.
pub const fn linked() -> bool {
    cfg!(feature = "link")
}

/// Instrumentation range, mirroring `QBDI::Range`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}

/// A single QBDI VM.  QBDI requires one VM per guest thread and is not
/// re-entrant; callers must serialize access.
pub struct Vm {
    ranges: Vec<Range>,
}

impl Vm {
    pub fn new() -> Result<Self> {
        if !linked() {
            return Err(Error::Unsupported("QBDI is not linked (feature = link)"));
        }
        Ok(Self { ranges: Vec::new() })
    }

    pub fn add_instrumented_range(&mut self, range: Range) {
        self.ranges.push(range);
    }

    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_link_state() {
        assert_eq!(QBDI_VERSION, "0.12");
        assert!(!linked(), "test build should not link QBDI");
    }

    #[test]
    fn vm_requires_link() {
        assert!(Vm::new().is_err());
    }
}
