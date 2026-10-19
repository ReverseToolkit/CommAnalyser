//! QBDI-backed function trace (TAL door: intercept, run under DBI, batch events).
//!
//! The `link` feature embeds a compressed `libtal.so` and dlopens it on
//! first `Trace.function`. Host tests compile without that payload.

mod blacklist;
mod probe;
mod ring;
mod session;

#[cfg(feature = "link")]
mod engine;
#[cfg(feature = "link")]
mod load;

pub use blacklist::{excluded_executable_ranges, is_conflict, is_excluded, ANDROID_CONFLICT};
pub use probe::MemProbe;
pub use ring::{EventKind, EventRing, TraceEvent};
pub use session::{
    begin, exclude_module, extra_excludes, Escape, EventMask, TraceConfig, TraceSession,
};

use runtime::{Error, Result};

/// QBDI version this crate is designed against.
pub const QBDI_VERSION: &str = "0.12";

/// Whether this build embeds a QBDI shared library payload.
pub const fn linked() -> bool {
    cfg!(feature = "link")
}

/// Drain events produced by the last traced call (empty when not linked).
pub fn take_events() -> Vec<TraceEvent> {
    #[cfg(feature = "link")]
    {
        crate::engine::drain_events()
    }
    #[cfg(not(feature = "link"))]
    {
        Vec::new()
    }
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
        let err = match Vm::new() {
            Ok(_) => panic!("Vm::new must fail without link"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("QBDI is not linked"), "{err}");
        assert!(take_events().is_empty());
    }

    #[test]
    fn link_feature_embeds_shared_payload() {
        let build = include_str!("../build.rs");
        assert!(build.contains("libtal.so.gz"));
        assert!(
            !build.contains("cargo:rustc-link-lib=static=QBDI"),
            "TAL is a shared library, not statically linked QBDI"
        );
        let loader = include_str!("load.rs");
        assert!(loader.contains("tal_prepare"));
        assert!(loader.contains("tal_enter"));
        let agent = include_str!("../../agent/Cargo.toml");
        assert!(agent.contains("qbdi-static"));
        assert!(agent.contains("qbdi/link"));
    }

    #[test]
    fn engine_follows_tal_door() {
        let engine = include_str!("engine.rs");
        assert!(engine.contains("InlineHook"), "our Interceptor is the door");
        assert!(engine.contains("tal_prepare") || include_str!("load.rs").contains("tal_prepare"));
        assert!(!engine.contains("qbdi_callA"));
        assert!(!engine.contains("gum_attach"));
    }
}
