//! QBDI-backed function trace (TAL door: intercept, run under DBI, batch events).
//!
//! The `link` feature statically links TAL (`tal_prepare` / `tal_enter`).
//! Host tests compile without that payload.

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

/// Whether this build statically links TAL.
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
    fn link_feature_statically_links_tal() {
        let build = include_str!("../build.rs");
        assert!(build.contains("cargo:rustc-link-lib=static:+whole-archive=tal_static"));
        assert!(build.contains("cargo:rustc-link-lib=static=QBDI"));
        let loader = include_str!("load.rs");
        assert!(loader.contains("fn tal_prepare"));
        assert!(loader.contains("fn tal_enter"));
        assert!(!loader.contains("memfd"));
        assert!(!loader.contains("libtal.so.gz"));
        let clear = include_str!("../../agent/clear_cache.c");
        assert!(!clear.contains("__builtin___clear_cache"));
        assert!(clear.contains("dc cvau"));
        let agent = include_str!("../../agent/Cargo.toml");
        assert!(agent.contains("qbdi-static"));
        assert!(agent.contains("qbdi/link"));
    }

    #[test]
    fn engine_follows_tal_door() {
        let engine = include_str!("engine.rs");
        assert!(engine.contains("InlineHook"), "our Interceptor is the door");
        assert!(engine.contains("attach_and_return"), "TAL already ran the body");
        assert!(engine.contains("orig_lr"), "keep SP-PAC'd LR for trampoline ret");
        assert!(engine.contains("tal_prepare") || include_str!("load.rs").contains("tal_prepare"));
        assert!(include_str!("load.rs").contains("pub q"));
        assert!(!engine.contains("qbdi_callA"));
        assert!(!engine.contains("gum_attach"));
    }
}
