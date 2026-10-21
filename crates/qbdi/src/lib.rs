//! QBDI-backed function trace.
//!
//! The crate is split in three layers:
//!
//! - `qbdi-sys` — the raw `qbdi_*` FFI and the `repr(C)` mirrors of QBDI's
//!   structs.
//! - `qbdi-rs` — a safe wrapper: an owned VM, typed registers, Rust
//!   closures as callbacks.
//! - this crate — CommAnalyser's trace session: what to instrument, when to
//!   break out of the VM, and what to record.
//!
//! The `link` feature pulls in QBDI. Without it the crate compiles and the
//! host tests run, but a trace cannot start.

mod args;
mod blacklist;
mod disasm;
mod policy;
mod ring;
mod session;
mod symbols;

#[cfg(feature = "link")]
mod engine;
#[cfg(feature = "vm")]
mod load;

pub use blacklist::{excluded_executable_ranges, is_conflict, is_excluded, ANDROID_CONFLICT};
pub use ring::{EventKind, EventRing, TraceEvent};
pub use session::{
    begin, exclude_module, extra_excludes, Escape, EventMask, PrintMode, TraceConfig,
    DEFAULT_MAX_EVENTS,
};

/// QBDI version this crate is designed against.
pub const QBDI_VERSION: &str = "0.12";

/// Whether this build statically links QBDI.
pub const fn linked() -> bool {
    cfg!(feature = "vm")
}

/// Drain events produced by the last traced call (empty when not linked).
pub fn take_events() -> Vec<TraceEvent> {
    #[cfg(feature = "vm")]
    {
        crate::load::take_events()
    }
    #[cfg(not(feature = "vm"))]
    {
        Vec::new()
    }
}

/// Drain the last batch and report how many events were dropped.
pub fn take_batch() -> (Vec<TraceEvent>, u64) {
    #[cfg(feature = "vm")]
    {
        crate::load::take_batch()
    }
    #[cfg(not(feature = "vm"))]
    {
        (Vec::new(), 0)
    }
}

/// Instrumentation range, mirroring `QBDI::Range`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: u64,
    pub end: u64,
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
    fn unlinked_take_events_is_empty() {
        assert!(!linked());
        assert!(take_events().is_empty());
    }

    #[test]
    fn unlinked_take_batch_is_empty() {
        assert_eq!(take_batch(), (Vec::new(), 0));
    }

    #[test]
    fn events_are_bounded() {
        let mut ring = EventRing::new(2);
        for pc in 0..5 {
            ring.push(TraceEvent::inst(pc, 4, String::new()));
        }
        assert_eq!(ring.dropped(), 3);
        assert_eq!(ring.drain().len(), 2);
        // Dropped is cumulative for the session, not per batch.
        assert_eq!(ring.dropped(), 3);
    }

    #[test]
    fn default_session_is_bounded() {
        let config = TraceConfig::new(0x1000);
        assert_eq!(config.max_events, DEFAULT_MAX_EVENTS);
        assert!(config.max_events > 0);
    }
}
