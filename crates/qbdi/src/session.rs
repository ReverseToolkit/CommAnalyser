//! Function-trace session policy (TAL door), independent of the QBDI FFI.

use crate::blacklist;
use crate::ring::{EventKind, EventRing, TraceEvent};

/// Which DBI callbacks fill the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventMask {
    pub inst: bool,
    pub mem: bool,
    pub call: bool,
}

impl Default for EventMask {
    fn default() -> Self {
        Self {
            inst: true,
            mem: true,
            call: true,
        }
    }
}

impl EventMask {
    pub fn from_names(names: &[String]) -> Self {
        if names.is_empty() {
            return Self::default();
        }
        let mut mask = Self {
            inst: false,
            mem: false,
            call: false,
        };
        for name in names {
            match name.as_str() {
                "inst" | "instruction" => mask.inst = true,
                "mem" | "memory" => mask.mem = true,
                "call" => mask.call = true,
                _ => {}
            }
        }
        if !mask.inst && !mask.mem && !mask.call {
            return Self::default();
        }
        mask
    }

    pub fn accepts(self, kind: EventKind) -> bool {
        match kind {
            EventKind::Inst => self.inst,
            EventKind::Mem => self.mem,
            EventKind::Call => self.call,
        }
    }
}

/// Break out of the VM at `break_at` and re-enter at `resume`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Escape {
    pub break_at: u64,
    pub resume: u64,
}

/// Configuration for one `Trace.function` session.
#[derive(Clone, Debug)]
pub struct TraceConfig {
    pub target: u64,
    pub module: Option<String>,
    pub extra_exclude: Vec<String>,
    pub until: Option<u64>,
    pub escapes: Vec<Escape>,
    pub events: EventMask,
}

impl TraceConfig {
    pub fn new(target: u64) -> Self {
        Self {
            target,
            module: None,
            extra_exclude: Vec::new(),
            until: None,
            escapes: Vec::new(),
            events: EventMask::default(),
        }
    }

    /// Ranges to strip after instrumenting the target module.
    pub fn blacklist_ranges(&self) -> runtime::Result<Vec<(u64, u64)>> {
        blacklist::excluded_executable_ranges(&self.extra_exclude)
    }

    pub fn should_stop(&self, pc: u64) -> bool {
        self.until == Some(pc) || self.escapes.iter().any(|escape| escape.break_at == pc)
    }
}

/// Host-side session: ring + config. The QBDI VM is created only when linked.
pub struct TraceSession {
    pub config: TraceConfig,
    pub ring: EventRing,
}

impl TraceSession {
    pub fn new(config: TraceConfig) -> Self {
        Self {
            config,
            ring: EventRing::new(4096),
        }
    }

    pub fn record(&mut self, event: TraceEvent) {
        if self.config.events.accepts(event.kind) {
            self.ring.push(event);
        }
    }
}

static EXTRA_EXCLUDE: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Extra module-name needles for `Trace.exclude`.
pub fn exclude_module(name: impl Into<String>) {
    EXTRA_EXCLUDE
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .push(name.into());
}

pub fn extra_excludes() -> Vec<String> {
    EXTRA_EXCLUDE
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .clone()
}

/// Start tracing `config.target`. Without the `link` feature this always errors.
pub fn begin(mut config: TraceConfig) -> runtime::Result<u32> {
    config.extra_exclude.extend(extra_excludes());
    #[cfg(feature = "link")]
    {
        crate::engine::install(config)
    }
    #[cfg(not(feature = "link"))]
    {
        let _ = config;
        Err(runtime::Error::Unsupported(
            "QBDI is not linked (feature = link)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_without_link_is_a_clear_error() {
        let err = begin(TraceConfig::new(0x1000)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("QBDI is not linked"), "{text}");
    }

    #[test]
    fn event_names_and_until() {
        let mask = EventMask::from_names(&["inst".into(), "bogus".into()]);
        assert!(mask.inst && !mask.mem);
        let mut config = TraceConfig::new(0x10);
        config.until = Some(0x20);
        config.escapes.push(Escape {
            break_at: 0x30,
            resume: 0x40,
        });
        assert!(config.should_stop(0x20));
        assert!(config.should_stop(0x30));
        assert!(!config.should_stop(0x10));
    }
}
