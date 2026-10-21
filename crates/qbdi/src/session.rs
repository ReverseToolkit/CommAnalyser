//! Function-trace session policy (TAL door), independent of the QBDI FFI.

use crate::policy;
use crate::ring::EventKind;

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

/// TAL `PrintMode` values that are not taint or Triton.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrintMode {
    Bin = 1,
    Debug = 2,
    Trace = 3,
    TraceArgs = 5,
}

impl PrintMode {
    pub fn from_name(name: &str) -> runtime::Result<Self> {
        match name {
            "bin" => Ok(Self::Bin),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            "trace_args" => Ok(Self::TraceArgs),
            "addr" | "triton" => Err(runtime::Error::Unsupported(
                "taint and triton are not linked",
            )),
            other => Err(runtime::Error::Parse(format!("unknown trace mode {other}"))),
        }
    }
}

/// Default event budget for one trace (each event owns a String).
pub const DEFAULT_MAX_EVENTS: usize = 100_000;

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
    /// TAL trace_end: stop QBDI before this address and resume native execution.
    pub until: Option<u64>,
    pub escapes: Vec<Escape>,
    pub events: EventMask,
    pub mode: PrintMode,
    /// TAL `trace_all`: instrument every executable map, then `avoid`.
    pub trace_all: bool,
    /// TAL `avoid_range` / `remove_range` pairs `(start, end)`.
    pub avoid: Vec<(u64, u64)>,
    /// Hard cap on buffered events. A trace that overruns it drops the newest
    /// events and reports the count instead of growing until the process OOMs.
    pub max_events: usize,
    /// When set, the traced call writes this file before returning to the guest.
    pub file: Option<String>,
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
            mode: PrintMode::Trace,
            trace_all: false,
            avoid: Vec::new(),
            max_events: DEFAULT_MAX_EVENTS,
            file: None,
        }
    }

    pub fn trace_end(&self) -> u64 {
        self.until.unwrap_or(0)
    }

    pub fn hits_break(&self, pc: u64) -> bool {
        let escapes: Vec<(u64, u64)> = self
            .escapes
            .iter()
            .map(|escape| (escape.break_at, escape.resume))
            .collect();
        policy::hits_break(pc, self.trace_end(), &escapes)
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
        let default = EventMask::default();
        assert!(default.inst && default.mem && default.call);
        assert!(default.accepts(EventKind::Inst));
        let mask = EventMask::from_names(&["inst".into(), "bogus".into()]);
        assert!(mask.inst && !mask.mem);
        assert!(mask.accepts(EventKind::Inst));
        assert!(!mask.accepts(EventKind::Mem));
        let mut config = TraceConfig::new(0x10);
        assert_eq!(config.mode, PrintMode::Trace);
        assert!(PrintMode::from_name("bin").is_ok());
        assert!(PrintMode::from_name("addr").is_err());
        assert!(!config.trace_all);
        assert!(config.avoid.is_empty());
        assert!(config.file.is_none());
        config.until = Some(0x20);
        config.escapes.push(Escape {
            break_at: 0x30,
            resume: 0x40,
        });
        assert!(config.hits_break(0x20));
        assert!(config.hits_break(0x30));
        assert!(!config.hits_break(0x10));
        exclude_module("libhost-test-exclude.so");
        assert!(extra_excludes()
            .iter()
            .any(|name| name == "libhost-test-exclude.so"));
    }
}
