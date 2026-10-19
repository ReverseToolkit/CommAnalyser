//! Readable-page cache refreshed from `/proc/self/statm`, not per instruction.

use std::fs;

use runtime::maps::{self, Mapping};

/// Cached readable ranges. Refresh when the first `statm` field changes.
pub struct MemProbe {
    pages: u64,
    readable: Vec<(usize, usize)>,
}

impl Default for MemProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl MemProbe {
    pub fn new() -> Self {
        let mut probe = Self {
            pages: 0,
            readable: Vec::new(),
        };
        probe.force_refresh();
        probe
    }

    /// True if `addr` is in a currently cached readable mapping.
    pub fn readable(&mut self, addr: usize) -> bool {
        self.refresh_if_needed();
        self.readable
            .iter()
            .any(|&(start, end)| addr >= start && addr < end)
    }

    fn refresh_if_needed(&mut self) {
        let pages = statm_pages();
        if pages != self.pages {
            self.pages = pages;
            self.force_refresh();
        }
    }

    fn force_refresh(&mut self) {
        self.readable = maps::read_self_maps()
            .unwrap_or_default()
            .into_iter()
            .filter(|mapping: &Mapping| mapping.perms.read)
            .map(|mapping| (mapping.range.start, mapping.range.end))
            .collect();
        if self.pages == 0 {
            self.pages = statm_pages();
        }
    }
}

fn statm_pages() -> u64 {
    let Ok(text) = fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    text.split_whitespace()
        .next()
        .and_then(|field| field.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_and_code_are_readable() {
        let mut probe = MemProbe::new();
        let local = 1u32;
        assert!(probe.readable(&local as *const u32 as usize));
        let fn_addr = stack_and_code_are_readable as *const () as usize;
        assert!(probe.readable(fn_addr));
        assert!(!probe.readable(0));
        let before = probe.pages;
        assert!(before > 0);
        assert!(probe.readable(&local as *const u32 as usize));
    }
}
