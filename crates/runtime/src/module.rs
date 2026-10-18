use std::collections::BTreeMap;
use std::path::Path;

use crate::error::Result;
use crate::maps::{self, Mapping};
use crate::range::Range;

/// A loaded file-backed module (or `[vdso]`) aggregated from maps entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// Basename shown to scripts, e.g. `libc.so`.
    pub name: String,
    /// Full path as seen in `/proc/self/maps`, with ` (deleted)` removed.
    pub path: String,
    /// Lowest mapping start, i.e. the ELF load bias is `base` for most libs.
    pub base: usize,
    /// Highest mapping end.
    pub end: usize,
    /// All mappings belonging to this module, sorted by address.
    pub ranges: Vec<Range>,
}

impl Module {
    #[inline]
    pub fn size(&self) -> usize {
        self.end.saturating_sub(self.base)
    }

    #[inline]
    pub fn range(&self) -> Range {
        Range::new(self.base, self.end)
    }

    #[inline]
    pub fn contains(&self, addr: usize) -> bool {
        self.range().contains(addr)
    }

    /// The mapping containing `addr`, if any.
    pub fn mapping_at<'a>(&self, addr: usize, maps: &'a [Mapping]) -> Option<&'a Mapping> {
        maps.iter()
            .find(|m| m.range.contains(addr) && self.ranges.contains(&m.range))
    }
}

/// Enumerate modules of the current process from `/proc/self/maps`.
///
/// Notes:
/// - anonymous mappings (`[anon:...]`, `[stack]`, `[heap]`) are skipped;
/// - `[vdso]` is kept because scripts commonly look it up by name;
/// - the same path can appear many times (split segments), so entries are
///   grouped by cleaned path.
pub fn enumerate() -> Result<Vec<Module>> {
    let maps = maps::read_self_maps()?;
    Ok(aggregate(&maps))
}

/// Aggregate raw mappings into modules.  Kept public for testing and for
/// remote-process enumeration (where maps come from `/proc/<pid>/maps`).
pub fn aggregate(maps: &[Mapping]) -> Vec<Module> {
    let mut by_path: BTreeMap<String, Module> = BTreeMap::new();

    for m in maps {
        let Some(path) = m.clean_path() else {
            continue;
        };
        if !path.starts_with('/') && path != "[vdso]" {
            continue;
        }
        let name = if path == "[vdso]" {
            "[vdso]".to_owned()
        } else {
            Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(path)
                .to_owned()
        };

        let entry = by_path.entry(path.to_owned()).or_insert_with(|| Module {
            name,
            path: path.to_owned(),
            base: m.range.start,
            end: m.range.end,
            ranges: Vec::new(),
        });
        entry.base = entry.base.min(m.range.start);
        entry.end = entry.end.max(m.range.end);
        entry.ranges.push(m.range);
    }

    let mut result: Vec<Module> = by_path.into_values().collect();
    for module in &mut result {
        module.ranges.sort_by_key(|r| r.start);
    }
    result.sort_by_key(|m| m.base);
    result
}

/// Find a module by exact basename.
pub fn find_by_name(name: &str) -> Result<Option<Module>> {
    Ok(enumerate()?.into_iter().find(|m| m.name == name))
}

/// Find the module containing `addr`.
pub fn find_by_address(addr: usize) -> Result<Option<Module>> {
    Ok(enumerate()?.into_iter().find(|m| m.contains(addr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_groups_segments() {
        let maps = maps::parse_maps(
            "1000-2000 r--p 00000000 fd:01 1 /data/libfoo.so\n\
             2000-3000 r-xp 00001000 fd:01 1 /data/libfoo.so\n\
             3000-4000 rw-p 00002000 fd:01 1 /data/libfoo.so\n\
             5000-6000 rw-p 00000000 00:00 0 [anon:dalvik-main]\n\
             7000-8000 r-xp 00000000 00:00 0 [vdso]\n",
        )
        .unwrap();
        let modules = aggregate(&maps);
        assert_eq!(modules.len(), 2);
        let foo = modules.iter().find(|m| m.name == "libfoo.so").unwrap();
        assert_eq!(foo.base, 0x1000);
        assert_eq!(foo.end, 0x4000);
        assert_eq!(foo.ranges.len(), 3);
        assert_eq!(foo.size(), 0x3000);
        assert!(modules.iter().any(|m| m.name == "[vdso]"));
    }

    #[test]
    fn current_process_has_modules() {
        let modules = enumerate().unwrap();
        assert!(!modules.is_empty(), "expected at least one module");
        assert!(modules.iter().all(|m| m.end >= m.base));
        assert!(modules.windows(2).all(|w| w[0].base <= w[1].base));
    }
}
