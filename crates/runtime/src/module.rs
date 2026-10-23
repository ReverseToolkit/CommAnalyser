use std::collections::HashSet;
use std::path::Path;

use crate::error::{Error, Result};
use crate::maps::{self, Mapping};
use crate::range::Range;

/// A loaded file-backed module (or `[vdso]`) aggregated from maps entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// Basename shown to scripts, e.g. `libc.so`.
    pub name: String,
    /// Full path as seen in `/proc/self/maps`, with ` (deleted)` removed.
    pub path: String,
    /// Start of the loaded image. For a normal ELF this is the load bias:
    /// the first mapping of the contiguous run that contains the text,
    /// not a separate read-only file snapshot of the same path.
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
/// - consecutive mappings of the same path (split PT_LOAD segments) form one
///   module, matching Frida's proc-maps walk;
/// - a later disjoint run of the same path that is only readable is dropped
///   when another run is executable. That is a file snapshot (`g_mapped_file`),
///   not the linker load. Using its start as `base` relocates symbols into a
///   non-executable page.
pub fn enumerate() -> Result<Vec<Module>> {
    let maps = maps::read_self_maps()?;
    Ok(aggregate(&maps))
}

struct Run {
    module: Module,
    executable: bool,
}

/// Aggregate raw mappings into modules.  Kept public for testing and for
/// remote-process enumeration (where maps come from `/proc/<pid>/maps`).
///
/// `maps` must be in address order, as `/proc/<pid>/maps` is.
pub fn aggregate(maps: &[Mapping]) -> Vec<Module> {
    let mut runs: Vec<Run> = Vec::new();
    for mapping in maps {
        let Some(path) = mapping.clean_path() else {
            continue;
        };
        if !path.starts_with('/') && path != "[vdso]" {
            continue;
        }
        if let Some(run) = runs.last_mut().filter(|run| run.module.path == path) {
            run.module.end = run.module.end.max(mapping.range.end);
            run.module.ranges.push(mapping.range);
            run.executable |= mapping.perms.exec;
            continue;
        }
        runs.push(Run {
            module: Module {
                name: module_name(path),
                path: path.to_owned(),
                base: mapping.range.start,
                end: mapping.range.end,
                ranges: vec![mapping.range],
            },
            executable: mapping.perms.exec,
        });
    }

    let loaded: HashSet<String> = runs
        .iter()
        .filter(|run| run.executable)
        .map(|run| run.module.path.clone())
        .collect();
    let mut result: Vec<Module> = runs
        .into_iter()
        .filter(|run| run.executable || !loaded.contains(&run.module.path))
        .map(|run| run.module)
        .collect();
    for module in &mut result {
        module.ranges.sort_by_key(|range| range.start);
    }
    result.sort_by_key(|module| module.base);
    result
}

fn module_name(path: &str) -> String {
    if path == "[vdso]" {
        return "[vdso]".to_owned();
    }
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_owned()
}

/// The module covering the process executable, Frida's `Process.mainModule`.
pub fn main_module() -> Result<Option<Module>> {
    let exe = std::fs::read_link("/proc/self/exe")
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let modules = enumerate()?;
    if let Some(exe) = exe {
        if let Some(module) = modules
            .iter()
            .find(|module| module.path == exe || exe.ends_with(&module.name))
            .cloned()
        {
            return Ok(Some(module));
        }
    }
    Ok(modules.into_iter().next())
}

/// Find a module by exact basename.
pub fn find_by_name(name: &str) -> Result<Option<Module>> {
    Ok(find_in(&maps::read_self_maps()?, name))
}

/// Find `name` in an already parsed map list.
pub fn find_in(maps: &[maps::Mapping], name: &str) -> Option<Module> {
    aggregate(maps)
        .into_iter()
        .find(|module| module.name == name || module.path == name)
}

/// Bytes of one loaded module, plus the anonymous `.bss` mapped immediately
/// after its last file-backed page.
#[derive(Clone, Debug)]
pub struct CapturedImage {
    pub base: usize,
    pub bytes: Vec<u8>,
    pub perms: Vec<DumpPerm>,
}

/// One readable piece of a captured image. Offsets are relative to `base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DumpPerm {
    pub offset: usize,
    pub len: usize,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

/// Address span to dump: the module's file-backed run, extended through a
/// contiguous nameless writable tail.
pub fn dump_span(module: &Module, maps: &[maps::Mapping]) -> Range {
    let mut end = module.end;
    while let Some(mapping) = maps.iter().find(|mapping| mapping.range.start == end) {
        if mapping.path.is_some()
            || !mapping.perms.read
            || !mapping.perms.write
            || mapping.perms.exec
        {
            break;
        }
        end = mapping.range.end;
    }
    Range::new(module.base, end)
}

/// Capture `name` from the current process.
pub fn capture_here(name: &str) -> Result<CapturedImage> {
    capture_process(std::process::id(), name, true)
}

/// Capture `name` from another process through `/proc/<pid>/mem`.
pub fn capture_pid(pid: u32, name: &str) -> Result<CapturedImage> {
    capture_process(pid, name, false)
}

fn capture_process(pid: u32, name: &str, direct: bool) -> Result<CapturedImage> {
    let maps = maps::read_maps(pid)?;
    let module = find_in(&maps, name).ok_or_else(|| Error::NotFound(name.to_owned()))?;
    let span = dump_span(&module, &maps);
    let mut bytes = vec![0u8; span.len()];
    let mut perms = Vec::new();
    let mut mem = if direct {
        None
    } else {
        Some(std::fs::File::open(format!("/proc/{pid}/mem"))?)
    };
    for mapping in &maps {
        if mapping.range.end <= span.start || mapping.range.start >= span.end {
            continue;
        }
        let start = mapping.range.start.max(span.start);
        let end = mapping.range.end.min(span.end);
        let offset = start - span.start;
        let len = end - start;
        if mapping.perms.read {
            if let Some(file) = mem.as_mut() {
                read_mem(file, start, &mut bytes[offset..offset + len])?;
            } else {
                // SAFETY: `start..end` is a readable mapping in this process.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        start as *const u8,
                        bytes[offset..offset + len].as_mut_ptr(),
                        len,
                    );
                }
            }
        }
        perms.push(DumpPerm {
            offset,
            len,
            read: mapping.perms.read,
            write: mapping.perms.write,
            exec: mapping.perms.exec,
        });
    }
    Ok(CapturedImage {
        base: span.start,
        bytes,
        perms,
    })
}

fn read_mem(file: &mut std::fs::File, address: usize, buf: &mut [u8]) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut done = 0usize;
    while done < buf.len() {
        let chunk = (buf.len() - done).min(0x1000);
        let at = address + done;
        if file.seek(SeekFrom::Start(at as u64)).is_err() {
            done += chunk;
            continue;
        }
        match file.read(&mut buf[done..done + chunk]) {
            Ok(0) | Err(_) => {}
            Ok(n) => {
                done += n;
                continue;
            }
        }
        done += chunk;
    }
    Ok(())
}

pub fn score_containing(module: &Module, addr: usize) -> (u8, u8, usize) {
    let exact = u8::from(module.base != addr);
    let ephemeral = u8::from(
        module.name.contains("memfd")
            || module.name.contains("jit")
            || !module.path.starts_with('/'),
    );
    (exact, ephemeral, module.size())
}

/// Find the module containing `addr`.
///
/// Prefer an exact `base` match, then a file-backed mapping, then the
/// smallest containing module (ART jit/memfd ranges can overlap an ELF).
pub fn find_by_address(addr: usize) -> Result<Option<Module>> {
    Ok(enumerate()?
        .into_iter()
        .filter(|module| module.contains(addr))
        .min_by_key(|module| score_containing(module, addr)))
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
    fn file_snapshot_does_not_become_the_load_bias() {
        // Lowest run is a whole-file r-- image. The linker mapping comes later,
        // after another module, and is the one that contains executable pages.
        let maps = maps::parse_maps(
            "1000-4000 r--p 00000000 fd:01 1 /apex/libm.so\n\
             5000-6000 r-xp 00000000 fd:01 2 /apex/libc.so\n\
             8000-9000 r--p 00000000 fd:01 1 /apex/libm.so\n\
             9000-b000 r-xp 00001000 fd:01 1 /apex/libm.so\n",
        )
        .unwrap();
        let modules = aggregate(&maps);
        let libm = modules.iter().find(|m| m.name == "libm.so").unwrap();
        assert_eq!(libm.base, 0x8000);
        assert_eq!(libm.end, 0xb000);
        assert_eq!(libm.ranges.len(), 2);
        assert!(!libm.contains(0x1000));
        assert_eq!(
            modules.iter().filter(|m| m.name == "libm.so").count(),
            1
        );
        assert_eq!(
            modules.iter().find(|m| m.name == "libc.so").unwrap().base,
            0x5000
        );
    }

    #[test]
    fn dump_span_includes_a_nameless_writable_tail() {
        let maps = maps::parse_maps(
            "1000-2000 r--p 00000000 fd:01 1 /data/libfoo.so\n\
             2000-3000 r-xp 00001000 fd:01 1 /data/libfoo.so\n\
             3000-4000 rw-p 00002000 fd:01 1 /data/libfoo.so\n\
             4000-4800 rw-p 00000000 00:00 0 \n\
             5000-6000 r-xp 00000000 fd:01 2 /data/libbar.so\n",
        )
        .unwrap();
        let foo = aggregate(&maps)
            .into_iter()
            .find(|module| module.name == "libfoo.so")
            .unwrap();
        assert_eq!(foo.end, 0x4000);
        assert_eq!(dump_span(&foo, &maps), Range::new(0x1000, 0x4800));
    }

    #[test]
    fn dump_span_stops_at_a_hole_or_a_named_mapping() {
        let maps = maps::parse_maps(
            "1000-2000 r-xp 00000000 fd:01 1 /data/libfoo.so\n\
             3000-4000 rw-p 00000000 00:00 0 \n\
             4000-5000 rw-p 00000000 00:00 0 [anon:libc_malloc]\n",
        )
        .unwrap();
        let foo = aggregate(&maps)
            .into_iter()
            .find(|module| module.name == "libfoo.so")
            .unwrap();
        assert_eq!(dump_span(&foo, &maps), Range::new(0x1000, 0x2000));
    }

    #[test]
    fn readable_only_module_is_kept_when_it_is_the_only_run() {
        let maps = maps::parse_maps("1000-2000 r--p 00000000 fd:01 1 /data/libonly.so\n").unwrap();
        let modules = aggregate(&maps);
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].base, 0x1000);
    }

    #[test]
    fn current_process_has_modules() {
        let modules = enumerate().unwrap();
        assert!(!modules.is_empty(), "expected at least one module");
        assert!(modules.iter().all(|m| m.end >= m.base));
        assert!(modules.windows(2).all(|w| w[0].base <= w[1].base));
    }

    #[test]
    fn main_module_and_lookup() {
        let main = main_module().unwrap().expect("main module");
        assert!(!main.name.is_empty());
        assert!(main.end > main.base);
        let by_name = find_by_name(&main.name).unwrap().expect("find_by_name");
        assert_eq!(by_name.base, main.base);
        let by_addr = find_by_address(main.base)
            .unwrap()
            .expect("find_by_address");
        assert!(by_addr.contains(main.base));
    }
}
