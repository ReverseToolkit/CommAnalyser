//! ELF symbol lookup combined with `/proc/<pid>/maps` load biases.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use goblin::elf::Elf;
use runtime::maps::Mapping;
use runtime::{Error, Result};

/// Compute the load bias of a file-backed module from its first mapping.
pub fn module_base(maps: &[Mapping], path_suffix: &str) -> Option<usize> {
    let mapping = maps.iter().find(|m| {
        m.clean_path()
            .is_some_and(|p| p == path_suffix || p.ends_with(path_suffix))
    })?;
    Some(mapping.range.start.saturating_sub(mapping.offset as usize))
}

/// Resolve a dynamic symbol in an on-disk ELF, returning its file-relative
/// value.  Undefined/import symbols are ignored.
pub fn symbol_in_file(path: &str, name: &str) -> Result<Option<u64>> {
    let data = fs::read(path).map_err(Error::Io)?;
    let elf = Elf::parse(&data).map_err(|err| Error::Parse(format!("ELF {path}: {err}")))?;

    for sym in elf.dynsyms.iter() {
        if sym.st_value == 0 || sym.is_import() {
            continue;
        }
        if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
            let base = sym_name.split('@').next().unwrap_or(sym_name);
            if base == name {
                return Ok(Some(sym.st_value));
            }
        }
    }

    // Some libs expose symbols only in .symtab (rare for bionic, useful for
    // locally built agents during testing).
    for sym in elf.syms.iter() {
        if sym.st_value == 0 || sym.is_import() {
            continue;
        }
        if let Some(sym_name) = elf.strtab.get_at(sym.st_name) {
            if sym_name == name {
                return Ok(Some(sym.st_value));
            }
        }
    }

    Ok(None)
}

/// Resolve `name` in the module at `path`, using `base` as load bias.
pub fn resolve(path: &str, base: usize, name: &str) -> Result<Option<usize>> {
    Ok(symbol_in_file(path, name)?.map(|value| base.wrapping_add(value as usize)))
}

/// A small cache of module path -> symbol value.  Useful because the injector
/// resolves several libc/linker symbols in one attach.
#[derive(Default)]
pub struct SymbolCache {
    cache: HashMap<(String, String), u64>,
}

impl SymbolCache {
    pub fn resolve(&mut self, path: &str, name: &str) -> Result<Option<u64>> {
        let key = (path.to_owned(), name.to_owned());
        if let Some(value) = self.cache.get(&key) {
            return Ok(Some(*value));
        }
        let value = symbol_in_file(path, name)?;
        if let Some(value) = value {
            self.cache.insert(key, value);
        }
        Ok(value)
    }
}

/// Find the first module path in maps whose basename equals `name`.
pub fn find_module_path(maps: &[Mapping], name: &str) -> Option<String> {
    maps.iter()
        .filter_map(|m| m.clean_path())
        .find(|p| Path::new(p).file_name().and_then(|n| n.to_str()) == Some(name))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_libc_mmap() {
        // Host-only test; the build machine always has libc.
        let candidates = [
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/x86_64-linux-gnu/libc.so.6",
        ];
        let path = candidates.iter().find(|p| Path::new(p).exists());
        if let Some(path) = path {
            assert!(symbol_in_file(path, "mmap").unwrap().is_some());
            assert!(symbol_in_file(path, "__definitely_not_a_symbol")
                .unwrap()
                .is_none());
        }
    }
}
