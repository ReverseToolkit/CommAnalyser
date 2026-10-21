#![cfg_attr(not(feature = "vm"), allow(dead_code))]

//! Module symbol cache. TAL walks Gum's symbol and export tables once per module.

use std::collections::{HashMap, HashSet};
use std::fs;

use goblin::elf::Elf;

/// Addresses that are known not to resolve, capped so a long trace through
/// JIT code cannot grow the set without bound.
const MAX_MISSES: usize = 4096;

#[derive(Default)]
pub struct Symbols {
    modules: HashMap<String, HashMap<u64, String>>,
    miss: HashSet<u64>,
}

impl Symbols {
    /// Resolve `addr` inside the module at `path` with load bias `base`.
    ///
    /// The caller gets the module from the session index; this function never
    /// touches /proc, so it stays usable from an instruction callback.
    pub fn resolve(&mut self, path: &str, base: u64, addr: u64) -> Option<String> {
        if self.miss.contains(&addr) {
            return None;
        }
        let table = self
            .modules
            .entry(path.to_owned())
            .or_insert_with(|| load_module(path, base).unwrap_or_default());
        if let Some(symbol) = table.get(&addr) {
            return Some(symbol.clone());
        }
        if self.miss.len() < MAX_MISSES {
            self.miss.insert(addr);
        }
        None
    }
}

fn load_module(path: &str, base: u64) -> Option<HashMap<u64, String>> {
    let data = fs::read(path).ok()?;
    let elf = Elf::parse(&data).ok()?;
    let mut table = HashMap::new();
    push_syms(&mut table, base, elf.syms, elf.strtab);
    push_syms(&mut table, base, elf.dynsyms, elf.dynstrtab);
    Some(table)
}

fn push_syms(
    table: &mut HashMap<u64, String>,
    base: u64,
    syms: goblin::elf::sym::Symtab,
    strtab: goblin::strtab::Strtab,
) {
    for sym in syms.iter() {
        if sym.st_value == 0 || sym.is_import() {
            continue;
        }
        let Some(name) = strtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let name = name.split('@').next().unwrap_or(name);
        let addr = base.wrapping_add(sym.st_value);
        table.insert(addr, name.to_owned());
    }
}
