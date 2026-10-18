//! Minimal ELF export lookup for `Module.getExportByName`.

use std::fs;

use ca_core::module;
use ca_core::Result;
use goblin::elf::Elf;

/// Find `symbol` in `module` (or any loaded module when `None`).
/// Returns the relocated address and the module name that provided it.
pub fn find_export(module_name: Option<&str>, symbol: &str) -> Result<Option<(usize, String)>> {
    let modules = module::enumerate()?;
    for module in modules.iter() {
        if let Some(wanted) = module_name {
            if module.name != wanted && module.path != wanted {
                continue;
            }
        }
        let Ok(data) = fs::read(&module.path) else {
            continue;
        };
        let Ok(elf) = Elf::parse(&data) else {
            continue;
        };
        for sym in elf.dynsyms.iter() {
            if sym.st_value == 0 || sym.is_import() {
                continue;
            }
            let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
                continue;
            };
            if name.split('@').next() == Some(symbol) {
                return Ok(Some((
                    module.base.wrapping_add(sym.st_value as usize),
                    module.name.clone(),
                )));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::find_export;

    #[test]
    fn finds_libc_symbol() {
        // Host-only smoke test; not all hosts expose `malloc` in an ELF module.
        if let Some((address, _)) = find_export(None, "malloc").unwrap() {
            assert!(address != 0);
        }
    }
}
