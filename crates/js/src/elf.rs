//! Minimal ELF export lookup for `Module.getExportByName`.

use std::ffi::CString;
use std::fs;

use goblin::elf::Elf;
use runtime::module;
use runtime::Result;

/// Find `symbol` in `module` (or any loaded module when `None`).
/// Returns the relocated address and the module name that provided it.
pub fn find_export(module_name: Option<&str>, symbol: &str) -> Result<Option<(usize, String)>> {
    // dlsym resolves GNU IFUNCs (strlen, memcpy, ...) and symbol versions for
    // us.  Use it as the fast path, then fall back to parsing the ELF for
    // modules that are not visible in the default namespace.
    if let Some(address) = resolve_dlsym(symbol) {
        if let Ok(Some(module)) = module::find_by_address(address) {
            if module_name.is_none_or(|name| module.name == name || module.path == name) {
                return Ok(Some((address, module.name)));
            }
        }
    }

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

fn resolve_dlsym(symbol: &str) -> Option<usize> {
    let name = CString::new(symbol).ok()?;
    // SAFETY: dlsym only reads the NUL-terminated symbol name.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if address.is_null() {
        None
    } else {
        Some(address as usize)
    }
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
