//! Minimal ELF export lookup for `Module.getExportByName`.

use std::ffi::CString;
use std::fs;

use goblin::elf::Elf;
use runtime::module;
use runtime::{Error, Result};

/// Find `symbol` in `module` (or any loaded module when `None`).
/// Returns the relocated address and the module name that provided it.
pub fn find_export(module_name: Option<&str>, symbol: &str) -> Result<Option<(usize, String)>> {
    // dlsym resolves GNU IFUNCs (strlen, memcpy, ...) and symbol versions for
    // us.  Use it as the fast path, then fall back to parsing the ELF for
    // modules that are not visible in the default namespace.
    if let Some(address) = resolve_dlsym(symbol) {
        // bionic may PAC-sign dlsym results; maps lookup needs the VA bits only.
        let va = address & 0x0000_FFFF_FFFF_FFFF;
        if let Ok(Some(module)) = module::find_by_address(va) {
            if module_name.is_none_or(|name| module.name == name || module.path == name) {
                return Ok(Some((address, module.name)));
            }
        }
        if module_name.is_none() {
            return Ok(Some((address, String::new())));
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

/// One ELF symbol as shown to scripts.
#[derive(Clone, Debug)]
pub struct SymbolInfo {
    pub name: String,
    pub address: usize,
    pub kind: &'static str,
}

/// Address that can be called: prefer `dlsym` (PAC / IFUNC / PLT) when the
/// ELF actually defines `symbol`.
pub fn callable_export(
    path: &str,
    base: usize,
    module_name: &str,
    symbol: &str,
) -> Result<Option<usize>> {
    let defined = symbol_value(path, symbol, true)?;
    if defined.is_none() {
        return find_export(Some(module_name), symbol).map(|v| v.map(|(addr, _)| addr));
    }
    if let Some(address) = resolve_dlsym(symbol) {
        return Ok(Some(address));
    }
    Ok(defined.map(|value| base.wrapping_add(value)))
}

/// Resolve `symbol` in the on-disk ELF at `path` using `base` as load bias.
pub fn find_in_file(path: &str, base: usize, symbol: &str) -> Result<Option<(usize, String)>> {
    Ok(symbol_value(path, symbol, false)?.map(|value| (base.wrapping_add(value), path.to_owned())))
}

/// Look up a symbol in `.symtab` then `.dynsym`.
pub fn find_symbol(path: &str, base: usize, symbol: &str) -> Result<Option<usize>> {
    Ok(symbol_value(path, symbol, true)?.map(|value| base.wrapping_add(value)))
}

pub fn enumerate_exports(path: &str, base: usize) -> Result<Vec<SymbolInfo>> {
    list_symbols(path, base, false)
}

pub fn enumerate_symbols(path: &str, base: usize) -> Result<Vec<SymbolInfo>> {
    list_symbols(path, base, true)
}

pub fn enumerate_imports(path: &str, base: usize) -> Result<Vec<SymbolInfo>> {
    let _ = base;
    let data = fs::read(path).map_err(runtime::Error::Io)?;
    let elf =
        Elf::parse(&data).map_err(|err| runtime::Error::Parse(format!("ELF {path}: {err}")))?;
    let mut out = Vec::new();
    for sym in elf.dynsyms.iter() {
        if !sym.is_import() {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.push(SymbolInfo {
            name: name.split('@').next().unwrap_or(name).to_owned(),
            address: 0,
            kind: "function",
        });
    }
    Ok(out)
}

/// One ELF section for `Module.enumerateSections`.
#[derive(Clone, Debug)]
pub struct SectionInfo {
    pub name: String,
    pub address: usize,
    pub size: usize,
}

pub fn enumerate_sections(path: &str, base: usize) -> Result<Vec<SectionInfo>> {
    let data = fs::read(path).map_err(runtime::Error::Io)?;
    let elf =
        Elf::parse(&data).map_err(|err| runtime::Error::Parse(format!("ELF {path}: {err}")))?;
    let mut out = Vec::new();
    for section in &elf.section_headers {
        let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.push(SectionInfo {
            name: name.to_owned(),
            address: base.wrapping_add(section.sh_addr as usize),
            size: section.sh_size as usize,
        });
    }
    Ok(out)
}

pub fn enumerate_dependencies(path: &str) -> Result<Vec<String>> {
    let data = fs::read(path).map_err(runtime::Error::Io)?;
    let elf =
        Elf::parse(&data).map_err(|err| runtime::Error::Parse(format!("ELF {path}: {err}")))?;
    Ok(elf
        .libraries
        .iter()
        .map(|name| (*name).to_owned())
        .collect())
}

fn symbol_value(path: &str, symbol: &str, include_symtab: bool) -> Result<Option<usize>> {
    let data = fs::read(path).map_err(runtime::Error::Io)?;
    let elf =
        Elf::parse(&data).map_err(|err| runtime::Error::Parse(format!("ELF {path}: {err}")))?;
    let check = |syms: goblin::elf::sym::Symtab, strtab: goblin::strtab::Strtab| {
        for sym in syms.iter() {
            if sym.st_value == 0 || sym.is_import() {
                continue;
            }
            let Some(name) = strtab.get_at(sym.st_name) else {
                continue;
            };
            if name.split('@').next() == Some(symbol) {
                return Some(sym.st_value as usize);
            }
        }
        None
    };
    if let Some(value) = check(elf.dynsyms, elf.dynstrtab) {
        return Ok(Some(value));
    }
    if include_symtab {
        return Ok(check(elf.syms, elf.strtab));
    }
    Ok(None)
}

fn list_symbols(path: &str, base: usize, include_symtab: bool) -> Result<Vec<SymbolInfo>> {
    let data = fs::read(path).map_err(runtime::Error::Io)?;
    let elf =
        Elf::parse(&data).map_err(|err| runtime::Error::Parse(format!("ELF {path}: {err}")))?;
    let mut out = Vec::new();
    let mut push = |syms: goblin::elf::sym::Symtab, strtab: goblin::strtab::Strtab| {
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
            out.push(SymbolInfo {
                name: name.split('@').next().unwrap_or(name).to_owned(),
                address: base.wrapping_add(sym.st_value as usize),
                kind: if goblin::elf::sym::st_type(sym.st_info) == goblin::elf::sym::STT_FUNC {
                    "function"
                } else {
                    "variable"
                },
            });
        }
    };
    push(elf.dynsyms, elf.dynstrtab);
    if include_symtab {
        push(elf.syms, elf.strtab);
    }
    Ok(out)
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
