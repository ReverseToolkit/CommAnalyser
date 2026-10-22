//! Symbol lookup that works from a library the system linker did not load.
//!
//! `dlsym(RTLD_DEFAULT)` finds the caller's `soinfo` from the return address.
//! The agent is mapped by the in-process ELF loader, so that search returns
//! NULL even when `libc.so` and `libart.so` are in the process. `__loader_dlsym`
//! takes the caller address as an argument; an address inside `libc.so` makes
//! the lookup use the app namespace, and it resolves GNU IFUNC.

use std::ffi::CString;
use std::fs;
use std::sync::OnceLock;

use goblin::elf::Elf;

use crate::maps;
use crate::module;

/// Resolve `symbol` in the default namespace.
///
/// Tries `dlsym(RTLD_DEFAULT)` first. When the caller is not a linker-loaded
/// object, asks `__loader_dlsym` with a return address inside `libc.so`.
pub fn resolve(symbol: &str) -> Option<usize> {
    if let Some(address) = rtld_default(symbol) {
        return Some(address);
    }
    loader_dlsym(symbol)
}

fn rtld_default(symbol: &str) -> Option<usize> {
    let name = CString::new(symbol).ok()?;
    // SAFETY: `name` is a NUL-terminated C string. `dlsym` only reads it.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if address.is_null() {
        None
    } else {
        Some(address as usize)
    }
}

fn loader_dlsym(symbol: &str) -> Option<usize> {
    let function = loader_dlsym_address()?;
    let caller = libc_caller()?;
    let name = CString::new(symbol).ok()?;
    // `__loader_dlsym(handle, symbol, caller)`. Handle 0 is `RTLD_DEFAULT`.
    // SAFETY: `function` is `__loader_dlsym` in linker64. `name` outlives the
    // call. `caller` is an address mapped inside `libc.so`.
    let lookup: unsafe extern "C" fn(usize, *const libc::c_char, usize) -> usize =
        unsafe { std::mem::transmute(function) };
    let address = unsafe { lookup(0, name.as_ptr(), caller) };
    (address != 0).then_some(address)
}

fn loader_dlsym_address() -> Option<usize> {
    static LOADER: OnceLock<usize> = OnceLock::new();
    if let Some(address) = LOADER.get() {
        return (*address != 0).then_some(*address);
    }
    let address = find_loader().unwrap_or(0);
    let _ = LOADER.set(address);
    (address != 0).then_some(address)
}

fn find_loader() -> Option<usize> {
    let modules = module::enumerate().ok()?;
    let linker = modules.iter().find(|module| {
        module.name == "linker64" || module.name == "linker" || module.path.ends_with("/linker64")
    })?;
    export_value(&linker.path, linker.base, "__loader_dlsym")
}

fn libc_caller() -> Option<usize> {
    let maps = maps::read_self_maps().ok()?;
    maps.iter().find_map(|mapping| {
        let path = mapping.clean_path()?;
        (mapping.perms.exec && path.ends_with("/libc.so")).then_some(mapping.range.start)
    })
}

fn export_value(path: &str, base: usize, symbol: &str) -> Option<usize> {
    let data = fs::read(path).ok()?;
    let elf = Elf::parse(&data).ok()?;
    for sym in elf.dynsyms.iter() {
        if sym.st_value == 0 || sym.is_import() {
            continue;
        }
        let name = elf.dynstrtab.get_at(sym.st_name)?;
        if name.split('@').next() == Some(symbol) {
            return Some(base.wrapping_add(sym.st_value as usize));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::resolve;

    #[test]
    fn resolves_a_libc_function() {
        let address = resolve("strlen").expect("strlen");
        assert_ne!(address, 0);
    }
}
