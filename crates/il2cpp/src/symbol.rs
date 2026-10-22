//! Locate `il2cpp_*` in the loaded `libil2cpp.so` / `GameAssembly.so`.

use std::fs;

use goblin::elf::Elf;
use runtime::module::{self, Module};
use runtime::{Error, Result};

pub const MODULE_NAMES: &[&str] = &["libil2cpp.so", "GameAssembly.so"];

pub fn find_module() -> Result<Module> {
    let modules = module::enumerate()?;
    modules
        .into_iter()
        .find(|module| MODULE_NAMES.iter().any(|name| module.name == *name))
        .ok_or_else(|| Error::NotFound("libil2cpp.so".into()))
}

pub fn find_export(module: &Module, symbol: &str) -> Result<Option<usize>> {
    let data = fs::read(&module.path).map_err(Error::Io)?;
    let elf = Elf::parse(&data).map_err(|err| Error::Parse(format!("elf {}: {err}", module.path)))?;
    for sym in elf.dynsyms.iter() {
        if sym.st_value == 0 || sym.is_import() {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.split('@').next() == Some(symbol) {
            return Ok(Some(module.base.wrapping_add(sym.st_value as usize)));
        }
    }
    Ok(None)
}

/// Unity version string baked into the IL2CPP image, when it is present.
pub fn unity_version(module: &Module) -> Option<String> {
    let data = fs::read(&module.path).ok()?;
    find_unity_version(&String::from_utf8_lossy(&data))
}

pub fn find_unity_version(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 6 < bytes.len() {
        if let Some((version, next)) = match_version(bytes, index) {
            if plausible(&version) {
                return Some(version);
            }
            index = next;
            continue;
        }
        index += 1;
    }
    None
}

fn match_version(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let (major, mut cursor) = take_number(bytes, start)?;
    if cursor >= bytes.len() || bytes[cursor] != b'.' {
        return None;
    }
    cursor += 1;
    let (minor, next) = take_number(bytes, cursor)?;
    cursor = next;
    if cursor >= bytes.len() || bytes[cursor] != b'.' {
        return None;
    }
    cursor += 1;
    let (patch, next) = take_number(bytes, cursor)?;
    cursor = next;
    if cursor >= bytes.len() || !matches!(bytes[cursor], b'a' | b'b' | b'c' | b'f' | b'p') {
        return None;
    }
    let mark = bytes[cursor] as char;
    cursor += 1;
    let (build, next) = take_number(bytes, cursor).unwrap_or((0, cursor));
    let version = if next == cursor {
        format!("{major}.{minor}.{patch}{mark}")
    } else {
        format!("{major}.{minor}.{patch}{mark}{build}")
    };
    Some((version, next.max(cursor)))
}

fn take_number(bytes: &[u8], start: usize) -> Option<(u32, usize)> {
    let mut cursor = start;
    let mut value: u32 = 0;
    let mut digits = 0;
    while cursor < bytes.len() && bytes[cursor].is_ascii_digit() && digits < 6 {
        value = value.saturating_mul(10).saturating_add((bytes[cursor] - b'0') as u32);
        cursor += 1;
        digits += 1;
    }
    (digits > 0).then_some((value, cursor))
}

fn plausible(version: &str) -> bool {
    let Some(major) = version.split('.').next().and_then(|text| text.parse::<u32>().ok()) else {
        return false;
    };
    major == 5 || (2017..=2035).contains(&major) || (6000..=6999).contains(&major)
}
