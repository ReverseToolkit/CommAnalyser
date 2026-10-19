//! In-process ELF shared-object mapper (自定义linker).
//!
//! Maps `PT_LOAD`, applies RELATIVE / GLOB_DAT / JUMP_SLOT / IRELATIVE, runs
//! `DT_INIT` / `init_array`, and looks up exports.  Imports are resolved by a
//! caller-supplied `dlsym`-style callback so GNU IFUNC and PAC addresses come
//! from the already-loaded libc, not from ELF `st_value`.

use std::collections::HashMap;

use goblin::elf::dynamic::{DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_GNU_RELRO, PT_LOAD};
use goblin::elf::reloc::{
    Reloc, R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_IRELATIVE, R_AARCH64_JUMP_SLOT,
    R_AARCH64_RELATIVE, R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_IRELATIVE, R_X86_64_JUMP_SLOT,
    R_X86_64_RELATIVE,
};
use goblin::elf::sym::{STB_WEAK, STT_GNU_IFUNC};
use goblin::elf::Elf;
use runtime::{Error, Result};

const PROT_READ: i32 = libc::PROT_READ;
const PROT_WRITE: i32 = libc::PROT_WRITE;
const PROT_EXEC: i32 = libc::PROT_EXEC;

/// AArch64 BTI page flag (`PROT_BTI`). Ignored on other architectures.
#[cfg(target_arch = "aarch64")]
const PROT_BTI: i32 = 0x10;
#[cfg(not(target_arch = "aarch64"))]
const PROT_BTI: i32 = 0;

/// One `PT_LOAD` segment.
#[derive(Clone, Debug)]
pub struct Segment {
    pub vaddr: u64,
    pub memsz: u64,
    pub filesz: u64,
    pub offset: u64,
    pub flags: u32,
}

/// Relocation the mapper understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocKind {
    Relative,
    Abs64,
    GlobDat,
    JumpSlot,
    Irelative,
}

/// One relocation against the load image.
#[derive(Clone, Debug)]
pub struct RelocOp {
    pub offset: u64,
    pub kind: RelocKind,
    pub addend: i64,
    pub symbol: Option<String>,
    pub ifunc: bool,
    pub weak: bool,
}

/// Parsed ELF load plan.  Host tests and the remote injector share this.
#[derive(Clone, Debug)]
pub struct Image {
    pub load_start: u64,
    pub load_end: u64,
    pub segments: Vec<Segment>,
    pub relocs: Vec<RelocOp>,
    pub symbols: HashMap<String, u64>,
    pub init: Option<u64>,
    pub init_array: Option<(u64, usize)>,
    pub relro: Option<(u64, u64)>,
}

impl Image {
    /// Parse a shared object into a load plan.
    ///
    /// # Errors
    /// Returns [`Error::Parse`] when the bytes are not a dynamic ELF, have no
    /// `PT_LOAD`, or use a relocation type this mapper does not apply.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let elf = Elf::parse(bytes).map_err(|err| Error::Parse(format!("ELF: {err}")))?;
        if elf.header.e_type != goblin::elf::header::ET_DYN
            && elf.header.e_type != goblin::elf::header::ET_EXEC
        {
            return Err(Error::Parse("ELF is not ET_DYN/ET_EXEC".into()));
        }

        let mut segments = Vec::new();
        let mut load_start = u64::MAX;
        let mut load_end = 0u64;
        let mut relro = None;
        for ph in &elf.program_headers {
            if ph.p_type == PT_LOAD {
                if ph.p_memsz == 0 {
                    continue;
                }
                load_start = load_start.min(ph.p_vaddr);
                load_end = load_end.max(ph.p_vaddr.saturating_add(ph.p_memsz));
                segments.push(Segment {
                    vaddr: ph.p_vaddr,
                    memsz: ph.p_memsz,
                    filesz: ph.p_filesz.min(ph.p_memsz),
                    offset: ph.p_offset,
                    flags: ph.p_flags,
                });
            } else if ph.p_type == PT_GNU_RELRO {
                relro = Some((ph.p_vaddr, ph.p_memsz));
            }
        }
        if segments.is_empty() || load_start == u64::MAX {
            return Err(Error::Parse("ELF has no PT_LOAD".into()));
        }

        let mut symbols = HashMap::new();
        let mut dyn_index: Vec<Option<(String, bool, bool, u64)>> =
            vec![None; elf.dynsyms.len().max(1)];
        for (index, sym) in elf.dynsyms.iter().enumerate() {
            let name = elf
                .dynstrtab
                .get_at(sym.st_name)
                .unwrap_or("")
                .split('@')
                .next()
                .unwrap_or("")
                .to_owned();
            let ifunc = sym.st_type() == STT_GNU_IFUNC;
            let weak = sym.st_bind() == STB_WEAK;
            if !name.is_empty() && !sym.is_import() && sym.st_value != 0 {
                symbols.insert(name.clone(), sym.st_value);
            }
            dyn_index[index] = Some((name, ifunc, weak, sym.st_value));
        }

        let mut relocs = Vec::new();
        for reloc in elf.dynrelas.iter().chain(elf.pltrelocs.iter()) {
            relocs.push(reloc_op(&reloc, &dyn_index)?);
        }

        let mut init = None;
        let mut init_array = None;
        if let Some(dynamic) = elf.dynamic.as_ref() {
            let mut array = None;
            let mut array_sz = None;
            for entry in &dynamic.dyns {
                match entry.d_tag {
                    DT_INIT => init = Some(entry.d_val),
                    DT_INIT_ARRAY => array = Some(entry.d_val),
                    DT_INIT_ARRAYSZ => array_sz = Some(entry.d_val),
                    _ => {}
                }
            }
            if let (Some(addr), Some(bytes)) = (array, array_sz) {
                let count = (bytes / 8) as usize;
                if count > 0 {
                    init_array = Some((addr, count));
                }
            }
        }

        Ok(Self {
            load_start,
            load_end,
            segments,
            relocs,
            symbols,
            init,
            init_array,
            relro,
        })
    }

    /// Byte span that must be mapped, rounded to `page`.
    pub fn span(&self, page: usize) -> usize {
        let page = page.max(1);
        let start = align_down(self.load_start, page as u64);
        let end = align_up(self.load_end, page as u64);
        end.saturating_sub(start) as usize
    }

    /// File-relative virtual address of an exported symbol.
    pub fn symbol_value(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }
}

fn reloc_op(reloc: &Reloc, dyn_index: &[Option<(String, bool, bool, u64)>]) -> Result<RelocOp> {
    let kind = match reloc.r_type {
        R_AARCH64_RELATIVE | R_X86_64_RELATIVE => RelocKind::Relative,
        R_AARCH64_ABS64 | R_X86_64_64 => RelocKind::Abs64,
        R_AARCH64_GLOB_DAT | R_X86_64_GLOB_DAT => RelocKind::GlobDat,
        R_AARCH64_JUMP_SLOT | R_X86_64_JUMP_SLOT => RelocKind::JumpSlot,
        R_AARCH64_IRELATIVE | R_X86_64_IRELATIVE => RelocKind::Irelative,
        other => return Err(Error::Parse(format!("unsupported relocation type {other}"))),
    };
    let (symbol, ifunc, weak) = dyn_index
        .get(reloc.r_sym)
        .and_then(|entry| entry.as_ref())
        .map(|(name, ifunc, weak, _)| {
            if name.is_empty() {
                (None, *ifunc, *weak)
            } else {
                (Some(name.clone()), *ifunc, *weak)
            }
        })
        .unwrap_or((None, false, false));
    Ok(RelocOp {
        offset: reloc.r_offset,
        kind,
        addend: reloc.r_addend.unwrap_or(0),
        symbol,
        ifunc,
        weak,
    })
}

/// A mapped shared object in this process.
pub struct MappedLibrary {
    base: usize,
    size: usize,
    load_start: u64,
    symbols: HashMap<String, u64>,
}

impl MappedLibrary {
    /// Map `bytes` into this process and run constructors.
    ///
    /// `resolve` is called for each imported symbol (typically `dlsym`).
    ///
    /// # Errors
    /// Returns parse, mmap, relocation, or constructor errors.
    pub fn load(bytes: &[u8], mut resolve: impl FnMut(&str) -> Result<u64>) -> Result<Self> {
        let image = Image::parse(bytes)?;
        let page = runtime::process::page_size();
        let size = image.span(page);
        let map = map_anonymous(size)?;
        let load_start = align_down(image.load_start, page as u64);
        copy_segments(map, load_start, &image, bytes)?;
        apply_relocs(
            map,
            load_start,
            &image,
            &mut resolve,
            |addr, value| unsafe {
                (addr as *mut u64).write_unaligned(value);
                Ok(())
            },
            |fn_addr| unsafe {
                let resolver: unsafe extern "C" fn() -> u64 = std::mem::transmute(fn_addr);
                Ok(resolver())
            },
        )?;
        protect_segments(map, load_start, page, &image)?;
        run_local_inits(map, load_start, &image)?;
        Ok(Self {
            base: map,
            size,
            load_start,
            symbols: image.symbols,
        })
    }

    pub fn base(&self) -> usize {
        self.base
    }

    /// Absolute address of an exported symbol.
    pub fn symbol(&self, name: &str) -> Option<usize> {
        let value = self.symbols.get(name)?;
        Some(self.base.wrapping_add((*value - self.load_start) as usize))
    }
}

impl Drop for MappedLibrary {
    fn drop(&mut self) {
        if self.base != 0 && self.size != 0 {
            unsafe {
                libc::munmap(self.base as *mut libc::c_void, self.size);
            }
        }
    }
}

/// Copy `PT_LOAD` file bytes into an already-mapped window at `map`.
pub fn copy_segments(map: usize, load_start: u64, image: &Image, bytes: &[u8]) -> Result<()> {
    for segment in &image.segments {
        let dest = map.wrapping_add((segment.vaddr - load_start) as usize);
        let filesz = usize::try_from(segment.filesz)
            .map_err(|_| Error::Parse("PT_LOAD filesz does not fit".into()))?;
        if filesz == 0 {
            continue;
        }
        let start = usize::try_from(segment.offset)
            .map_err(|_| Error::Parse("PT_LOAD offset does not fit".into()))?;
        let end = start
            .checked_add(filesz)
            .ok_or_else(|| Error::Parse("PT_LOAD file range overflow".into()))?;
        let src = bytes
            .get(start..end)
            .ok_or_else(|| Error::Parse("PT_LOAD truncated".into()))?;
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dest as *mut u8, filesz);
        }
    }
    Ok(())
}

/// Apply parsed relocations into the mapped window.
///
/// `write_u64` stores one slot. `call_ifunc` runs an IFUNC/IRELATIVE resolver
/// at `fn_addr` and returns the callable address.
pub fn apply_relocs(
    map: usize,
    load_start: u64,
    image: &Image,
    resolve: &mut impl FnMut(&str) -> Result<u64>,
    mut write_u64: impl FnMut(usize, u64) -> Result<()>,
    mut call_ifunc: impl FnMut(u64) -> Result<u64>,
) -> Result<()> {
    let bias = map as u64;
    let mut cache: HashMap<String, u64> = HashMap::new();
    for reloc in &image.relocs {
        let slot = map.wrapping_add((reloc.offset - load_start) as usize);
        let value = match reloc.kind {
            RelocKind::Relative | RelocKind::Irelative => {
                let raw = bias.wrapping_add(reloc.addend as u64);
                if reloc.kind == RelocKind::Irelative {
                    call_ifunc(raw)?
                } else {
                    raw
                }
            }
            RelocKind::Abs64 | RelocKind::GlobDat | RelocKind::JumpSlot => {
                let name = reloc.symbol.as_deref().unwrap_or("");
                if name.is_empty() {
                    if reloc.weak {
                        0
                    } else {
                        bias.wrapping_add(reloc.addend as u64)
                    }
                } else if let Some(&defined) = image.symbols.get(name) {
                    let addr = bias
                        .wrapping_add(defined.wrapping_sub(load_start))
                        .wrapping_add(reloc.addend as u64);
                    if reloc.ifunc {
                        call_ifunc(addr)?
                    } else {
                        addr
                    }
                } else if let Some(&hit) = cache.get(name) {
                    hit.wrapping_add(reloc.addend as u64)
                } else {
                    match resolve(name) {
                        Ok(addr) => {
                            cache.insert(name.to_owned(), addr);
                            addr.wrapping_add(reloc.addend as u64)
                        }
                        Err(err) if reloc.weak => {
                            let _ = err;
                            0
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
        };
        write_u64(slot, value)?;
    }
    Ok(())
}

/// Absolute addresses of `DT_INIT` / `init_array` after relocation.
pub fn constructor_addrs(map: usize, load_start: u64, image: &Image) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    if let Some(init) = image.init {
        if init != 0 {
            out.push(map as u64 + init - load_start);
        }
    }
    if let Some((addr, count)) = image.init_array {
        let start = map.wrapping_add((addr - load_start) as usize);
        for index in 0..count {
            let slot = start + index * 8;
            let value = unsafe { (slot as *const u64).read_unaligned() };
            if value != 0 && value != u64::MAX {
                out.push(value);
            }
        }
    }
    Ok(out)
}

fn run_local_inits(map: usize, load_start: u64, image: &Image) -> Result<()> {
    for addr in constructor_addrs(map, load_start, image)? {
        unsafe {
            let init: unsafe extern "C" fn() = std::mem::transmute(addr as usize);
            init();
        }
    }
    Ok(())
}

/// Convert `PF_*` to `PROT_*`, adding BTI on executable AArch64 pages.
pub fn prot_from_flags(flags: u32, bti: bool) -> i32 {
    let mut prot = 0;
    if flags & PF_R != 0 {
        prot |= PROT_READ;
    }
    if flags & PF_W != 0 {
        prot |= PROT_WRITE;
    }
    if flags & PF_X != 0 {
        prot |= PROT_EXEC;
        if bti {
            prot |= PROT_BTI;
        }
    }
    if prot == 0 {
        prot = PROT_READ;
    }
    prot
}

fn protect_segments(map: usize, load_start: u64, page: usize, image: &Image) -> Result<()> {
    let bti = cfg!(target_arch = "aarch64");
    for segment in &image.segments {
        let start = align_down(map as u64 + segment.vaddr - load_start, page as u64) as usize;
        let end = align_up(
            map as u64 + segment.vaddr + segment.memsz - load_start,
            page as u64,
        ) as usize;
        let len = end.saturating_sub(start);
        if len == 0 {
            continue;
        }
        let prot = prot_from_flags(segment.flags, bti);
        if unsafe { libc::mprotect(start as *mut libc::c_void, len, prot) } != 0 {
            #[cfg(target_arch = "aarch64")]
            {
                let fallback = prot & !PROT_BTI;
                if fallback != prot
                    && unsafe { libc::mprotect(start as *mut libc::c_void, len, fallback) } == 0
                {
                    continue;
                }
            }
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }
    if let Some((vaddr, memsz)) = image.relro {
        let start = align_down(map as u64 + vaddr - load_start, page as u64) as usize;
        let end = align_up(map as u64 + vaddr + memsz - load_start, page as u64) as usize;
        let len = end.saturating_sub(start);
        if len > 0 {
            let _ = unsafe { libc::mprotect(start as *mut libc::c_void, len, PROT_READ) };
        }
    }
    Ok(())
}

fn map_anonymous(size: usize) -> Result<usize> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(ptr as usize)
}

pub fn align_down(value: u64, page: u64) -> u64 {
    value & !(page - 1)
}

pub fn align_up(value: u64, page: u64) -> u64 {
    (value + page - 1) & !(page - 1)
}

/// `dlsym(RTLD_DEFAULT, name)` for local loads.
pub fn dlsym_default(name: &str) -> Result<u64> {
    let c_name = std::ffi::CString::new(name).map_err(|_| Error::Parse("bad symbol".into()))?;
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c_name.as_ptr()) };
    if ptr.is_null() {
        return Err(Error::NotFound(format!("dlsym({name})")));
    }
    Ok(ptr as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Command;

    fn compile_plugin() -> PathBuf {
        let dir = std::env::temp_dir().join("commanalyser-linker-fixture");
        let _ = std::fs::create_dir_all(&dir);
        let src = dir.join("plugin.c");
        let so = dir.join("plugin.so");
        std::fs::File::create(&src)
            .unwrap()
            .write_all(
                br#"
                #include <string.h>
                static int bias = 40;
                int plugin_add(int a, int b) { return a + b + bias; }
                int plugin_len(const char *s) { return (int)strlen(s); }
                "#,
            )
            .unwrap();
        let status = Command::new("cc")
            .args(["-shared", "-fPIC", "-O0", "-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .expect("cc");
        assert!(status.success(), "cc failed: {status}");
        so
    }

    #[test]
    fn loads_fixture_and_calls_exports() {
        let so = compile_plugin();
        let bytes = std::fs::read(&so).unwrap();
        let image = Image::parse(&bytes).unwrap();
        assert!(
            image
                .relocs
                .iter()
                .any(|reloc| reloc.kind == RelocKind::Relative),
            "fixture should contain at least one RELATIVE reloc"
        );
        assert!(
            image.symbol_value("plugin_add").is_some(),
            "plugin_add must be exported"
        );

        let mapped = MappedLibrary::load(&bytes, dlsym_default).unwrap();
        let add = mapped.symbol("plugin_add").expect("plugin_add");
        let len = mapped.symbol("plugin_len").expect("plugin_len");
        let add: extern "C" fn(i32, i32) -> i32 = unsafe { std::mem::transmute(add) };
        let len: extern "C" fn(*const u8) -> i32 = unsafe { std::mem::transmute(len) };
        assert_eq!(add(2, 3), 45);
        assert_eq!(len(c"abcd".as_ptr().cast()), 4);
    }
}
