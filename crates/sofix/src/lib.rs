//! Repair an AArch64 ELF64 image dumped from a running process.
//!
//! The dump is a contiguous copy of the loaded module: file offset equals
//! virtual address, and `load_bias` is the runtime address of virtual
//! address 0. Relative relocations and `DT_RELR` slots are turned back into
//! file offsets by subtracting that bias. Imported `GLOB_DAT` and
//! `JUMP_SLOT` slots point at a stub past the load image, indexed by the
//! undefined-symbol order in `.dynsym`.

use std::fs;

use runtime::module::{self, CapturedImage};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_FINI_ARRAY: u32 = 15;
const SHT_GNU_HASH: u32 = 0x6fff_fff6;
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_FINI: i64 = 13;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_PLTRELSZ: i64 = 2;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_RELRENT: i64 = 37;
const R_AARCH64_GLOB_DAT: u32 = 1025;
const R_AARCH64_JUMP_SLOT: u32 = 1026;
const R_AARCH64_RELATIVE: u32 = 1027;
const PHDR_SIZE: usize = 56;
const DYN_SIZE: usize = 16;
const SYM_SIZE: usize = 24;
const RELA_SIZE: usize = 24;
const SHDR_SIZE: usize = 64;

/// One dumped mapping, with offsets relative to the image start.
#[derive(Clone, Copy, Debug)]
pub struct Perm {
    pub offset: u64,
    pub len: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

/// Result of writing a repaired image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DumpReport {
    pub base: u64,
    pub size: u64,
    pub path: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not an ELF image")]
    NotElf,
    #[error("only AArch64 ELF64 is supported")]
    UnsupportedMachine,
    #[error("truncated ELF")]
    Truncated,
    #[error("no PT_DYNAMIC")]
    NoDynamic,
    #[error("cannot size the dynamic symbol table")]
    NoSymbolCount,
    #[error("module not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Capture(String),
}

pub type Result<T> = std::result::Result<T, Error>;

struct Ehdr {
    phoff: u64,
    phnum: u16,
}

struct Phdr {
    ty: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    memsz: u64,
    align: u64,
}

struct DynView {
    symtab: u64,
    syment: u64,
    strtab: u64,
    strsz: u64,
    hash: u64,
    gnu_hash: u64,
    rela: u64,
    relasz: u64,
    jmprel: u64,
    pltrelsz: u64,
    pltrel: i64,
    relr: u64,
    relrsz: u64,
    init_array: u64,
    init_arraysz: u64,
    fini_array: u64,
    fini_arraysz: u64,
    init: u64,
    fini: u64,
    dynamic: u64,
    dynamic_size: u64,
    nsyms: u64,
}

#[derive(Clone)]
struct Section {
    name: &'static str,
    ty: u32,
    flags: u64,
    addr: u64,
    size: u64,
    link: Link,
    align: u64,
    entsize: u64,
}

#[derive(Clone, Copy)]
enum Link {
    None,
    Dynsym,
    Dynstr,
}

struct Import {
    name: String,
}

/// Repair `image` in place-as-a-copy. `load_bias` is the runtime address of
/// virtual address 0. `perms` fills `PT_LOAD` flags when the dumped header
/// left them zero.
pub fn repair(image: &[u8], load_bias: u64, perms: &[Perm]) -> Result<Vec<u8>> {
    let ehdr = parse_ehdr(image)?;
    let mut phdrs = parse_phdrs(image, &ehdr)?;
    let load_len = image.len() as u64;
    fix_phdrs(&mut phdrs, load_len, perms);
    let mut out = image.to_vec();
    write_phdrs(&mut out, ehdr.phoff, &phdrs)?;
    let dynamic = dynamic_span(&phdrs)?;
    let view = parse_dynamic(&out, dynamic.0, dynamic.1)?;
    let imports = collect_imports(&out, &view)?;
    let stub_base = out.len() as u64;
    out.resize(out.len() + imports.len() * 8, 0);
    unrelocate(&mut out, load_bias, &view, &imports, stub_base)?;
    let sections = sections_for(&view, load_len);
    append_sections(&mut out, &sections)?;
    Ok(out)
}

/// Dump `name` from this process and write the repaired ELF.
pub fn dump_here(name: &str, path: &str) -> Result<DumpReport> {
    let captured = module::capture_here(name).map_err(capture_err)?;
    write_captured(&captured, path)
}

/// Dump `name` from `pid` via `/proc/<pid>/mem` and write the repaired ELF.
pub fn dump_pid(pid: u32, name: &str, path: &str) -> Result<DumpReport> {
    let captured = module::capture_pid(pid, name).map_err(capture_err)?;
    write_captured(&captured, path)
}

fn capture_err(err: runtime::Error) -> Error {
    match err {
        runtime::Error::NotFound(name) => Error::NotFound(name),
        other => Error::Capture(other.to_string()),
    }
}

fn write_captured(captured: &CapturedImage, path: &str) -> Result<DumpReport> {
    let perms = captured
        .perms
        .iter()
        .map(|perm| Perm {
            offset: perm.offset as u64,
            len: perm.len as u64,
            read: perm.read,
            write: perm.write,
            exec: perm.exec,
        })
        .collect::<Vec<_>>();
    let fixed = repair(&captured.bytes, captured.base as u64, &perms)?;
    fs::write(path, &fixed)?;
    Ok(DumpReport {
        base: captured.base as u64,
        size: u64::try_from(fixed.len()).unwrap_or(u64::MAX),
        path: path.to_owned(),
    })
}

fn parse_ehdr(image: &[u8]) -> Result<Ehdr> {
    if image.len() < 64 || image[0..4] != ELF_MAGIC {
        return Err(Error::NotElf);
    }
    if image[4] != ELFCLASS64 || image[5] != ELFDATA2LSB {
        return Err(Error::UnsupportedMachine);
    }
    if read_u16(image, 18)? != EM_AARCH64 {
        return Err(Error::UnsupportedMachine);
    }
    let phentsize = read_u16(image, 54)?;
    if phentsize as usize != PHDR_SIZE {
        return Err(Error::Truncated);
    }
    Ok(Ehdr {
        phoff: read_u64(image, 32)?,
        phnum: read_u16(image, 56)?,
    })
}

fn parse_phdrs(image: &[u8], ehdr: &Ehdr) -> Result<Vec<Phdr>> {
    let mut phdrs = Vec::with_capacity(ehdr.phnum as usize);
    for index in 0..ehdr.phnum as u64 {
        let off = ehdr
            .phoff
            .checked_add(index * PHDR_SIZE as u64)
            .ok_or(Error::Truncated)?;
        let off = need(image, off, PHDR_SIZE)?;
        phdrs.push(Phdr {
            ty: read_u32(image, off)?,
            flags: read_u32(image, off + 4)?,
            offset: read_u64(image, off + 8)?,
            vaddr: read_u64(image, off + 16)?,
            memsz: read_u64(image, off + 40)?,
            align: read_u64(image, off + 48)?,
        });
    }
    if !phdrs.iter().any(|phdr| phdr.ty == PT_LOAD) {
        return Err(Error::Truncated);
    }
    Ok(phdrs)
}

fn fix_phdrs(phdrs: &mut [Phdr], load_len: u64, perms: &[Perm]) {
    let mut loads: Vec<usize> = phdrs
        .iter()
        .enumerate()
        .filter(|(_, phdr)| phdr.ty == PT_LOAD)
        .map(|(index, _)| index)
        .collect();
    loads.sort_by_key(|&index| phdrs[index].vaddr);
    for (place, &index) in loads.iter().enumerate() {
        let vaddr = phdrs[index].vaddr;
        let memsz = if let Some(&next) = loads.get(place + 1) {
            phdrs[next].vaddr.saturating_sub(vaddr)
        } else {
            load_len.saturating_sub(vaddr)
        };
        phdrs[index].memsz = memsz;
        phdrs[index].offset = vaddr;
        if phdrs[index].flags == 0 {
            if let Some(flags) = flags_from_perms(vaddr, memsz, perms) {
                phdrs[index].flags = flags;
            }
        }
    }
    for phdr in phdrs.iter_mut() {
        phdr.offset = phdr.vaddr;
    }
}

fn flags_from_perms(vaddr: u64, memsz: u64, perms: &[Perm]) -> Option<u32> {
    let end = vaddr.saturating_add(memsz);
    let mut flags = 0u32;
    for perm in perms {
        let perm_end = perm.offset.saturating_add(perm.len);
        if perm.offset < end && perm_end > vaddr {
            if perm.read {
                flags |= PF_R;
            }
            if perm.write {
                flags |= PF_W;
            }
            if perm.exec {
                flags |= PF_X;
            }
        }
    }
    (flags != 0).then_some(flags)
}

fn write_phdrs(image: &mut [u8], phoff: u64, phdrs: &[Phdr]) -> Result<()> {
    for (index, phdr) in phdrs.iter().enumerate() {
        let off = need(image, phoff + index as u64 * PHDR_SIZE as u64, PHDR_SIZE)?;
        write_u32(image, off, phdr.ty)?;
        write_u32(image, off + 4, phdr.flags)?;
        write_u64(image, off + 8, phdr.offset)?;
        write_u64(image, off + 16, phdr.vaddr)?;
        write_u64(image, off + 24, phdr.vaddr)?;
        write_u64(image, off + 32, phdr.memsz)?;
        write_u64(image, off + 40, phdr.memsz)?;
        write_u64(image, off + 48, phdr.align)?;
    }
    Ok(())
}

fn dynamic_span(phdrs: &[Phdr]) -> Result<(u64, u64)> {
    phdrs
        .iter()
        .find(|phdr| phdr.ty == PT_DYNAMIC)
        .map(|phdr| (phdr.vaddr, phdr.memsz))
        .ok_or(Error::NoDynamic)
}

fn parse_dynamic(image: &[u8], offset: u64, size: u64) -> Result<DynView> {
    let mut view = DynView {
        symtab: 0,
        syment: SYM_SIZE as u64,
        strtab: 0,
        strsz: 0,
        hash: 0,
        gnu_hash: 0,
        rela: 0,
        relasz: 0,
        jmprel: 0,
        pltrelsz: 0,
        pltrel: DT_RELA,
        relr: 0,
        relrsz: 0,
        init_array: 0,
        init_arraysz: 0,
        fini_array: 0,
        fini_arraysz: 0,
        init: 0,
        fini: 0,
        dynamic: offset,
        dynamic_size: size,
        nsyms: 0,
    };
    let count = size as usize / DYN_SIZE;
    for index in 0..count.min(4096) {
        let at = offset as usize + index * DYN_SIZE;
        let tag = read_i64(image, at)?;
        let val = read_u64(image, at + 8)?;
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_HASH => view.hash = val,
            DT_STRTAB => view.strtab = val,
            DT_SYMTAB => view.symtab = val,
            DT_RELA => view.rela = val,
            DT_RELASZ => view.relasz = val,
            DT_STRSZ => view.strsz = val,
            DT_SYMENT => view.syment = val,
            DT_INIT => view.init = val,
            DT_FINI => view.fini = val,
            DT_PLTREL => view.pltrel = val as i64,
            DT_JMPREL => view.jmprel = val,
            DT_PLTRELSZ => view.pltrelsz = val,
            DT_INIT_ARRAY => view.init_array = val,
            DT_FINI_ARRAY => view.fini_array = val,
            DT_INIT_ARRAYSZ => view.init_arraysz = val,
            DT_FINI_ARRAYSZ => view.fini_arraysz = val,
            DT_GNU_HASH => view.gnu_hash = val,
            DT_RELR => view.relr = val,
            DT_RELRSZ => view.relrsz = val,
            DT_RELRENT if val != 8 => return Err(Error::Truncated),
            _ => {}
        }
    }
    if view.syment != SYM_SIZE as u64 {
        return Err(Error::Truncated);
    }
    view.nsyms = symbol_count(image, &view)?;
    Ok(view)
}

fn symbol_count(image: &[u8], view: &DynView) -> Result<u64> {
    if view.hash != 0 {
        let off = need(image, view.hash, 8)?;
        return Ok(u64::from(read_u32(image, off + 4)?));
    }
    if view.gnu_hash != 0 {
        return gnu_symbol_count(image, view.gnu_hash);
    }
    Err(Error::NoSymbolCount)
}

fn gnu_symbol_count(image: &[u8], hash: u64) -> Result<u64> {
    let off = need(image, hash, 16)?;
    let nbuckets = read_u32(image, off)?;
    let symoffset = read_u32(image, off + 4)?;
    let bloom_size = read_u32(image, off + 8)?;
    let buckets = off + 16 + bloom_size as usize * 8;
    let mut max_sym = 0u32;
    for index in 0..nbuckets {
        let bucket = read_u32(image, buckets + index as usize * 4)?;
        max_sym = max_sym.max(bucket);
    }
    if max_sym < symoffset {
        return Ok(u64::from(symoffset));
    }
    let chains = buckets + nbuckets as usize * 4;
    for symbol in (max_sym..).take(1_000_000) {
        let chain = read_u32(image, chains + (symbol - symoffset) as usize * 4)?;
        if chain & 1 == 1 {
            return Ok(u64::from(symbol) + 1);
        }
    }
    Err(Error::NoSymbolCount)
}

fn collect_imports(image: &[u8], view: &DynView) -> Result<Vec<Import>> {
    let mut imports = Vec::new();
    let mut started = false;
    for index in 0..view.nsyms {
        let sym = view.symtab + index * SYM_SIZE as u64;
        let name_off = read_u32(image, need(image, sym, SYM_SIZE)?)?;
        let value = read_u64(image, need(image, sym + 8, 8)?)?;
        if name_off == 0 && !started {
            continue;
        }
        started = true;
        if name_off != 0 && value != 0 {
            break;
        }
        imports.push(Import {
            name: read_cstr(image, view.strtab, view.strsz, name_off)?,
        });
    }
    Ok(imports)
}

fn unrelocate(
    image: &mut [u8],
    load_bias: u64,
    view: &DynView,
    imports: &[Import],
    stub_base: u64,
) -> Result<()> {
    if view.rela != 0 {
        apply_rela(image, view, imports, stub_base, view.rela, view.relasz)?;
    }
    if view.jmprel != 0 && view.pltrel == DT_RELA {
        apply_rela(image, view, imports, stub_base, view.jmprel, view.pltrelsz)?;
    }
    if view.relr != 0 {
        apply_relr(image, load_bias, view.relr, view.relrsz)?;
    }
    Ok(())
}

fn apply_rela(
    image: &mut [u8],
    view: &DynView,
    imports: &[Import],
    stub_base: u64,
    table: u64,
    size: u64,
) -> Result<()> {
    let count = size / RELA_SIZE as u64;
    for index in 0..count {
        let at = table + index * RELA_SIZE as u64;
        let at_off = need(image, at, RELA_SIZE)?;
        let offset = read_u64(image, at_off)?;
        let info = read_u64(image, at_off + 8)?;
        let addend = read_u64(image, at_off + 16)?;
        let ty = info as u32;
        let sym = (info >> 32) as u32;
        match ty {
            // The rela addend is the original file word. The in-memory word is
            // load_bias + addend, unless the process later tagged or rewrote it.
            R_AARCH64_RELATIVE => write_u64_at(image, offset, addend)?,
            R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
                let target = import_target(image, view, imports, stub_base, sym)?;
                write_u64_at(image, offset, target)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn import_target(
    image: &[u8],
    view: &DynView,
    imports: &[Import],
    stub_base: u64,
    sym: u32,
) -> Result<u64> {
    let sym_off = view
        .symtab
        .checked_add(u64::from(sym) * SYM_SIZE as u64)
        .ok_or(Error::Truncated)?;
    let name_off = read_u32(image, need(image, sym_off, SYM_SIZE)?)?;
    let value = read_u64(image, need(image, sym_off + 8, 8)?)?;
    if value != 0 {
        return Ok(value);
    }
    let name = read_cstr(image, view.strtab, view.strsz, name_off)?;
    match imports.iter().position(|import| import.name == name) {
        Some(index) => Ok(stub_base + index as u64 * 8),
        None => Ok(0),
    }
}

fn apply_relr(image: &mut [u8], load_bias: u64, table: u64, size: u64) -> Result<()> {
    let count = size / 8;
    let mut where_off: Option<u64> = None;
    for index in 0..count {
        let entry = read_u64(image, need(image, table + index * 8, 8)?)?;
        if entry & 1 == 0 {
            subtract_bias(image, entry, load_bias)?;
            where_off = Some(entry.saturating_add(8));
        } else if let Some(start) = where_off {
            let mut addr = start;
            let mut mask = entry;
            while {
                mask >>= 1;
                mask != 0
            } {
                if mask & 1 == 1 {
                    subtract_bias(image, addr, load_bias)?;
                }
                addr = addr.saturating_add(8);
            }
            where_off = Some(start.saturating_add(63 * 8));
        }
    }
    Ok(())
}

fn subtract_bias(image: &mut [u8], vaddr: u64, load_bias: u64) -> Result<()> {
    let off = need(image, vaddr, 8)?;
    let value = read_u64(image, off)?;
    if value >= load_bias {
        write_u64(image, off, value.wrapping_sub(load_bias))?;
    }
    Ok(())
}

fn write_u64_at(image: &mut [u8], vaddr: u64, value: u64) -> Result<()> {
    let off = need(image, vaddr, 8)?;
    write_u64(image, off, value)
}

fn sections_for(view: &DynView, load_len: u64) -> Vec<Section> {
    let mut sections = vec![Section {
        name: "",
        ty: 0,
        flags: 0,
        addr: 0,
        size: 0,
        link: Link::None,
        align: 0,
        entsize: 0,
    }];
    if view.symtab != 0 {
        sections.push(Section {
            name: ".dynsym",
            ty: SHT_DYNSYM,
            flags: SHF_ALLOC,
            addr: view.symtab,
            size: view.nsyms * SYM_SIZE as u64,
            link: Link::Dynstr,
            align: 8,
            entsize: SYM_SIZE as u64,
        });
    }
    if view.strtab != 0 {
        sections.push(Section {
            name: ".dynstr",
            ty: SHT_STRTAB,
            flags: SHF_ALLOC,
            addr: view.strtab,
            size: view.strsz,
            link: Link::None,
            align: 1,
            entsize: 0,
        });
    }
    if view.hash != 0 {
        sections.push(Section {
            name: ".hash",
            ty: SHT_HASH,
            flags: SHF_ALLOC,
            addr: view.hash,
            size: 0,
            link: Link::Dynsym,
            align: 4,
            entsize: 4,
        });
    }
    if view.gnu_hash != 0 {
        sections.push(Section {
            name: ".gnu.hash",
            ty: SHT_GNU_HASH,
            flags: SHF_ALLOC,
            addr: view.gnu_hash,
            size: 0,
            link: Link::Dynsym,
            align: 8,
            entsize: 0,
        });
    }
    if view.rela != 0 {
        sections.push(Section {
            name: ".rela.dyn",
            ty: SHT_RELA,
            flags: SHF_ALLOC,
            addr: view.rela,
            size: view.relasz,
            link: Link::Dynsym,
            align: 8,
            entsize: RELA_SIZE as u64,
        });
    }
    if view.jmprel != 0 {
        sections.push(Section {
            name: ".rela.plt",
            ty: SHT_RELA,
            flags: SHF_ALLOC,
            addr: view.jmprel,
            size: view.pltrelsz,
            link: Link::Dynsym,
            align: 8,
            entsize: RELA_SIZE as u64,
        });
    }
    if view.relr != 0 {
        sections.push(Section {
            name: ".relr.dyn",
            ty: SHT_PROGBITS,
            flags: SHF_ALLOC,
            addr: view.relr,
            size: view.relrsz,
            link: Link::None,
            align: 8,
            entsize: 8,
        });
    }
    if view.init_array != 0 {
        sections.push(Section {
            name: ".init_array",
            ty: SHT_INIT_ARRAY,
            flags: SHF_ALLOC | SHF_WRITE,
            addr: view.init_array,
            size: view.init_arraysz,
            link: Link::None,
            align: 8,
            entsize: 8,
        });
    }
    if view.fini_array != 0 {
        sections.push(Section {
            name: ".fini_array",
            ty: SHT_FINI_ARRAY,
            flags: SHF_ALLOC | SHF_WRITE,
            addr: view.fini_array,
            size: view.fini_arraysz,
            link: Link::None,
            align: 8,
            entsize: 8,
        });
    }
    if view.dynamic != 0 {
        sections.push(Section {
            name: ".dynamic",
            ty: SHT_DYNAMIC,
            flags: SHF_ALLOC | SHF_WRITE,
            addr: view.dynamic,
            size: view.dynamic_size,
            link: Link::Dynstr,
            align: 8,
            entsize: DYN_SIZE as u64,
        });
    }
    let _ = (view.init, view.fini, load_len);
    sections.retain(|section| section.name.is_empty() || section.addr < load_len);
    sections
}

fn append_sections(image: &mut Vec<u8>, sections: &[Section]) -> Result<()> {
    let mut named = sections.to_vec();
    // .hash size needs the image. Recompute before the string table is appended.
    for section in &mut named {
        if section.name == ".hash" && section.size == 0 {
            let off = need(image, section.addr, 8)?;
            let nbuckets = u64::from(read_u32(image, off)?);
            let nchain = u64::from(read_u32(image, off + 4)?);
            section.size = 8 + (nbuckets + nchain) * 4;
        }
        if section.name == ".gnu.hash" && section.size == 0 {
            section.size = gnu_hash_bytes(image, section.addr)?;
        }
    }
    named.sort_by_key(|section| (section.addr == 0 && section.name.is_empty(), section.addr));
    // Keep the null section first even if its address is 0.
    if let Some(null_at) = named.iter().position(|section| section.name.is_empty()) {
        let null = named.remove(null_at);
        named.insert(0, null);
    }

    let mut shstr = vec![0u8];
    let mut name_off = Vec::with_capacity(named.len());
    for section in &named {
        if section.name.is_empty() {
            name_off.push(0u32);
            continue;
        }
        name_off.push(u32::try_from(shstr.len()).unwrap_or(0));
        shstr.extend(section.name.as_bytes());
        shstr.push(0);
    }
    let shstr_name = u32::try_from(shstr.len()).unwrap_or(0);
    shstr.extend(b".shstrtab\0");
    let shstr_off = image.len() as u64;
    let shstr_size = shstr.len() as u64;
    image.extend(shstr);
    let shoff = image.len() as u64;
    let shnum = named.len() + 1;
    let shstrndx = named.len();
    for (index, section) in named.iter().enumerate() {
        write_shdr(image, name_off[index], section, &named)?;
    }
    let shstr_section = Section {
        name: ".shstrtab",
        ty: SHT_STRTAB,
        flags: 0,
        addr: shstr_off,
        size: shstr_size,
        link: Link::None,
        align: 1,
        entsize: 0,
    };
    write_shdr(image, shstr_name, &shstr_section, &named)?;

    write_u64(image, 40, shoff)?;
    write_u16(image, 58, SHDR_SIZE as u16)?;
    write_u16(image, 60, u16::try_from(shnum).unwrap_or(u16::MAX))?;
    write_u16(image, 62, u16::try_from(shstrndx).unwrap_or(0))?;
    let _ = shstr_section;
    Ok(())
}

fn write_shdr(image: &mut Vec<u8>, name: u32, section: &Section, all: &[Section]) -> Result<()> {
    let link = match section.link {
        Link::None => 0,
        Link::Dynsym => section_index(all, ".dynsym"),
        Link::Dynstr => section_index(all, ".dynstr"),
    };
    let mut bytes = [0u8; SHDR_SIZE];
    write_u32(&mut bytes, 0, name)?;
    write_u32(&mut bytes, 4, section.ty)?;
    write_u64(&mut bytes, 8, section.flags)?;
    write_u64(&mut bytes, 16, section.addr)?;
    write_u64(&mut bytes, 24, section.addr)?;
    write_u64(&mut bytes, 32, section.size)?;
    write_u32(&mut bytes, 40, link)?;
    write_u32(&mut bytes, 44, 0)?;
    write_u64(&mut bytes, 48, section.align)?;
    write_u64(&mut bytes, 56, section.entsize)?;
    image.extend(bytes);
    Ok(())
}

fn section_index(sections: &[Section], name: &str) -> u32 {
    sections
        .iter()
        .position(|section| section.name == name)
        .and_then(|index| u32::try_from(index).ok())
        .unwrap_or(0)
}

fn gnu_hash_bytes(image: &[u8], hash: u64) -> Result<u64> {
    let off = need(image, hash, 16)?;
    let nbuckets = u64::from(read_u32(image, off)?);
    let symoffset = u64::from(read_u32(image, off + 4)?);
    let bloom_size = u64::from(read_u32(image, off + 8)?);
    let nsyms = gnu_symbol_count(image, hash)?;
    let chains = nsyms.saturating_sub(symoffset);
    Ok(16 + bloom_size * 8 + nbuckets * 4 + chains * 4)
}

fn read_cstr(image: &[u8], strtab: u64, strsz: u64, name_off: u32) -> Result<String> {
    if u64::from(name_off) >= strsz {
        return Err(Error::Truncated);
    }
    let start = need(image, strtab + u64::from(name_off), 1)?;
    let limit = (strtab + strsz) as usize;
    let end = image[start..image.len().min(limit)]
        .iter()
        .position(|byte| *byte == 0)
        .map(|at| start + at)
        .unwrap_or(start);
    let bytes = image.get(start..end).ok_or(Error::Truncated)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn need(image: &[u8], offset: u64, len: usize) -> Result<usize> {
    let start = usize::try_from(offset).map_err(|_| Error::Truncated)?;
    let end = start.checked_add(len).ok_or(Error::Truncated)?;
    if end > image.len() {
        return Err(Error::Truncated);
    }
    Ok(start)
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = image
        .get(offset..offset + 2)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = image
        .get(offset..offset + 4)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(image: &[u8], offset: usize) -> Result<u64> {
    let bytes: [u8; 8] = image
        .get(offset..offset + 8)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_i64(image: &[u8], offset: usize) -> Result<i64> {
    Ok(read_u64(image, offset)? as i64)
}

fn write_u16(image: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let slot = image.get_mut(offset..offset + 2).ok_or(Error::Truncated)?;
    slot.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(image: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let slot = image.get_mut(offset..offset + 4).ok_or(Error::Truncated)?;
    slot.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(image: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let slot = image.get_mut(offset..offset + 8).ok_or(Error::Truncated)?;
    slot.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIAS: u64 = 0x7a00_0000_0000;

    #[test]
    fn repairs_relative_relr_and_import_order() {
        let image = sample_image();
        let fixed = repair(&image, BIAS, &[]).unwrap();
        assert_eq!(read_u64(&fixed, 0x400).unwrap(), 0x400);
        assert_eq!(read_u64(&fixed, 0x418).unwrap(), 0x418);
        // foo is the first undefined symbol, bar the second, regardless of
        // which relocation table mentions them first.
        assert_eq!(read_u64(&fixed, 0x410).unwrap(), 0x500);
        assert_eq!(read_u64(&fixed, 0x408).unwrap(), 0x508);
        assert_eq!(read_u16(&fixed, 18).unwrap(), EM_AARCH64);
        let shoff = read_u64(&fixed, 40).unwrap() as usize;
        let shnum = read_u16(&fixed, 60).unwrap() as usize;
        let rela_plt = (0..shnum)
            .map(|index| shoff + index * SHDR_SIZE)
            .find(|off| read_u32(&fixed, off + 4).unwrap() == SHT_RELA && read_u64(&fixed, off + 16).unwrap() == 0x230)
            .expect("rela.plt");
        assert_eq!(read_u64(&fixed, rela_plt + 56).unwrap(), 24);
        let load = 64;
        assert_eq!(read_u64(&fixed, load + 32).unwrap(), 0x500);
        assert_eq!(read_u64(&fixed, load + 40).unwrap(), 0x500);
    }

    #[test]
    fn zero_load_flags_come_from_the_dump_permissions() {
        let mut image = sample_image();
        write_u32(&mut image, 64 + 4, 0).unwrap();
        let fixed = repair(
            &image,
            BIAS,
            &[Perm {
                offset: 0,
                len: 0x500,
                read: true,
                write: false,
                exec: true,
            }],
        )
        .unwrap();
        assert_eq!(read_u32(&fixed, 64 + 4).unwrap(), PF_R | PF_X);
    }

    #[test]
    fn rejects_a_non_aarch64_image() {
        let mut image = sample_image();
        write_u16(&mut image, 18, 62).unwrap();
        assert!(matches!(
            repair(&image, BIAS, &[]),
            Err(Error::UnsupportedMachine)
        ));
    }

    fn sample_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x500];
        image[0..4].copy_from_slice(&ELF_MAGIC);
        image[4] = ELFCLASS64;
        image[5] = ELFDATA2LSB;
        image[6] = 1;
        write_u16(&mut image, 16, 3).unwrap();
        write_u16(&mut image, 18, EM_AARCH64).unwrap();
        write_u32(&mut image, 20, 1).unwrap();
        write_u64(&mut image, 32, 64).unwrap();
        write_u16(&mut image, 52, 64).unwrap();
        write_u16(&mut image, 54, PHDR_SIZE as u16).unwrap();
        write_u16(&mut image, 56, 2).unwrap();
        write_phdr(&mut image, 0, PT_LOAD, PF_R | PF_X, 0, 0x400, 0x1000);
        write_phdr(&mut image, 1, PT_DYNAMIC, PF_R | PF_W, 0x280, 14 * 16, 8);
        write_sym(&mut image, 0x100, 0, 0, 0);
        write_sym(&mut image, 0x100 + 24, 1, 0, 0);
        write_sym(&mut image, 0x100 + 48, 5, 0, 0);
        write_sym(&mut image, 0x100 + 72, 9, 0x300, 0);
        let dynstr: &[u8] = b"\0foo\0bar\0baz\0";
        image[0x160..0x160 + dynstr.len()].copy_from_slice(dynstr);
        write_u32(&mut image, 0x1c0, 1).unwrap();
        write_u32(&mut image, 0x1c4, 4).unwrap();
        write_rela(&mut image, 0x200, 0x400, 1027, 0, 0x400);
        write_rela(&mut image, 0x218, 0x408, 1025, 2, 0);
        write_rela(&mut image, 0x230, 0x410, 1026, 1, 0);
        write_u64(&mut image, 0x248, 0x418).unwrap();
        let tags = [
            (DT_SYMTAB, 0x100u64),
            (DT_SYMENT, 24),
            (DT_STRTAB, 0x160),
            (DT_STRSZ, dynstr.len() as u64),
            (DT_HASH, 0x1c0),
            (DT_RELA, 0x200),
            (DT_RELASZ, 48),
            (20, DT_RELA as u64),
            (DT_JMPREL, 0x230),
            (DT_PLTRELSZ, 24),
            (DT_RELR, 0x248),
            (DT_RELRSZ, 8),
            (DT_RELRENT, 8),
            (DT_NULL, 0),
        ];
        for (index, (tag, val)) in tags.iter().enumerate() {
            let at = 0x280 + index * 16;
            write_u64(&mut image, at, *tag as u64).unwrap();
            write_u64(&mut image, at + 8, *val).unwrap();
        }
        write_u64(&mut image, 0x400, BIAS + 0x400).unwrap();
        write_u64(&mut image, 0x408, 0x1111_2222_3333_4444).unwrap();
        write_u64(&mut image, 0x410, 0x5555_6666_7777_8888).unwrap();
        write_u64(&mut image, 0x418, BIAS + 0x418).unwrap();
        image
    }

    fn write_phdr(image: &mut [u8], index: usize, ty: u32, flags: u32, vaddr: u64, filesz: u64, align: u64) {
        let off = 64 + index * PHDR_SIZE;
        write_u32(image, off, ty).unwrap();
        write_u32(image, off + 4, flags).unwrap();
        write_u64(image, off + 8, vaddr).unwrap();
        write_u64(image, off + 16, vaddr).unwrap();
        write_u64(image, off + 24, vaddr).unwrap();
        write_u64(image, off + 32, filesz).unwrap();
        write_u64(image, off + 40, filesz).unwrap();
        write_u64(image, off + 48, align).unwrap();
    }

    fn write_sym(image: &mut [u8], at: usize, name: u32, value: u64, _shndx: u16) {
        write_u32(image, at, name).unwrap();
        image[at + 4] = 0x12;
        write_u64(image, at + 8, value).unwrap();
    }

    fn write_rela(image: &mut [u8], at: usize, offset: u64, ty: u32, sym: u32, addend: i64) {
        write_u64(image, at, offset).unwrap();
        write_u64(image, at + 8, (u64::from(sym) << 32) | u64::from(ty)).unwrap();
        write_u64(image, at + 16, addend as u64).unwrap();
    }
}
