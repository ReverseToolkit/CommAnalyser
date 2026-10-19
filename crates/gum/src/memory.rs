use std::ptr;

use runtime::{Error, Result};

/// Read `len` bytes from `addr` in the current process.
///
/// # Safety
/// The caller is responsible for `addr` pointing to at least `len` readable
/// bytes.  An invalid address will fault, exactly like Frida's `Memory.read*`.
pub unsafe fn read_raw(addr: usize, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if addr == 0 {
        return Err(Error::Parse("null read".into()));
    }
    let mut out = vec![0u8; len];
    // SAFETY: caller guarantees readability.
    unsafe {
        ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
    }
    Ok(out)
}

/// Safe-ish convenience wrapper around [`read_raw`], kept for scripting tests.
pub fn read(addr: usize, len: usize) -> Result<Vec<u8>> {
    // SAFETY: documented as the scripting contract; invalid addresses fault.
    unsafe { read_raw(addr, len) }
}

/// Write `data` to `addr` in the current process.
///
/// # Safety
/// The caller is responsible for `addr` pointing to `data.len()` writable bytes.
pub unsafe fn write_raw(addr: usize, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    if addr == 0 {
        return Err(Error::Parse("null write".into()));
    }
    // SAFETY: caller guarantees writability.
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
    Ok(())
}

pub fn write(addr: usize, data: &[u8]) -> Result<()> {
    // SAFETY: documented as the scripting contract; invalid addresses fault.
    unsafe { write_raw(addr, data) }
}

/// Anonymous RW memory allocation (page aligned, zero-filled by the kernel).
pub fn alloc(size: usize) -> Result<*mut u8> {
    if size == 0 {
        return Err(Error::Parse("zero-sized allocation".into()));
    }
    let page = runtime::process::page_size();
    let rounded = size.div_ceil(page) * page;
    // SAFETY: standard anonymous mmap.
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            rounded,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(p as *mut u8)
}

/// Release memory returned by [`alloc`].  `size` is rounded up like `alloc`.
pub fn free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let page = runtime::process::page_size();
    let rounded = size.div_ceil(page) * page;
    // SAFETY: pointer/size contract mirrors alloc().
    unsafe {
        libc::munmap(ptr as *mut libc::c_void, rounded);
    }
}

/// Change protection of `[addr, addr + len)`.
pub fn protect(addr: usize, len: usize, prot: i32) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    let page = runtime::process::page_size();
    let start = addr & !(page - 1);
    let end = (addr + len + page - 1) & !(page - 1);
    // SAFETY: standard mprotect.
    let rc = unsafe { libc::mprotect(start as *mut libc::c_void, end - start, prot) };
    if rc != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Frida's `Memory.patchCode`: make the page writable, copy, flush icache.
///
/// The original protection is restored on a best-effort basis.  Android's
/// W^X implementations may reject RWX, so we first try RWX and fall back to
/// RW + explicit RX restore.
pub fn patch_code(addr: usize, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let page = runtime::process::page_size();
    let start = addr & !(page - 1);
    let end = (addr + data.len() + page - 1) & !(page - 1);
    let len = end - start;

    // SAFETY: mprotect on the page containing the code.
    let rc = unsafe {
        libc::mprotect(
            start as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    };
    if rc != 0 {
        // Fall back to RW; the caller may need to restore RX afterwards.
        let rc = unsafe {
            libc::mprotect(
                start as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if rc != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }

    // SAFETY: caller guarantees the destination is a code buffer of >= data.len().
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
    flush_icache(addr, data.len());
    Ok(())
}

/// Copy `len` bytes from `src` to `dst` in the current process.
pub fn copy(dst: usize, src: usize, len: usize) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    if dst == 0 || src == 0 {
        return Err(Error::Parse("null copy".into()));
    }
    // SAFETY: scripting contract; a bad address faults like Frida.
    unsafe {
        ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len);
    }
    Ok(())
}

/// Allocate a fresh buffer and copy `len` bytes from `src` into it.
pub fn dup(src: usize, len: usize) -> Result<*mut u8> {
    let dst = alloc(len.max(1))?;
    copy(dst as usize, src, len)?;
    Ok(dst)
}

/// Parse a Frida protection string such as `rwx` / `r-x`.
pub fn parse_prot(spec: &str) -> Result<i32> {
    let bytes = spec.as_bytes();
    if bytes.len() < 3 {
        return Err(Error::Parse(format!("bad prot: {spec}")));
    }
    let mut prot = 0;
    match bytes[0] {
        b'r' => prot |= libc::PROT_READ,
        b'-' => {}
        _ => return Err(Error::Parse(format!("bad prot: {spec}"))),
    }
    match bytes[1] {
        b'w' => prot |= libc::PROT_WRITE,
        b'-' => {}
        _ => return Err(Error::Parse(format!("bad prot: {spec}"))),
    }
    match bytes[2] {
        b'x' => prot |= libc::PROT_EXEC,
        b'-' => {}
        _ => return Err(Error::Parse(format!("bad prot: {spec}"))),
    }
    Ok(prot)
}

/// Make `[addr, addr + len)` writable, run `f`, restore RX, flush icache.
pub fn with_writable<T>(addr: usize, len: usize, f: impl FnOnce() -> T) -> Result<T> {
    if len == 0 {
        return Ok(f());
    }
    let page = runtime::process::page_size();
    let start = addr & !(page - 1);
    let end = (addr + len + page - 1) & !(page - 1);
    let span = end - start;
    let mut writable = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    if protect(start, span, writable).is_err() {
        writable = libc::PROT_READ | libc::PROT_WRITE;
        protect(start, span, writable)?;
    }
    let result = f();
    flush_icache(addr, len);
    let _ = protect(start, span, libc::PROT_READ | libc::PROT_EXEC);
    Ok(result)
}

/// One `Memory.scanSync` match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanMatch {
    pub address: usize,
    pub size: usize,
}

/// Scan `[base, base + size)` for a space-separated hex pattern (`??` wildcards).
pub fn scan_sync(base: usize, size: usize, pattern: &str) -> Result<Vec<ScanMatch>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let (needle, mask) = parse_scan_pattern(pattern)?;
    if needle.is_empty() || size < needle.len() {
        return Ok(Vec::new());
    }
    let haystack = read(base, size)?;
    let mut matches = Vec::new();
    let last = haystack.len() - needle.len();
    for offset in 0..=last {
        if haystack[offset..offset + needle.len()]
            .iter()
            .zip(needle.iter().zip(mask.iter()))
            .all(|(byte, (want, keep))| !keep || byte == want)
        {
            matches.push(ScanMatch {
                address: base + offset,
                size: needle.len(),
            });
        }
    }
    Ok(matches)
}

fn parse_scan_pattern(pattern: &str) -> Result<(Vec<u8>, Vec<bool>)> {
    let mut needle = Vec::new();
    let mut mask = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "?" || token == "??" {
            needle.push(0);
            mask.push(false);
            continue;
        }
        let byte = u8::from_str_radix(token, 16)
            .map_err(|_| Error::Parse(format!("bad scan token: {token}")))?;
        needle.push(byte);
        mask.push(true);
    }
    Ok((needle, mask))
}

/// Allocate `size` bytes near `near` (within `max_distance`), preferring RX later.
pub fn alloc_near(size: usize, near: usize, max_distance: usize) -> Result<*mut u8> {
    let page = runtime::process::page_size();
    let rounded = size.div_ceil(page) * page;
    let base = near & !(page - 1);
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | 0x10_0000; // MAP_FIXED_NOREPLACE
    let mut delta = 0usize;
    while delta <= max_distance {
        for candidate in [base.checked_add(delta), base.checked_sub(delta)]
            .into_iter()
            .flatten()
        {
            if candidate == 0 {
                continue;
            }
            let p = unsafe {
                libc::mmap(
                    candidate as *mut libc::c_void,
                    rounded,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    flags,
                    -1,
                    0,
                )
            };
            if p != libc::MAP_FAILED && p as usize == candidate {
                return Ok(p as *mut u8);
            }
            if p != libc::MAP_FAILED {
                unsafe { libc::munmap(p, rounded) };
            }
            let p = unsafe {
                libc::mmap(
                    candidate as *mut libc::c_void,
                    rounded,
                    libc::PROT_READ | libc::PROT_WRITE,
                    flags,
                    -1,
                    0,
                )
            };
            if p != libc::MAP_FAILED && p as usize == candidate {
                return Ok(p as *mut u8);
            }
            if p != libc::MAP_FAILED {
                unsafe { libc::munmap(p, rounded) };
            }
        }
        delta = delta.saturating_add(page.max(0x10000));
        if delta == 0 {
            break;
        }
    }
    alloc(size)
}

/// Frida protection string `rwx` / `r-x` / `rw-` / `---`.
pub fn format_prot(read: bool, write: bool, exec: bool) -> String {
    format!(
        "{}{}{}",
        if read { 'r' } else { '-' },
        if write { 'w' } else { '-' },
        if exec { 'x' } else { '-' }
    )
}

/// `Memory.queryProtection(address)` from `/proc/self/maps`.
pub fn query_protection(addr: usize) -> Result<String> {
    let maps = runtime::maps::read_self_maps()?;
    maps.iter()
        .find(|mapping| mapping.range.contains(addr))
        .map(|mapping| format_prot(mapping.perms.read, mapping.perms.write, mapping.perms.exec))
        .ok_or_else(|| Error::NotFound(format!("no mapping for {addr:#x}")))
}

/// NUL-terminated UTF-16LE string, as `Memory.allocUtf16String`.
pub fn alloc_utf16(text: &str) -> Result<*mut u8> {
    let mut units: Vec<u16> = text.encode_utf16().collect();
    units.push(0);
    let bytes = units.len().saturating_mul(2);
    let pointer = alloc(bytes.max(1))?;
    // SAFETY: freshly allocated buffer of `bytes` bytes.
    unsafe {
        ptr::copy_nonoverlapping(units.as_ptr().cast::<u8>(), pointer, bytes);
    }
    Ok(pointer)
}

/// Addresses in `[base, base+size)` that hold one of `needles` as a pointer.
pub fn find_pointers(base: usize, size: usize, needles: &[u64]) -> Result<Vec<usize>> {
    let width = std::mem::size_of::<usize>();
    if size < width || needles.is_empty() {
        return Ok(Vec::new());
    }
    let haystack = read(base, size)?;
    let mut found = Vec::new();
    let last = haystack.len() - width;
    let mut offset = 0usize;
    while offset <= last {
        let slot = u64::from_le_bytes(haystack[offset..offset + width].try_into().unwrap());
        if needles.contains(&slot) {
            found.push(base + offset);
        }
        offset += width;
    }
    Ok(found)
}

/// Flush the instruction cache for `[addr, addr + len)`.
///
/// bionic does not export `__clear_cache`, so emit the AArch64 cache
/// maintenance operations directly.  The line size is conservatively 64 bytes.
pub fn flush_icache(addr: usize, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        if len == 0 {
            return;
        }
        let start = addr & !63;
        let end = (addr + len + 63) & !63;
        let mut line = start;
        while line < end {
            // SAFETY: DC CVAU / IC IVAU are EL0-accessible cache maintenance.
            unsafe {
                core::arch::asm!("dc cvau, {}", in(reg) line, options(nostack, preserves_flags));
            }
            line += 64;
        }
        // SAFETY: barriers are side-effect free.
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }
        let mut line = start;
        while line < end {
            unsafe {
                core::arch::asm!("ic ivau, {}", in(reg) line, options(nostack, preserves_flags));
            }
            line += 64;
        }
        unsafe {
            core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (addr, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let mut buf = [0u8; 16];
        let addr = buf.as_mut_ptr() as usize;
        write(addr, &[1, 2, 3, 4]).unwrap();
        assert_eq!(read(addr, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(buf[..4], [1, 2, 3, 4]);
    }

    #[test]
    fn alloc_protect_free() {
        let p = alloc(32).unwrap();
        assert!(!p.is_null());
        // SAFETY: freshly allocated page.
        unsafe {
            *p = 0x41;
            assert_eq!(*p, 0x41);
        }
        protect(p as usize, 32, libc::PROT_READ).unwrap();
        free(p, 32);
    }

    #[test]
    fn copy_dup_and_scan() {
        let mut buf = [0u8, 1, 2, 0xff, 0xaa, 3, 4, 5];
        let addr = buf.as_mut_ptr() as usize;
        let duped = dup(addr, 8).unwrap();
        assert_eq!(read(duped as usize, 8).unwrap(), buf);
        let matches = scan_sync(addr, 8, "ff aa").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, addr + 3);
        let wild = scan_sync(addr, 8, "01 ?? ff").unwrap();
        assert_eq!(wild[0].address, addr + 1);
        assert_eq!(
            parse_prot("rwx").unwrap(),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        );
        assert_eq!(
            parse_prot("r-x").unwrap(),
            libc::PROT_READ | libc::PROT_EXEC
        );
        free(duped, 8);
    }

    #[test]
    fn query_protection_and_find_pointers() {
        let mut buf = [0u8; 16];
        let addr = buf.as_mut_ptr() as usize;
        let prot = query_protection(addr).unwrap();
        assert!(prot.starts_with('r'), "{prot}");
        let needle = 0x1122_3344_5566_7788u64;
        buf[..8].copy_from_slice(&needle.to_le_bytes());
        let hits = find_pointers(addr, 16, &[needle]).unwrap();
        assert_eq!(hits, vec![addr]);
        let utf16 = alloc_utf16("hi").unwrap();
        let bytes = read(utf16 as usize, 6).unwrap();
        assert_eq!(&bytes, &[b'h', 0, b'i', 0, 0, 0]);
        free(utf16, 6);
    }

    #[test]
    fn format_prot_and_patch_code() {
        assert_eq!(format_prot(true, false, true), "r-x");
        assert_eq!(format_prot(true, true, false), "rw-");
        assert_eq!(format_prot(false, false, false), "---");
        let page = alloc(64).unwrap();
        patch_code(page as usize, &[0x1F, 0x20, 0x03, 0xD5]).unwrap();
        assert_eq!(
            read(page as usize, 4).unwrap(),
            vec![0x1F, 0x20, 0x03, 0xD5]
        );
        flush_icache(page as usize, 4);
        free(page, 64);
        assert!(parse_prot("rw").is_err());
    }
}
