//! TAL `PrintFunctionArgs`: demangle, AArch64 ABI args, hexdump.
//! `__cxa_demangle` is only referenced when QBDI (and libc++) is linked.

#![cfg_attr(not(feature = "vm"), allow(dead_code))]

const DEFAULT_C_ARGC: i32 = 3;
const HEXDUMP: usize = 0x40;
const READABLE_ADDR: u64 = 0x3000;

pub fn format_call(symbol: &str, regs: &[u64; 8], sp: u64) -> String {
    let (demangled, argc, reason, used_default) = describe(symbol);
    let args = abi_args(regs, sp, argc.max(0) as usize);
    let mut out = format!("demangled : {demangled}\nargc      : {argc}");
    if used_default {
        out.push_str(&format!(" default({DEFAULT_C_ARGC}) reason={reason}"));
    } else {
        out.push_str(&format!(" reason={reason}"));
    }
    out.push('\n');
    for (index, value) in args.iter().enumerate() {
        out.push_str(&format!("arg[{index}] = {value:#x}"));
        if let Some(clean) = readable_pointer(*value) {
            if clean != *value {
                out.push_str(&format!(" -> {clean:#x}"));
            }
            out.push_str(":\n");
            out.push_str(&hexdump(clean, HEXDUMP));
        } else {
            out.push('\n');
        }
    }
    out
}

fn describe(symbol: &str) -> (String, i32, &'static str, bool) {
    if symbol.is_empty() {
        return (String::new(), DEFAULT_C_ARGC, "empty_symbol", true);
    }
    if !is_mangled(symbol) {
        return (symbol.to_owned(), DEFAULT_C_ARGC, "c_symbol", true);
    }
    let Some(demangled) = demangle(symbol) else {
        return (symbol.to_owned(), DEFAULT_C_ARGC, "parse_failed", true);
    };
    match count_params(&demangled) {
        Some(count) => (demangled, count + 1, "demangled", false),
        None => (demangled, DEFAULT_C_ARGC, "parse_failed", true),
    }
}

fn is_mangled(name: &str) -> bool {
    name.starts_with("_Z") || name.starts_with('?')
}

fn count_params(demangled: &str) -> Option<i32> {
    let bytes = demangled.as_bytes();
    let mut pairs = Vec::new();
    let mut stack = Vec::new();
    let mut angle = 0i32;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'<' => angle += 1,
            b'>' => {
                if angle > 0 {
                    angle -= 1;
                }
            }
            b'(' if angle == 0 => stack.push(index),
            b')' if angle == 0 => {
                if let Some(start) = stack.pop() {
                    if stack.is_empty() {
                        pairs.push((start, index));
                    }
                }
            }
            _ => {}
        }
    }
    let mut param = None;
    for (start, end) in pairs {
        let mut cursor = start;
        while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
            cursor -= 1;
        }
        if cursor == 0 || bytes[cursor - 1] == b':' {
            continue;
        }
        let inside = demangled[start + 1..end].trim();
        if inside.starts_with('.') {
            continue;
        }
        param = Some((start, end));
    }
    let (start, end) = param?;
    if end <= start {
        return None;
    }
    let args = demangled[start + 1..end].trim();
    if args.is_empty() || args == "void" {
        return Some(0);
    }
    let mut count = 1i32;
    let mut angle = 0i32;
    let mut paren = 0i32;
    let mut square = 0i32;
    for ch in args.chars() {
        match ch {
            '<' => angle += 1,
            '>' => {
                if angle > 0 {
                    angle -= 1;
                }
            }
            '(' => paren += 1,
            ')' => {
                if paren > 0 {
                    paren -= 1;
                }
            }
            '[' => square += 1,
            ']' => {
                if square > 0 {
                    square -= 1;
                }
            }
            ',' if angle == 0 && paren == 0 && square == 0 => count += 1,
            _ => {}
        }
    }
    Some(count)
}

fn abi_args(regs: &[u64; 8], sp: u64, want: usize) -> Vec<u64> {
    let mut args = Vec::with_capacity(want);
    let from_regs = want.min(regs.len());
    args.extend_from_slice(&regs[..from_regs]);
    if want <= regs.len() {
        return args;
    }
    for index in regs.len()..want {
        let slot = index - regs.len();
        let addr = sp.wrapping_add((slot as u64).wrapping_mul(8));
        if !span_readable(addr, 8) {
            break;
        }
        let value = unsafe { (addr as *const u64).read_unaligned() };
        args.push(value);
    }
    args
}

fn readable_pointer(raw: u64) -> Option<u64> {
    if span_readable(raw, HEXDUMP) {
        return Some(raw);
    }
    let masked = raw & 0x0000_FFFF_FFFF_FFFF;
    if masked != raw && span_readable(masked, HEXDUMP) {
        Some(masked)
    } else {
        None
    }
}

fn span_readable(addr: u64, size: usize) -> bool {
    if addr <= READABLE_ADDR || size == 0 {
        return false;
    }
    let end = addr.saturating_add(size as u64);
    let Ok(maps) = runtime::maps::read_self_maps() else {
        return false;
    };
    maps.iter().any(|mapping| {
        mapping.perms.read
            && (mapping.range.start as u64) <= addr
            && (mapping.range.end as u64) >= end
    })
}

fn hexdump(addr: u64, size: usize) -> String {
    let ptr = addr as *const u8;
    let mut out = String::new();
    let mut offset = 0usize;
    while offset < size {
        let row = (size - offset).min(16);
        out.push_str(&format!(
            "{addr_row:016x}  ",
            addr_row = addr + offset as u64
        ));
        for column in 0..16 {
            if column < row {
                let byte = unsafe { ptr.add(offset + column).read_unaligned() };
                out.push_str(&format!("{byte:02x} "));
            } else {
                out.push_str("   ");
            }
            if column == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for column in 0..row {
            let byte = unsafe { ptr.add(offset + column).read_unaligned() };
            let ch = if (32..=126).contains(&byte) {
                byte as char
            } else {
                '.'
            };
            out.push(ch);
        }
        out.push_str("|\n");
        offset += 16;
    }
    out
}

#[cfg(feature = "vm")]
fn demangle(raw: &str) -> Option<String> {
    use std::ffi::{CStr, CString};

    extern "C" {
        fn __cxa_demangle(
            name: *const i8,
            buffer: *mut i8,
            length: *mut usize,
            status: *mut i32,
        ) -> *mut i8;
    }
    let c_name = CString::new(raw).ok()?;
    let mut status = 0;
    let ptr = unsafe {
        __cxa_demangle(
            c_name.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut status,
        )
    };
    if ptr.is_null() || status != 0 {
        return None;
    }
    let text = unsafe { CStr::from_ptr(ptr.cast()) }
        .to_string_lossy()
        .into_owned();
    unsafe { libc::free(ptr.cast()) };
    Some(text)
}

#[cfg(not(feature = "vm"))]
fn demangle(_raw: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_template_parameters() {
        assert_eq!(count_params("void foo()"), Some(0));
        assert_eq!(count_params("void foo(void)"), Some(0));
        assert_eq!(count_params("int foo(int, std::pair<int, int>)"), Some(2));
        assert_eq!(
            count_params("art::(anonymous namespace)::bar(int)"),
            Some(1)
        );
        assert!(count_params("no paren").is_none());
    }

    #[test]
    fn c_symbol_uses_three_args() {
        let text = format_call("sqrt", &[1, 2, 3, 4, 5, 6, 7, 8], 0);
        assert!(text.contains("demangled : sqrt"), "{text}");
        assert!(text.contains("argc      : 3"), "{text}");
        assert!(text.contains("reason=c_symbol"), "{text}");
        assert!(text.contains("arg[0] = 0x1"), "{text}");
        assert!(text.contains("arg[2] = 0x3"), "{text}");
        assert!(!text.contains("arg[3]"));
    }
}
